"""Palo Alto (PAN-OS) ``set``-format parser for Wargame.

Turns PAN-OS CLI ``set`` output (``show config running`` converted with
``set cli config-output-format set``) into vendor-neutral
:class:`~app.engine.wargame.model.RuleSet` objects. DEFENSIVE: this is a pure
text-to-model transform; nothing is sent anywhere or exploited.

What is modelled
----------------
* Objects: ``address`` (ip-netmask, ip-range, fqdn), ``address-group``
  (static / dynamic), ``service`` (tcp/udp, comma lists and ranges),
  ``service-group`` and ``external-list``.
* ``rulebase security rules``: from / to / source / destination /
  application / service / source-user / action (plus ``disabled``,
  ``negate-*`` and ``category``).

Honesty rule (a rule is marked ``conditional`` when its real effect cannot
be proved from config alone)
    * application other than ``any``       -> APP_ID
    * service ``application-default``      -> APP_ID (ports depend on the
      app; resolved to any port). An unset service is the PAN-OS default,
      i.e. also ``application-default``.
    * source-user other than ``any``       -> USER_ID
    * URL ``category`` other than ``any``  -> URL_CATEGORY
    * fqdn / dynamic address group / external list / unresolved object ->
      conditional through the :class:`ObjectTable`
    * ``negate-source`` / ``negate-destination`` cannot be inverted by the
      neutral model; the side is widened to any and flagged UNRESOLVED.

Grouping and multi-zone rules
-----------------------------
Rules are grouped into one RuleSet per zone pair, id ``"<from>><to>"``
(``any`` when unset), each with a :class:`RuleSetBinding`. A rule with
several from/to zones is emitted into **each** zone-pair set (cartesian
product). A rule with from/to ``any`` is additionally placed in every
concrete zone-pair set that exists, because on a real firewall it also
governs those flows and may precede (or follow) a concrete rule; global
appearance order is preserved so first-match semantics stay correct.
``default_action`` is DENY. (PAN-OS's implicit intrazone-allow default is not
modelled; an INFO warning says so.)

Never raises: anything unrecognised becomes a warning. Output is
deterministic for a fixed input.
"""
from __future__ import annotations

import itertools
import re
from typing import Union

from ..model import Action, PortRange, Proto, RuleSet
from .base import (
    ANY_CIDRS,
    CONDITIONAL_REASON,
    AddressObject,
    ConditionalFeature,
    ObjectTable,
    ParseResult,
    ParseWarning,
    Parser,
    ResolvedAddresses,
    ResolvedService,
    RuleSetBinding,
    ServiceObject,
    WarningLevel,
    build_rule,
    normalize_cidrs,
    port_range,
    proto_from,
    register,
)

VENDOR = "paloalto"

Token = Union[str, "list[str]"]

_PROMPT_RE = re.compile(r"^\S+[>#]\s+(?=set\s)")
_ANY = "any"


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

def tokenize(line: str) -> list[Token]:
    """Split one ``set`` line (without the leading ``set``) into tokens.

    Whitespace separates tokens; ``"double quoted"`` text is one token (with
    ``\\"`` as an escaped quote); ``[ a b c ]`` (spaces optional) becomes a
    nested ``list[str]`` token. An unclosed bracket list is tolerated.
    """
    out: list[Token] = []
    lst: list[str] | None = None
    cur: list[str] = []
    has_cur = False
    in_q = False

    def emit(tok: str) -> None:
        (lst if lst is not None else out).append(tok)  # type: ignore[arg-type]

    def flush() -> None:
        nonlocal cur, has_cur
        if has_cur:
            emit("".join(cur))
        cur, has_cur = [], False

    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if in_q:
            if ch == "\\" and i + 1 < n and line[i + 1] == '"':
                cur.append('"')
                i += 1
            elif ch == '"':
                in_q = False
            else:
                cur.append(ch)
        elif ch == '"':
            in_q = True
            has_cur = True
        elif ch == "[" and lst is None:
            flush()
            lst = []
        elif ch == "]" and lst is not None:
            flush()
            out.append(lst)
            lst = None
        elif ch.isspace():
            flush()
        else:
            cur.append(ch)
            has_cur = True
        i += 1
    flush()
    if lst is not None:  # unclosed bracket
        out.append(lst)
    return out


def _flat(items: list[Token]) -> list[str]:
    out: list[str] = []
    for it in items:
        if isinstance(it, list):
            out.extend(it)
        else:
            out.append(it)
    return out


def _strip_scope(tokens: list[Token]) -> list[Token]:
    """Drop ``vsys vsysN`` / ``device-group X`` / ``shared`` prefixes."""
    while tokens and isinstance(tokens[0], str):
        head = tokens[0]
        if head in ("vsys", "device-group", "template") and len(tokens) > 2:
            tokens = tokens[2:]
        elif head == "shared" and len(tokens) > 1:
            tokens = tokens[1:]
        else:
            break
    return tokens


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _merge_addrs(parts: list[ResolvedAddresses]) -> ResolvedAddresses:
    cidrs: list[str] = []
    feats: set[ConditionalFeature] = set()
    unresolved: list[str] = []
    for p in parts:
        for c in p.cidrs:
            if c not in cidrs:
                cidrs.append(c)
        feats.update(p.features)
        unresolved.extend(p.unresolved)
    return ResolvedAddresses(
        cidrs=tuple(cidrs) if cidrs else ANY_CIDRS,
        conditional=bool(feats),
        features=tuple(sorted(feats, key=lambda f: f.value)),
        unresolved=tuple(dict.fromkeys(unresolved)),
    )


def _merge_services(parts: list[ResolvedService]) -> ResolvedService:
    ports: list[PortRange] = []
    feats: set[ConditionalFeature] = set()
    unresolved: list[str] = []
    for p in parts:
        for pr in p.ports:
            if pr not in ports:
                ports.append(pr)
        feats.update(p.features)
        unresolved.extend(p.unresolved)
    return ResolvedService(
        ports=tuple(ports) if ports else (PortRange.any(),),
        conditional=bool(feats),
        features=tuple(sorted(feats, key=lambda f: f.value)),
        unresolved=tuple(dict.fromkeys(unresolved)),
    )


def _parse_ports(proto: Proto, values: list[str]) -> list[PortRange] | None:
    """``["80,443", "1000-2000"]`` -> PortRanges, or None if malformed."""
    out: list[PortRange] = []
    for val in values:
        for piece in val.split(","):
            piece = piece.strip()
            if not piece:
                continue
            lo_s, sep, hi_s = piece.partition("-")
            try:
                lo = int(lo_s)
                hi = int(hi_s) if sep else lo
            except ValueError:
                return None
            if not (0 <= lo <= 65535 and 0 <= hi <= 65535):
                return None
            out.append(port_range(proto, lo, hi))
    return out or None


def _is_yes(vals: list[str] | None) -> bool:
    return bool(vals) and vals[0].lower() in ("yes", "true")  # type: ignore[index]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

@register(VENDOR)
class PaloAltoParser(Parser):
    """Parse PAN-OS ``set``-format config into per-zone-pair RuleSets."""

    def parse(self, raw: str, **opts) -> ParseResult:  # type: ignore[override]
        result = ParseResult(vendor=VENDOR)
        try:
            self._parse(raw, result)
        except Exception as exc:  # pragma: no cover - defensive, never raise
            result.add_warning(
                WarningLevel.UNSUPPORTED, f"palo alto parse aborted: {exc!r}"
            )
        return result

    # -- driver ------------------------------------------------------------
    def _parse(self, raw: object, result: ParseResult) -> None:
        if isinstance(raw, (bytes, bytearray)):
            raw = bytes(raw).decode("utf-8", "replace")
        elif not isinstance(raw, str):
            raw = "" if raw is None else str(raw)

        self.table = ObjectTable()
        # PAN-OS predefined services that rules commonly reference.
        self.table.add_service(
            ServiceObject("service-http", ports=(port_range(Proto.TCP, 80),)))
        self.table.add_service(
            ServiceObject("service-https", ports=(port_range(Proto.TCP, 443),)))
        self.rules: dict[str, dict[str, list[str]]] = {}
        noise: dict[str, list[int]] = {}

        for lineno, line in enumerate(raw.splitlines(), 1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            text = _PROMPT_RE.sub("", text)
            if not text.startswith("set ") and text != "set":
                noise.setdefault("non-set line", []).append(lineno)
                continue
            try:
                tokens = _strip_scope(tokenize(text[3:]))
                key = self._dispatch(tokens, lineno, result)
            except Exception as exc:  # tolerate any malformed line
                result.add_warning(
                    WarningLevel.UNSUPPORTED,
                    f"could not parse line: {exc!r}", f"line {lineno}")
                continue
            if key is not None:
                noise.setdefault(key, []).append(lineno)

        for key, lines in noise.items():
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"ignored {len(lines)} '{key}' line(s)", f"first at line {lines[0]}")

        self._build(result)

    def _dispatch(
        self, tokens: list[Token], lineno: int, result: ParseResult
    ) -> str | None:
        """Handle one line. Returns a noise key when the line is ignored."""
        if not tokens or not isinstance(tokens[0], str):
            return "empty set line"
        kw = tokens[0]
        if kw == "rulebase" and len(tokens) >= 3 and tokens[1] == "security" \
                and tokens[2] == "rules":
            self._rule_line(tokens[3:], lineno, result)
            return None
        if kw == "address" and len(tokens) >= 2:
            self._address(tokens, lineno, result)
            return None
        if kw == "address-group" and len(tokens) >= 2:
            self._address_group(tokens)
            return None
        if kw == "service" and len(tokens) >= 2:
            self._service(tokens, lineno, result)
            return None
        if kw == "service-group" and len(tokens) >= 2:
            self._service_group(tokens)
            return None
        if kw == "external-list" and len(tokens) >= 2:
            name = _flat(tokens[1:2])[0]
            if name not in self.table.addresses:
                self.table.add_address(AddressObject(
                    name, conditional=True,
                    feature=ConditionalFeature.EXTERNAL_DYNAMIC_LIST))
            return None
        if kw == "rulebase":
            return "rulebase " + (tokens[1] if len(tokens) > 1
                                  and isinstance(tokens[1], str) else "")
        return kw

    # -- objects -----------------------------------------------------------
    def _address(self, tokens: list[Token], lineno: int, result: ParseResult) -> None:
        name = _flat(tokens[1:2])[0]
        if len(tokens) < 4 or not isinstance(tokens[2], str):
            return  # description / tag / bare declaration
        kind, vals = tokens[2], _flat(tokens[3:])
        ref = f"address {name}"
        if kind == "fqdn":
            self.table.add_address(AddressObject(
                name, conditional=True, feature=ConditionalFeature.FQDN))
        elif kind in ("ip-netmask", "ip-range"):
            cidrs = normalize_cidrs(vals[0]) if vals else None
            if cidrs is None:
                result.add_warning(
                    WarningLevel.UNSUPPORTED,
                    f"unparseable {kind} value {vals[:1]}", ref)
                self.table.add_address(AddressObject(
                    name, conditional=True, feature=ConditionalFeature.UNRESOLVED))
            else:
                self.table.add_address(AddressObject(name, cidrs=tuple(cidrs)))
        elif kind == "ip-wildcard":
            result.add_warning(
                WarningLevel.UNSUPPORTED, "ip-wildcard address not modelled", ref)
            self.table.add_address(AddressObject(
                name, conditional=True, feature=ConditionalFeature.UNRESOLVED))
        # other sub-keys (description, tag, ...) are irrelevant

    def _address_group(self, tokens: list[Token]) -> None:
        name = _flat(tokens[1:2])[0]
        if len(tokens) < 4 or not isinstance(tokens[2], str):
            return
        kind = tokens[2]
        if kind == "static":
            members = tuple(_flat(tokens[3:]))
            old = self.table.addresses.get(name)
            if old is not None and not old.conditional:
                members = old.members + tuple(m for m in members if m not in old.members)
            self.table.add_address(AddressObject(name, members=members))
        elif kind == "dynamic":
            self.table.add_address(AddressObject(
                name, conditional=True,
                feature=ConditionalFeature.DYNAMIC_ADDRESS_GROUP))

    def _service(self, tokens: list[Token], lineno: int, result: ParseResult) -> None:
        name = _flat(tokens[1:2])[0]
        if len(tokens) < 6 or tokens[2] != "protocol" or tokens[4] != "port":
            return  # source-port, override, description, tag, ...
        proto_tok = _flat(tokens[3:4])[0].lower()
        proto = proto_from(proto_tok)
        ref = f"service {name}"
        if proto is Proto.ANY:
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"protocol {proto_tok!r} not modelled; treated as any", ref)
        ports = _parse_ports(proto, _flat(tokens[5:]))
        old = self.table.services.get(name)
        if ports is None:
            result.add_warning(
                WarningLevel.UNSUPPORTED, "unparseable port spec", ref)
            self.table.add_service(ServiceObject(
                name, ports=(PortRange.any(),), conditional=True,
                feature=ConditionalFeature.UNRESOLVED))
            return
        merged = tuple(ports)
        if old is not None and not old.conditional:
            merged = old.ports + tuple(p for p in merged if p not in old.ports)
        self.table.add_service(ServiceObject(name, ports=merged))

    def _service_group(self, tokens: list[Token]) -> None:
        name = _flat(tokens[1:2])[0]
        if len(tokens) < 4 or tokens[2] != "members":
            return
        members = tuple(_flat(tokens[3:]))
        old = self.table.services.get(name)
        if old is not None and old.members:
            members = old.members + tuple(m for m in members if m not in old.members)
        self.table.add_service(ServiceObject(name, members=members))

    # -- rule accumulation -------------------------------------------------
    def _rule_line(self, rest: list[Token], lineno: int, result: ParseResult) -> None:
        if not rest:
            return
        name = _flat(rest[:1])[0]
        fields = self.rules.setdefault(name, {})
        if len(rest) < 2 or not isinstance(rest[1], str):
            return
        fld = rest[1]
        vals = _flat(rest[2:])
        bucket = fields.setdefault(fld, [])
        for v in vals:
            if v not in bucket:
                bucket.append(v)

    # -- assembly ----------------------------------------------------------
    def _build(self, result: ParseResult) -> None:
        # (rule, zone pairs) in appearance order
        entries: list[tuple[object, list[tuple[str, str]]]] = []
        for idx, (name, f) in enumerate(self.rules.items()):
            ref = f"rulebase security rules {name}"
            if _is_yes(f.get("disabled")):
                result.add_warning(WarningLevel.INFO, "rule disabled; skipped", ref)
                continue

            acts = f.get("action")
            if acts:
                action = Action.ALLOW if acts[0].lower() == "allow" else Action.DENY
            else:
                action = Action.ALLOW  # PAN-OS default action is allow
                result.add_warning(
                    WarningLevel.INFO, "no action set; PAN-OS default is allow", ref)

            src = self._side(f, "source", "negate-source", ref, result)
            dst = self._side(f, "destination", "negate-destination", ref, result)

            svc_tokens = f.get("service")
            if not svc_tokens:
                svc_tokens = ["application-default"]
                result.add_warning(
                    WarningLevel.INFO,
                    "no service set; PAN-OS default is application-default", ref)
            app_default = False
            parts: list[ResolvedService] = []
            for tok in svc_tokens:
                low = tok.lower()
                if low == "application-default":
                    app_default = True
                    parts.append(ResolvedService(ports=(PortRange.any(),)))
                elif low == _ANY:
                    parts.append(ResolvedService(ports=(PortRange.any(),)))
                else:
                    parts.append(self.table.resolve_service(tok))
            service = _merge_services(parts)

            feats: list[ConditionalFeature] = []
            apps = f.get("application") or [_ANY]
            if app_default or _ANY not in (a.lower() for a in apps):
                feats.append(ConditionalFeature.APP_ID)
            users = f.get("source-user") or []
            if users and _ANY not in (u.lower() for u in users):
                feats.append(ConditionalFeature.USER_ID)
            cats = f.get("category") or []
            if cats and _ANY not in (c.lower() for c in cats):
                feats.append(ConditionalFeature.URL_CATEGORY)

            rule, warns = build_rule(
                rule_id=name, action=action, order=idx, src=src, dst=dst,
                service=service, vendor=VENDOR, raw_ref=ref,
                extra_conditional=bool(feats),
                extra_feature=feats[0] if feats else None)
            seen = {w.message for w in warns}
            for ft in feats[1:]:  # build_rule takes one extra feature only
                if CONDITIONAL_REASON[ft] not in seen:
                    warns.append(ParseWarning(
                        WarningLevel.CONDITIONAL, CONDITIONAL_REASON[ft], ref))
            result.warnings.extend(warns)

            froms = f.get("from") or [_ANY]
            tos = f.get("to") or [_ANY]
            entries.append((rule, list(itertools.product(froms, tos))))

        # Zone-pair keys in first-seen order.
        keys: list[tuple[str, str]] = []
        for _rule, pairs in entries:
            for p in pairs:
                if p not in keys:
                    keys.append(p)

        for kf, kt in keys:
            rules = [
                rule for rule, pairs in entries
                if any((rf == kf or rf == _ANY) and (rt == kt or rt == _ANY)
                       for rf, rt in pairs)
            ]
            rid = f"{kf}>{kt}"
            result.rulesets[rid] = RuleSet(
                id=rid, rules=rules,  # type: ignore[arg-type]
                default_action=Action.DENY, vendor=VENDOR)
            result.bindings.append(
                RuleSetBinding(ruleset_id=rid, src_zone=kf, dst_zone=kt))
            if kf == kt and kf != _ANY:
                result.add_warning(
                    WarningLevel.INFO,
                    "intrazone traffic is allowed by default on PAN-OS; "
                    "default_action DENY is modelled for this set", rid)

    def _side(
        self, f: dict[str, list[str]], fld: str, neg: str, ref: str,
        result: ParseResult,
    ) -> ResolvedAddresses:
        toks = f.get(fld) or [_ANY]
        if _is_yes(f.get(neg)):
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"{neg} cannot be modelled; {fld} widened to any", ref)
            return ResolvedAddresses(
                cidrs=ANY_CIDRS, conditional=True,
                features=(ConditionalFeature.UNRESOLVED,))
        return _merge_addrs([self.table.resolve_addresses(t) for t in toks])
