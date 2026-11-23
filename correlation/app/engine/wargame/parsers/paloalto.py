"""Palo Alto (PAN-OS) ``set``-format parser for Wargame.

Turns PAN-OS CLI ``set`` output (``show config running`` converted with
``set cli config-output-format set``, or a Panorama export) into
vendor-neutral :class:`~app.engine.wargame.model.RuleSet` objects. DEFENSIVE:
this is a pure text-to-model transform; nothing is sent anywhere or exploited.

What is modelled
----------------
* Objects: ``address`` (ip-netmask, ip-range, fqdn, ip-wildcard),
  ``address-group`` (static / dynamic), ``service`` (tcp/udp, comma lists
  and ranges), ``service-group`` and ``external-list``, each in its scope:
  ``shared`` objects are visible everywhere and a ``vsys`` / ``device-group``
  object of the same name shadows the shared one.
* Security rules from ``rulebase`` (local), ``pre-rulebase`` and
  ``post-rulebase`` (Panorama), evaluated in PAN-OS order: shared pre →
  device-group pre → local → device-group post → shared post. Fields:
  from / to / source / destination / application / service / source-user /
  action / rule-type, plus ``disabled``, ``negate-*``, ``category`` and HIP /
  device matches.
* The default rules: **intrazone traffic is allowed** and interzone traffic
  denied unless ``default-security-rules`` overrides them.
* NAT: destination translation (and bi-directional static source NAT) means
  a security rule matches the *pre-NAT* destination; rules touching a
  translated address get the other half added and are flagged conditional.

Honesty rule (a rule is marked ``conditional`` when its real effect cannot
be proved from config alone)
    * application other than ``any``       -> APP_ID
    * service ``application-default``      -> APP_ID (ports depend on the
      app; resolved to any port). An unset service is the PAN-OS default,
      i.e. also ``application-default``.
    * source-user other than ``any``       -> USER_ID (HIP / device too)
    * URL ``category`` other than ``any``  -> URL_CATEGORY
    * fqdn / dynamic address group / external list / ip-wildcard /
      unresolved object -> conditional through the :class:`ObjectTable`
    * a service name that is not defined in the config (PAN-OS predefines
      only ``service-http`` / ``service-https``) -> UNRESOLVED
    * ``negate-source`` / ``negate-destination`` are modelled exactly as the
      address complement when the side resolves cleanly; otherwise the side
      widens to any and is flagged UNRESOLVED.

Grouping and multi-zone rules
-----------------------------
Rules are grouped into one RuleSet per zone pair, id ``"<from>><to>"``
(``any`` when unset; prefixed ``<vsys|device-group>:`` when the config has
more than one), each with a :class:`RuleSetBinding`. A rule with several
from/to zones is emitted into **each** zone-pair set (cartesian product),
honouring ``rule-type`` (intrazone / interzone / universal). A rule with
from/to ``any`` is additionally placed in every concrete zone-pair set that
exists, because on a real firewall it also governs those flows; global
order is preserved so first-match semantics stay correct. Every concrete
zone also gets its intrazone ``Z>Z`` set. ``default_action`` is the
intrazone default (ALLOW) for ``Z>Z`` sets and the interzone default (DENY)
otherwise.

Never raises: anything unrecognised becomes a warning. Output is
deterministic for a fixed input.
"""
from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from typing import Optional, Union

from ..model import Action, PortRange, Proto, Rule, RuleSet
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
    apply_nat_overapprox,
    build_rule,
    complement_cidrs,
    normalize_cidrs,
    port_range,
    proto_from,
    register,
)

VENDOR = "paloalto"

Token = Union[str, "list[str]"]

_PROMPT_RE = re.compile(r"^\S+[>#]\s+(?=set\s)")
_ANY = "any"
_SHARED = "shared"
_DEFAULT_CONTAINER = "vsys:vsys1"
_PHASES = ("pre-rulebase", "rulebase", "post-rulebase")
_DENY_ACTIONS = frozenset({"deny", "drop", "reset-client", "reset-server", "reset-both"})
#: Rule match fields that narrow a rule at runtime when not "any".
_RUNTIME_FIELDS: dict[str, ConditionalFeature] = {
    "source-user": ConditionalFeature.USER_ID,
    "source-hip": ConditionalFeature.USER_ID,
    "destination-hip": ConditionalFeature.USER_ID,
    "source-device": ConditionalFeature.USER_ID,
    "destination-device": ConditionalFeature.USER_ID,
    "category": ConditionalFeature.URL_CATEGORY,
}


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




def _strip_scope(tokens: list[Token]) -> tuple[str, list[Token]]:
    """Split off the ``vsys X`` / ``device-group X`` / ``template X`` /
    ``shared`` prefix. Returns ``(container, rest)``; a line with no prefix
    belongs to the default ``vsys1`` container."""
    container = _DEFAULT_CONTAINER
    while tokens and isinstance(tokens[0], str):
        head = tokens[0]
        if head in ("vsys", "device-group", "template", "template-stack") \
                and len(tokens) > 2 and isinstance(tokens[1], str):
            kind = {"vsys": "vsys", "device-group": "dg"}.get(head, "tpl")
            container = f"{kind}:{tokens[1]}"
            tokens = tokens[2:]
        elif head == "shared" and len(tokens) > 1:
            container = _SHARED
            tokens = tokens[1:]
        elif head == "config" and len(tokens) > 1:
            tokens = tokens[1:]         # template "config devices ..." wrapper
        elif head == "devices" and len(tokens) > 2:
            tokens = tokens[2:]
        else:
            break
    return container, tokens


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
        conditional=bool(feats) or any(p.conditional for p in parts),
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
        conditional=bool(feats) or any(p.conditional for p in parts),
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


def _is_any(vals: list[str] | None) -> bool:
    return not vals or any(v.lower() == _ANY for v in vals)


def _display(container: str) -> str:
    return container.split(":", 1)[1] if ":" in container else container


@dataclass
class _RuleDef:
    container: str
    phase: str
    name: str
    fields: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class _Built:
    rule: Rule
    pairs: list[tuple[str, str]]
    rule_type: str


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

        self.tables: dict[str, ObjectTable] = {}
        shared = self._table(_SHARED)
        # PAN-OS predefined services (service-http is TCP 80 *and* 8080).
        shared.add_service(ServiceObject(
            "service-http", ports=(port_range(Proto.TCP, 80), port_range(Proto.TCP, 8080))))
        shared.add_service(ServiceObject(
            "service-https", ports=(port_range(Proto.TCP, 443),)))
        self.rules: dict[tuple[str, str, str], _RuleDef] = {}
        self.nat: dict[tuple[str, str, str], dict[str, list[str]]] = {}
        self.defaults: dict[str, dict[str, str]] = {}
        self.zones: dict[str, list[str]] = {}
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
                container, tokens = _strip_scope(tokenize(text[3:]))
                key = self._dispatch(container, tokens, lineno, result)
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

    def _table(self, container: str) -> ObjectTable:
        t = self.tables.get(container)
        if t is None:
            t = self.tables[container] = ObjectTable()
        return t

    def _dispatch(
        self, container: str, tokens: list[Token], lineno: int, result: ParseResult
    ) -> str | None:
        """Handle one line. Returns a noise key when the line is ignored."""
        if not tokens or not isinstance(tokens[0], str):
            return "empty set line"
        kw = tokens[0]
        if kw in _PHASES and len(tokens) >= 3 and tokens[2] == "rules" \
                and tokens[1] in ("security", "nat"):
            if tokens[1] == "security":
                self._rule_line(container, kw, tokens[3:])
            else:
                self._nat_line(container, kw, tokens[3:])
            return None
        if kw in _PHASES and len(tokens) >= 6 and tokens[1] == "default-security-rules" \
                and tokens[2] == "rules" and tokens[4] == "action":
            name, act = _flat(tokens[3:4])[0], _flat(tokens[5:6])[0]
            self.defaults.setdefault(container, {})[name] = act.lower()
            return None
        t = self._table(container)
        if kw == "address" and len(tokens) >= 2:
            self._address(t, tokens, lineno, result)
            return None
        if kw == "address-group" and len(tokens) >= 2:
            self._address_group(t, tokens)
            return None
        if kw == "service" and len(tokens) >= 2:
            self._service(t, tokens, lineno, result)
            return None
        if kw == "service-group" and len(tokens) >= 2:
            self._service_group(t, tokens)
            return None
        if kw == "external-list" and len(tokens) >= 2:
            name = _flat(tokens[1:2])[0]
            if name not in t.addresses:
                t.add_address(AddressObject(
                    name, conditional=True,
                    feature=ConditionalFeature.EXTERNAL_DYNAMIC_LIST))
            return None
        if kw == "zone" and len(tokens) >= 2:
            z = _flat(tokens[1:2])[0]
            zl = self.zones.setdefault(container, [])
            if z not in zl:
                zl.append(z)
            return None
        if kw in _PHASES:
            return kw + " " + (tokens[1] if len(tokens) > 1
                               and isinstance(tokens[1], str) else "")
        return kw

    # -- objects -----------------------------------------------------------
    def _address(self, t: ObjectTable, tokens: list[Token], lineno: int,
                 result: ParseResult) -> None:
        name = _flat(tokens[1:2])[0]
        if len(tokens) < 4 or not isinstance(tokens[2], str):
            return  # description / tag / bare declaration
        kind, vals = tokens[2], _flat(tokens[3:])
        ref = f"address {name}"
        if kind == "fqdn":
            t.add_address(AddressObject(
                name, conditional=True, feature=ConditionalFeature.FQDN))
        elif kind in ("ip-netmask", "ip-range"):
            cidrs = normalize_cidrs(vals[0]) if vals else None
            if cidrs is None:
                result.add_warning(
                    WarningLevel.UNSUPPORTED,
                    f"unparseable {kind} value {vals[:1]}", ref)
                t.add_address(AddressObject(
                    name, conditional=True, feature=ConditionalFeature.UNRESOLVED))
            else:
                t.add_address(AddressObject(name, cidrs=tuple(cidrs)))
        elif kind == "ip-wildcard":
            result.add_warning(
                WarningLevel.UNSUPPORTED, "ip-wildcard address not modelled", ref)
            t.add_address(AddressObject(
                name, conditional=True, feature=ConditionalFeature.UNRESOLVED))
        # other sub-keys (description, tag, ...) are irrelevant

    def _address_group(self, t: ObjectTable, tokens: list[Token]) -> None:
        name = _flat(tokens[1:2])[0]
        if len(tokens) < 4 or not isinstance(tokens[2], str):
            return
        kind = tokens[2]
        if kind == "static":
            members = tuple(_flat(tokens[3:]))
            old = t.addresses.get(name)
            if old is not None and not old.conditional:
                members = old.members + tuple(m for m in members if m not in old.members)
            t.add_address(AddressObject(name, members=members))
        elif kind == "dynamic":
            t.add_address(AddressObject(
                name, conditional=True,
                feature=ConditionalFeature.DYNAMIC_ADDRESS_GROUP))

    def _service(self, t: ObjectTable, tokens: list[Token], lineno: int,
                 result: ParseResult) -> None:
        name = _flat(tokens[1:2])[0]
        if len(tokens) < 5 or tokens[2] != "protocol":
            return  # description, tag, ...
        proto_tok = _flat(tokens[3:4])[0].lower()
        ref = f"service {name}"
        sub = tokens[4]
        if sub in ("source-port",):
            # a source-port restriction is not modelled: the service is a
            # widening of the real one, so it must be conditional
            old = t.services.get(name)
            ports = old.ports if old is not None else ()
            t.add_service(ServiceObject(
                name, ports=ports, conditional=True,
                feature=ConditionalFeature.PARTIAL_MATCH))
            result.add_warning(
                WarningLevel.INFO, "source-port not modelled; service conditional", ref)
            return
        if sub != "port" or len(tokens) < 6:
            return  # override (timeouts), ...
        proto = proto_from(proto_tok)
        exact = proto in (Proto.TCP, Proto.UDP)
        if not exact:
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"protocol {proto_tok!r} not modelled; treated as any (conditional)", ref)
        ports = _parse_ports(proto, _flat(tokens[5:]))
        old = t.services.get(name)
        if ports is None:
            result.add_warning(
                WarningLevel.UNSUPPORTED, "unparseable port spec", ref)
            t.add_service(ServiceObject(
                name, ports=(PortRange.any(),), conditional=True,
                feature=ConditionalFeature.UNRESOLVED))
            return
        merged = tuple(ports)
        if old is not None:
            merged = old.ports + tuple(p for p in merged if p not in old.ports)
        cond = (old is not None and old.conditional) or not exact
        feat = (old.feature if old is not None and old.conditional
                else (ConditionalFeature.PARTIAL_MATCH if not exact else None))
        t.add_service(ServiceObject(name, ports=merged, conditional=cond, feature=feat))

    def _service_group(self, t: ObjectTable, tokens: list[Token]) -> None:
        name = _flat(tokens[1:2])[0]
        if len(tokens) < 4 or tokens[2] != "members":
            return
        members = tuple(_flat(tokens[3:]))
        old = t.services.get(name)
        if old is not None and old.members:
            members = old.members + tuple(m for m in members if m not in old.members)
        t.add_service(ServiceObject(name, members=members))

    # -- rule accumulation -------------------------------------------------
    def _rule_line(self, container: str, phase: str, rest: list[Token]) -> None:
        if not rest:
            return
        name = _flat(rest[:1])[0]
        rd = self.rules.setdefault(
            (container, phase, name), _RuleDef(container, phase, name))
        if len(rest) < 2 or not isinstance(rest[1], str):
            return
        bucket = rd.fields.setdefault(rest[1], [])
        for v in _flat(rest[2:]):
            if v not in bucket:
                bucket.append(v)

    def _nat_line(self, container: str, phase: str, rest: list[Token]) -> None:
        if len(rest) < 2:
            return
        name = _flat(rest[:1])[0]
        f = self.nat.setdefault((container, phase, name), {})
        vals = _flat(rest[1:])
        if rest[1] in ("source", "destination", "disabled"):
            f.setdefault(str(rest[1]), []).extend(_flat(rest[2:]))
        elif "translated-address" in vals:
            k = vals.index("translated-address")
            kind = "dnat" if "destination-translation" in str(rest[1]) else "snat"
            f.setdefault(kind, []).extend(vals[k + 1:])
        elif "bi-directional" in vals:
            k = vals.index("bi-directional")
            f["bidir"] = vals[k + 1:k + 2]

    # -- assembly ----------------------------------------------------------
    def _containers(self) -> list[str]:
        seen: list[str] = []
        for (c, _p, _n) in self.rules:
            if c != _SHARED and c not in seen:
                seen.append(c)
        if not seen and any(c == _SHARED for (c, _p, _n) in self.rules):
            seen.append(_SHARED)
        return seen

    def _merged_table(self, container: str) -> ObjectTable:
        t = ObjectTable()
        for scope in (_SHARED, container):
            src = self.tables.get(scope)
            if src is None:
                continue
            t.addresses.update(src.addresses)
            t.services.update(src.services)
        return t

    def _ordered(self, container: str) -> list[_RuleDef]:
        def phase(c: str, p: str) -> list[_RuleDef]:
            return [rd for (rc, rp, _n), rd in self.rules.items() if rc == c and rp == p]
        if container == _SHARED:
            return [rd for p in _PHASES for rd in phase(_SHARED, p)]
        return (phase(_SHARED, "pre-rulebase") + phase(container, "pre-rulebase")
                + phase(container, "rulebase") + phase(container, "post-rulebase")
                + phase(_SHARED, "post-rulebase"))

    def _build(self, result: ParseResult) -> None:
        containers = self._containers()
        multi = len(containers) > 1
        for container in containers:
            prefix = f"{_display(container)}:" if multi else ""
            table = self._merged_table(container)
            built: list[_Built] = []
            names: set[str] = set()
            for idx, rd in enumerate(self._ordered(container)):
                rid = rd.name if rd.name not in names else f"{rd.name}@{rd.phase}"
                names.add(rid)
                b = self._build_rule_guarded(rd, rid, idx, table, result)
                if b is not None:
                    built.append(b)
            self._apply_nat(container, table, built, result)
            self._emit(container, prefix, built, result)

    def _build_rule_guarded(
        self, rd: _RuleDef, rid: str, idx: int, table: ObjectTable, result: ParseResult,
    ) -> Optional[_Built]:
        try:
            return self._build_rule(rd, rid, idx, table, result)
        except Exception as exc:  # never let one rule sink the parse
            ref = f"{rd.phase} security rules {rd.name}"
            acts = rd.fields.get("action") or ["allow"]
            if acts[0].lower() in _DENY_ACTIONS:
                result.add_warning(
                    WarningLevel.UNSUPPORTED, f"deny rule could not be parsed ({exc!r}); skipped",
                    ref)
                return None
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"rule could not be parsed ({exc!r}); kept as a conditional allow-any", ref)
            any_a = ResolvedAddresses(ANY_CIDRS, True, (ConditionalFeature.UNRESOLVED,))
            rule, warns = build_rule(
                rule_id=rid, action=Action.ALLOW, order=idx, src=any_a, dst=any_a,
                service=ResolvedService((PortRange.any(),)), vendor=VENDOR, raw_ref=ref)
            result.warnings.extend(warns)
            return _Built(rule, [(_ANY, _ANY)], "universal")

    def _build_rule(
        self, rd: _RuleDef, rid: str, idx: int, table: ObjectTable, result: ParseResult,
    ) -> Optional[_Built]:
        f = rd.fields
        base_ref = "rulebase" if rd.phase == "rulebase" else rd.phase
        ref = f"{base_ref} security rules {rd.name}"
        if _is_yes(f.get("disabled")):
            result.add_warning(WarningLevel.INFO, "rule disabled; skipped", ref)
            return None
        if f.get("target"):
            result.add_warning(
                WarningLevel.INFO,
                "Panorama target devices not evaluated; rule assumed to apply", ref)

        feats: list[ConditionalFeature] = []
        acts = f.get("action")
        if acts:
            a = acts[0].lower()
            if a == "allow":
                action = Action.ALLOW
            elif a in _DENY_ACTIONS:
                action = Action.DENY
            else:
                action = Action.ALLOW
                feats.append(ConditionalFeature.UNRESOLVED)
                result.add_warning(
                    WarningLevel.UNSUPPORTED,
                    f"unknown action {a!r}; modelled as a conditional allow", ref)
        else:
            action = Action.ALLOW  # PAN-OS default action is allow
            result.add_warning(
                WarningLevel.INFO, "no action set; PAN-OS default is allow", ref)

        src = self._side(table, f, "source", "negate-source", ref, result)
        dst = self._side(table, f, "destination", "negate-destination", ref, result)
        if src is None or dst is None:
            result.add_warning(
                WarningLevel.INFO, "negated address matches nothing; rule never matches", ref)
            return None

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
            elif tok in table.services:
                parts.append(table.resolve_service(tok))
            else:
                # PAN-OS has no generic named services: an undefined name is
                # an object we did not see (e.g. Panorama shared), never a
                # well-known port.
                parts.append(ResolvedService(
                    (PortRange.any(),), True, (ConditionalFeature.UNRESOLVED,), (tok,)))
        service = _merge_services(parts)

        if app_default or not _is_any(f.get("application")):
            feats.append(ConditionalFeature.APP_ID)
        for fld, feat in _RUNTIME_FIELDS.items():
            if f.get(fld) and not _is_any(f.get(fld)):
                feats.append(feat)

        rule, warns = build_rule(
            rule_id=rid, action=action, order=idx, src=src, dst=dst,
            service=service, vendor=VENDOR, raw_ref=ref,
            extra_conditional=bool(feats),
            extra_features=tuple(dict.fromkeys(feats)))
        result.warnings.extend(warns)

        froms = f.get("from") or [_ANY]
        tos = f.get("to") or [_ANY]
        rtype = (f.get("rule-type") or ["universal"])[0].lower()
        pairs = list(itertools.product(froms, tos))
        if rtype == "intrazone":
            pairs = [(a, b) for a, b in pairs if a == b or _ANY in (a, b)]
        elif rtype == "interzone":
            pairs = [(a, b) for a, b in pairs if a != b or a == _ANY]
        return _Built(rule, pairs, rtype)

    def _side(
        self, table: ObjectTable, f: dict[str, list[str]], fld: str, neg: str, ref: str,
        result: ParseResult,
    ) -> Optional[ResolvedAddresses]:
        """Resolve one side; ``None`` means it matches nothing."""
        toks = f.get(fld) or [_ANY]
        side = _merge_addrs([table.resolve_addresses(t) for t in toks])
        if not _is_yes(f.get(neg)):
            return side
        if side.conditional:
            result.add_warning(
                WarningLevel.UNSUPPORTED,
                f"{neg} over a conditional address cannot be inverted; {fld} widened to any",
                ref)
            return ResolvedAddresses(
                cidrs=ANY_CIDRS, conditional=True,
                features=tuple(sorted(set(side.features) | {ConditionalFeature.UNRESOLVED},
                                      key=lambda x: x.value)),
                unresolved=side.unresolved)
        comp = complement_cidrs(side.cidrs)
        result.add_warning(WarningLevel.INFO, f"{neg} modelled as the exact complement", ref)
        return ResolvedAddresses(tuple(comp)) if comp else None

    # -- NAT -----------------------------------------------------------------
    def _apply_nat(
        self, container: str, table: ObjectTable, built: list[_Built], result: ParseResult,
    ) -> None:
        pairs: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
        any_nat = False
        for (c, _p, name), f in self.nat.items():
            if c not in (container, _SHARED) or _is_yes(f.get("disabled")):
                continue
            def res(toks: list[str]) -> tuple[str, ...]:
                if _is_any(toks):
                    return ()
                r = _merge_addrs([table.resolve_addresses(t) for t in toks])
                return () if set(r.cidrs) <= set(ANY_CIDRS) else tuple(r.cidrs)
            if f.get("dnat"):
                any_nat = True
                pairs.append((res(f["dnat"]), res(f.get("destination", []))))
            if f.get("snat") and _is_yes(f.get("bidir")):
                any_nat = True
                pairs.append((res(f.get("source", [])), res(f["snat"])))
        if not any_nat:
            return
        result.add_warning(
            WarningLevel.CONDITIONAL,
            "destination NAT is configured: security rules match the pre-NAT "
            "destination; rules touching a translated address are widened to both "
            "halves and flagged conditional", _display(container))
        pairs = [(r, m) for r, m in pairs if r and m]
        for b in built:
            nr, changed = apply_nat_overapprox(b.rule, pairs)
            if changed:
                b.rule = nr
                result.warnings.append(ParseWarning(
                    WarningLevel.CONDITIONAL,
                    CONDITIONAL_REASON[ConditionalFeature.NAT], b.rule.raw_ref))

    # -- rule sets -------------------------------------------------------------
    def _emit(
        self, container: str, prefix: str, built: list[_Built], result: ParseResult,
    ) -> None:
        defaults = dict(self.defaults.get(_SHARED, {}))
        defaults.update(self.defaults.get(container, {}))
        intra = Action.DENY if defaults.get("intrazone-default") in _DENY_ACTIONS \
            else Action.ALLOW
        inter = Action.ALLOW if defaults.get("interzone-default") == "allow" \
            else Action.DENY

        keys: list[tuple[str, str]] = []
        for b in built:
            for p in b.pairs:
                if p not in keys:
                    keys.append(p)
        # every concrete zone has intrazone traffic (allowed by default)
        zones: list[str] = []
        for kf, kt in keys:
            for z in (kf, kt):
                if z != _ANY and z not in zones:
                    zones.append(z)
        for z in self.zones.get(container, []):
            if z not in zones:
                zones.append(z)
        for z in zones:
            if (z, z) not in keys:
                keys.append((z, z))

        def applies(b: _Built, kf: str, kt: str) -> bool:
            if not any((rf == kf or rf == _ANY) and (rt == kt or rt == _ANY)
                       for rf, rt in b.pairs):
                return False
            if b.rule_type == "universal":
                return True
            if _ANY in (kf, kt):
                # mixed intra/inter set: keep a typed allow (over-approximates
                # open), drop a typed deny (it may not apply here)
                return b.rule.action is Action.ALLOW
            return (kf == kt) == (b.rule_type == "intrazone")

        for kf, kt in keys:
            rules = [b.rule for b in built if applies(b, kf, kt)]
            if _ANY in (kf, kt):
                default = Action.ALLOW if Action.ALLOW in (intra, inter) else Action.DENY
            else:
                default = intra if kf == kt else inter
            rid = f"{prefix}{kf}>{kt}"
            result.rulesets[rid] = RuleSet(
                id=rid, rules=rules,  # type: ignore[arg-type]
                default_action=default, vendor=VENDOR)
            result.bindings.append(
                RuleSetBinding(ruleset_id=rid, src_zone=kf, dst_zone=kt))
            if _ANY in (kf, kt) and intra != inter:
                result.add_warning(
                    WarningLevel.INFO,
                    "zone pair with 'any' mixes intrazone (default "
                    f"{intra.value}) and interzone (default {inter.value}) traffic; "
                    "default_action ALLOW is modelled", rid)
