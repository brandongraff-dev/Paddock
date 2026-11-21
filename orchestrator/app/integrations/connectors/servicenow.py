"""ServiceNow (Table API), two-way.

Outbound: records in ``incident`` (default) or ``sn_vul_vulnerable_item``
(or another table you name), keyed by ``correlation_id = paddock-<finding>``.
Auth: basic (``username`` + secret ``password``) or OAuth client credentials
(secrets ``client_id`` + ``client_secret``; token from ``/oauth_token.do``).

Inbound: a Business Rule (async, after update) that POSTs a small JSON
document to ``/v1/integrations/<id>/inbound`` with the shared secret in a
header (default ``X-Paddock-Secret``), compared in constant time. The
script is in docs/INTEGRATIONS-TICKETING.md.
"""
from __future__ import annotations

import base64
import re
import time
from typing import Any, Mapping, Optional

from ..base import Event, HealthResult, register
from ._ticketing import (
    CAT_ACTIVE,
    CAT_DONE,
    CAT_NEW,
    COMMENT_PREFIX,
    ExternalRef,
    FindingView,
    NotFound,
    RemoteError,
    TicketConnector,
    TicketInboundUpdate,
    constant_eq,
    finding_id_from_marker,
    lower_headers,
    parse_json,
    summary_for,
)

# severity -> (impact, urgency); incident priority = f(impact, urgency)
DEFAULT_SEVERITY_MAP: dict[str, dict[str, int]] = {
    "critical": {"impact": 1, "urgency": 1},
    "high": {"impact": 1, "urgency": 2},
    "medium": {"impact": 2, "urgency": 2},
    "low": {"impact": 2, "urgency": 3},
    "info": {"impact": 3, "urgency": 3},
}

# Per-table defaults: state values and their Paddock meaning.
_TABLES: dict[str, dict[str, Any]] = {
    "incident": {
        "resolved_state": "6", "reopen_state": "2",
        "states": {"1": "open", "2": "triaged", "3": "triaged", "6": "fixed", "7": "fixed", "8": "accepted"},
        "done": {"6", "7", "8"}, "new": {"1"},
    },
    "sn_vul_vulnerable_item": {
        "resolved_state": "3", "reopen_state": "1",
        "states": {"1": "open", "2": "triaged", "10": "triaged", "11": "triaged",
                   "3": "fixed", "13": "accepted"},
        "done": {"3"}, "new": {"1"},
    },
}
_GENERIC = {"resolved_state": "6", "reopen_state": "2", "states": {}, "done": set(), "new": set()}
_TABLE_RE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")


def _close_code_status(text: Any) -> Optional[str]:
    t = str(text or "").lower()
    if "false positive" in t or "false_positive" in t or "not a vulnerability" in t:
        return "false_positive"
    if "risk accept" in t or "accepted" in t or "won't fix" in t or "deferred" in t or "exception" in t:
        return "accepted"
    return None


@register
class ServiceNowConnector(TicketConnector):
    kind = "servicenow"
    display_name = "ServiceNow"
    docs_url = "docs/INTEGRATIONS-TICKETING.md#servicenow"
    secret_fields = ("password", "client_id", "client_secret", "inbound_secret")
    config_schema = {
        "type": "object",
        "required": ["instance_url"],
        "properties": {
            "instance_url": {"type": "string", "format": "uri", "description": "https://acme.service-now.com"},
            "table": {"type": "string", "default": "incident",
                      "examples": ["incident", "sn_vul_vulnerable_item"]},
            "auth_method": {"type": "string", "enum": ["basic", "oauth"], "default": "basic"},
            "username": {"type": "string"},
            "assignment_group": {"type": "string", "description": "sys_id or name"},
            "category": {"type": "string"},
            "caller_id": {"type": "string"},
            "severity_map": {"type": "object", "description": "severity -> {impact, urgency}"},
            "resolved_state": {"type": "string"},
            "reopen_state": {"type": "string"},
            "close_code": {"type": "string", "default": "Solution provided"},
            "comment_field": {"type": "string", "enum": ["work_notes", "comments"], "default": "work_notes"},
            "extra_fields": {"type": "object", "description": "Merged into every created record"},
            "status_map": {"type": "object", "description": "state value or label -> Paddock status"},
            "inbound_secret_header": {"type": "string", "default": "X-Paddock-Secret"},
        },
    }

    def __init__(self, config: Mapping[str, Any], secrets: Mapping[str, str], http: Any) -> None:
        super().__init__(config, secrets, http)
        self._token: Optional[str] = None
        self._token_exp = 0.0

    # -- plumbing ------------------------------------------------------------ #
    @property
    def _base(self) -> str:
        return str(self.config.get("instance_url") or "").rstrip("/")

    @property
    def _table(self) -> str:
        t = str(self.config.get("table") or "incident")
        if not _TABLE_RE.fullmatch(t):
            raise RemoteError("invalid ServiceNow table name", retryable=False)
        return t

    @property
    def _defaults(self) -> dict[str, Any]:
        return _TABLES.get(self._table, _GENERIC)

    async def _auth_header(self) -> dict[str, str]:
        if (self.config.get("auth_method") or "basic") == "oauth":
            if not self._token or time.monotonic() >= self._token_exp:
                cid, csec = self.secrets.get("client_id"), self.secrets.get("client_secret")
                if not (cid and csec):
                    raise RemoteError("OAuth selected but client_id/client_secret are not set", retryable=False)
                resp = await self._request(
                    "POST", f"{self._base}/oauth_token.do",
                    data={"grant_type": "client_credentials", "client_id": cid, "client_secret": csec},
                    headers={"Accept": "application/json"},
                )
                body = resp.json() or {}
                tok = body.get("access_token")
                if not tok:
                    raise RemoteError("ServiceNow OAuth returned no access_token", retryable=False)
                self._token = str(tok)
                self._token_exp = time.monotonic() + max(30, int(body.get("expires_in") or 1800) - 30)
            return {"Authorization": f"Bearer {self._token}"}
        user, pw = self.config.get("username"), self.secrets.get("password")
        if not (user and pw):
            raise RemoteError("basic auth selected but username/password are not set", retryable=False)
        return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}

    async def _call(self, method: str, path: str, **kw: Any):
        if not self._base:
            raise RemoteError("instance_url is not configured", retryable=False)
        headers = {"Accept": "application/json", "Content-Type": "application/json",
                   **(await self._auth_header())}
        return await self._request(method, f"{self._base}/api/now/table/{self._table}{path}",
                                   headers=headers, **kw)

    def _url(self, sys_id: str) -> str:
        return f"{self._base}/{self._table}.do?sys_id={sys_id}"

    def _category(self, state: Any) -> Optional[str]:
        s = str(state) if state is not None else None
        d = self._defaults
        if s is None:
            return None
        if s in d["done"] or s == str(self.config.get("resolved_state") or ""):
            return CAT_DONE
        if s in d["new"]:
            return CAT_NEW
        return CAT_ACTIVE

    def _ref(self, rec: Mapping[str, Any]) -> ExternalRef:
        sys_id = str(rec.get("sys_id"))
        state = rec.get("state")
        if isinstance(state, Mapping):          # sysparm_display_value=all
            state = state.get("value")
        return ExternalRef(external_id=sys_id, external_url=self._url(sys_id),
                           status=str(state) if state is not None else None,
                           category=self._category(state), display=rec.get("number") or sys_id)

    def _severity_fields(self, fv: FindingView) -> dict[str, Any]:
        smap = {**DEFAULT_SEVERITY_MAP, **(self.config.get("severity_map") or {})}
        return dict(smap.get(fv.severity) or {})

    @property
    def _comment_field(self) -> str:
        f = self.config.get("comment_field") or "work_notes"
        return f if f in ("work_notes", "comments") else "work_notes"

    # -- TicketConnector hooks ------------------------------------------------ #
    async def _find(self, fv: FindingView) -> Optional[ExternalRef]:
        resp = await self._call("GET", "", params={
            "sysparm_query": f"correlation_id={fv.marker}", "sysparm_limit": "1",
            "sysparm_fields": "sys_id,number,state",
        })
        rows = (resp.json() or {}).get("result") or []
        return self._ref(rows[0]) if rows else None

    async def _get(self, external_id: str) -> Optional[ExternalRef]:
        if not re.fullmatch(r"[0-9a-fA-F]{32}", external_id):
            return None
        try:
            resp = await self._call("GET", f"/{external_id}", params={"sysparm_fields": "sys_id,number,state"})
        except NotFound:
            return None
        return self._ref((resp.json() or {}).get("result") or {})

    async def _create(self, fv: FindingView, event: Event) -> ExternalRef:
        rec: dict[str, Any] = {
            "short_description": summary_for(fv, 160),
            "description": fv.plain_text(),
            "correlation_id": fv.marker,
            "correlation_display": "Paddock",
            **self._severity_fields(fv),
        }
        for k in ("assignment_group", "category", "caller_id"):
            if self.config.get(k):
                rec[k] = self.config[k]
        extra = self.config.get("extra_fields") or {}
        if isinstance(extra, Mapping):
            rec.update({str(k): v for k, v in extra.items()})
        resp = await self._call("POST", "", json=rec)
        ref = self._ref((resp.json() or {}).get("result") or {})
        if ref.category is None:
            ref.category = CAT_NEW
        return ref

    async def _update(self, ref: ExternalRef, fv: FindingView, event: Event) -> ExternalRef:
        await self._call("PATCH", f"/{ref.external_id}", json={
            "short_description": summary_for(fv, 160),
            "description": fv.plain_text(),
            **self._severity_fields(fv),
        })
        return ref

    async def _set_state(self, ref: ExternalRef, state: str, extra: dict[str, Any]) -> ExternalRef:
        resp = await self._call("PATCH", f"/{ref.external_id}", json={"state": state, **extra})
        rec = (resp.json() or {}).get("result") or {}
        new = self._ref({"sys_id": ref.external_id, "number": rec.get("number") or ref.display,
                         "state": rec.get("state", state)})
        return new

    async def _close(self, ref: ExternalRef, fv: FindingView, event: Event) -> ExternalRef:
        state = str(self.config.get("resolved_state") or self._defaults["resolved_state"])
        new = await self._set_state(ref, state, {
            "close_code": self.config.get("close_code") or "Solution provided",
            "close_notes": f"{COMMENT_PREFIX} Paddock verified this finding as fixed.",
        })
        new.category = CAT_DONE
        return new

    async def _reopen(self, ref: ExternalRef, fv: FindingView, event: Event) -> ExternalRef:
        state = str(self.config.get("reopen_state") or self._defaults["reopen_state"])
        new = await self._set_state(ref, state, {
            self._comment_field: f"{COMMENT_PREFIX} Paddock observed this finding again; reopened.",
        })
        if new.category == CAT_DONE:
            new.category = CAT_ACTIVE
        return new

    async def _comment(self, ref: ExternalRef, text: str) -> None:
        await self._call("PATCH", f"/{ref.external_id}", json={self._comment_field: text})

    async def test(self) -> HealthResult:
        async def _run() -> HealthResult:
            await self._call("GET", "", params={"sysparm_limit": "1", "sysparm_fields": "sys_id"})
            return HealthResult(ok=True, detail=f"authenticated; table {self._table} readable")
        return await self._health(_run())

    # -- inbound -------------------------------------------------------------- #
    def delivery_id(self, headers: Mapping[str, str], body: bytes) -> Optional[str]:
        return lower_headers(headers).get("x-paddock-delivery")

    def map_state(self, rec: Mapping[str, Any]) -> Optional[str]:
        state = rec.get("state")
        label = rec.get("state_label") or rec.get("state_display")
        override = self.status_override(state, label)
        if override:
            return override
        mapped = self._defaults["states"].get(str(state)) if state is not None else None
        if mapped in ("fixed", "accepted"):
            refined = _close_code_status(rec.get("close_code")) or _close_code_status(rec.get("substate"))
            if refined:
                return refined
        return mapped

    async def handle_inbound(self, headers: Mapping[str, str], body: bytes) -> list[TicketInboundUpdate]:
        h = lower_headers(headers)
        secret = self.secrets.get("inbound_secret")
        header = str(self.config.get("inbound_secret_header") or "X-Paddock-Secret").lower()
        self.check_inbound_auth(constant_eq(h.get(header), secret) if secret else None)
        payload = parse_json(body)
        records = payload if isinstance(payload, list) else [payload]
        out: list[TicketInboundUpdate] = []
        for rec in records[:100]:
            if not isinstance(rec, Mapping) or not rec.get("sys_id"):
                continue
            table = rec.get("table")
            if table and str(table) != self._table:
                continue
            comment = str(rec.get("comment") or rec.get("work_notes") or "").strip() or None
            if comment and comment.startswith(COMMENT_PREFIX):
                comment = None
            status = self.map_state(rec) if rec.get("state") is not None else None
            if status is None and comment is None:
                continue
            sys_id = str(rec["sys_id"])
            out.append(TicketInboundUpdate(
                external_id=sys_id,
                finding_id=finding_id_from_marker(rec.get("correlation_id")),
                status=status, comment=comment,
                actor=str(rec.get("updated_by") or rec.get("sys_updated_by") or "") or None,
                external_status=str(rec.get("state_label") or rec.get("state") or "") or None,
                external_url=self._url(sys_id) if self._base else None,
            ))
        return out
