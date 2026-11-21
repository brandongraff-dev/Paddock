"""Jira (Cloud REST v3 and Data Center / Server REST v2), two-way.

Outbound: create / update / transition / comment, see ``_ticketing``.
Auth: Cloud uses ``email`` + ``api_token`` (HTTP basic); Data Center uses a
personal access token ``pat`` (Bearer).

Inbound: a Jira webhook (Settings -> System -> WebHooks, or an Automation
"Send web request") pointed at ``/v1/integrations/<id>/inbound``. With a
``webhook_secret`` set, Jira Cloud signs the body and we verify
``X-Hub-Signature: sha256=<hex>`` in constant time; otherwise the URL must
carry the integration's ``?token=`` (verified by the router).
"""
from __future__ import annotations

import base64
from typing import Any, Mapping, Optional

from ..base import Event, HealthResult, register
from ._ticketing import (
    CAT_ACTIVE,
    CAT_DONE,
    CAT_NEW,
    COMMENT_PREFIX,
    MARKER_PREFIX,
    ExternalRef,
    FindingView,
    NotFound,
    RemoteError,
    TicketConnector,
    TicketInboundUpdate,
    finding_id_from_marker,
    lower_headers,
    parse_json,
    summary_for,
    verify_hmac_sha256,
)

DEFAULT_PRIORITIES = {
    "critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest",
}
_CATEGORY = {"new": CAT_NEW, "indeterminate": CAT_ACTIVE, "done": CAT_DONE}
_ACCEPT_RESOLUTIONS = {"won't do", "won't fix", "wont do", "wont fix", "risk accepted", "accepted"}
_FP_RESOLUTIONS = {"not a bug", "invalid", "cannot reproduce", "false positive", "not an issue"}
_IGNORE_RESOLUTIONS = {"duplicate"}


def _text(value: Any) -> str:
    """Plain text of an ADF node (v3) or a string (v2)."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        if value.get("type") == "text":
            return str(value.get("text") or "")
        parts = [_text(c) for c in value.get("content") or []]
        sep = "\n" if value.get("type") in ("doc",) else ""
        return sep.join(p for p in parts if p)
    if isinstance(value, list):
        return "".join(_text(v) for v in value)
    return ""


def _t(text: str, *marks: dict[str, Any]) -> dict[str, Any]:
    node: dict[str, Any] = {"type": "text", "text": text}
    if marks:
        node["marks"] = list(marks)
    return node


def _para(*nodes: dict[str, Any]) -> dict[str, Any]:
    return {"type": "paragraph", "content": [n for n in nodes if n.get("text")]}


def adf_description(fv: FindingView) -> dict[str, Any]:
    """Atlassian Document Format body for a finding."""
    strong = {"type": "strong"}
    content: list[dict[str, Any]] = [
        _para(_t(f"{k}: ", strong), _t(v)) for k, v in fv.facts()
    ]
    content.append({"type": "heading", "attrs": {"level": 3}, "content": [_t("Why it matters")]})
    content.append(_para(_t(fv.why)))
    if fv.remediation:
        content.append({"type": "heading", "attrs": {"level": 3}, "content": [_t("Remediation")]})
        content.append(_para(_t(fv.remediation)))
    if fv.url:
        content.append(_para(_t("Open in Paddock", {"type": "link", "attrs": {"href": fv.url}})))
    content.append(_para(_t(f"{fv.marker} (used for two-way sync)", {"type": "code"})))
    return {"type": "doc", "version": 1, "content": content}


def wiki_description(fv: FindingView) -> str:
    """Jira wiki markup body (Data Center / REST v2)."""
    lines = [f"*{k}:* {v}" for k, v in fv.facts()]
    lines += ["", "h3. Why it matters", fv.why]
    if fv.remediation:
        lines += ["", "h3. Remediation", fv.remediation]
    if fv.url:
        lines += ["", f"[Open in Paddock|{fv.url}]"]
    lines += ["", f"{{{{{fv.marker}}}}} (used for two-way sync)"]
    return "\n".join(lines)


@register
class JiraConnector(TicketConnector):
    kind = "jira"
    display_name = "Jira"
    docs_url = "docs/INTEGRATIONS-TICKETING.md#jira"
    secret_fields = ("api_token", "pat", "webhook_secret")
    config_schema = {
        "type": "object",
        "required": ["base_url", "project_key"],
        "properties": {
            "base_url": {"type": "string", "format": "uri", "title": "Base URL",
                         "description": "https://acme.atlassian.net or your Data Center URL"},
            "deployment": {"type": "string", "enum": ["cloud", "datacenter"], "default": "cloud"},
            "email": {"type": "string", "title": "Account email (Cloud)"},
            "project_key": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_]*$"},
            "issue_type": {"type": "string", "default": "Bug"},
            "priority_map": {"type": "object", "title": "Severity -> priority name",
                             "additionalProperties": {"type": "string"}},
            "set_priority": {"type": "boolean", "default": True},
            "component": {"type": "string"},
            "labels": {"type": "array", "items": {"type": "string"}},
            "done_transition": {"type": "string", "description": "Transition or status name; default: first to a Done-category status"},
            "done_resolution": {"type": "string", "description": "Resolution to set when closing (Data Center screens often require it)"},
            "reopen_transition": {"type": "string", "description": "Default: first to a To Do-category status"},
            "status_map": {"type": "object", "description": "Jira status name -> Paddock status (overrides the category mapping)",
                           "additionalProperties": {"type": "string", "enum": ["open", "triaged", "fixed", "accepted", "false_positive"]}},
            "sync_comments": {"type": "boolean", "default": True},
        },
    }

    # -- plumbing ------------------------------------------------------------ #
    @property
    def _base(self) -> str:
        return str(self.config.get("base_url") or "").rstrip("/")

    @property
    def _cloud(self) -> bool:
        return (self.config.get("deployment") or "cloud") == "cloud"

    @property
    def _api(self) -> str:
        return f"{self._base}/rest/api/{'3' if self._cloud else '2'}"

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        pat = self.secrets.get("pat")
        token = self.secrets.get("api_token")
        email = self.secrets.get("email") or self.config.get("email")
        if pat and (not self._cloud or not token):
            h["Authorization"] = f"Bearer {pat}"
        elif token and email:
            raw = base64.b64encode(f"{email}:{token}".encode()).decode()
            h["Authorization"] = f"Basic {raw}"
        return h

    async def _call(self, method: str, path: str, **kw: Any):
        if not self._base:
            raise RemoteError("base_url is not configured", retryable=False)
        return await self._request(method, f"{self._api}{path}", headers=self._headers(), **kw)

    def _browse(self, key: str) -> str:
        return f"{self._base}/browse/{key}"

    def _ref(self, issue: Mapping[str, Any]) -> ExternalRef:
        key = str(issue.get("key") or issue.get("id"))
        status = ((issue.get("fields") or {}).get("status") or {})
        cat = (status.get("statusCategory") or {}).get("key")
        return ExternalRef(
            external_id=key, external_url=self._browse(key),
            status=status.get("name"), category=_CATEGORY.get(cat), display=key,
        )

    def _body(self, text: str) -> Any:
        if self._cloud:
            return {"type": "doc", "version": 1, "content": [_para(_t(text))]}
        return text

    def _fields(self, fv: FindingView, *, create: bool) -> dict[str, Any]:
        f: dict[str, Any] = {
            "summary": summary_for(fv, 250),
            "description": adf_description(fv) if self._cloud else wiki_description(fv),
        }
        if self.config.get("set_priority", True):
            pmap = {**DEFAULT_PRIORITIES, **(self.config.get("priority_map") or {})}
            if pmap.get(fv.severity):
                f["priority"] = {"name": pmap[fv.severity]}
        if create:
            f["project"] = {"key": self.config.get("project_key")}
            f["issuetype"] = {"name": self.config.get("issue_type") or "Bug"}
            labels = [str(x).replace(" ", "-") for x in (self.config.get("labels") or [])]
            f["labels"] = sorted({"paddock", fv.marker, *labels})
            if self.config.get("component"):
                f["components"] = [{"name": self.config["component"]}]
        return f

    # -- TicketConnector hooks ------------------------------------------------ #
    async def _find(self, fv: FindingView) -> Optional[ExternalRef]:
        project = str(self.config.get("project_key") or "").replace('"', "").replace("\\", "")
        jql = f'project = "{project}" AND labels = "{fv.marker}" ORDER BY created ASC'
        path = "/search/jql" if self._cloud else "/search"
        resp = await self._call("GET", path, params={"jql": jql, "fields": "status", "maxResults": 1})
        issues = (resp.json() or {}).get("issues") or []
        return self._ref(issues[0]) if issues else None

    async def _get(self, external_id: str) -> Optional[ExternalRef]:
        try:
            resp = await self._call("GET", f"/issue/{external_id}", params={"fields": "status"})
        except NotFound:
            return None
        return self._ref(resp.json())

    async def _create(self, fv: FindingView, event: Event) -> ExternalRef:
        resp = await self._call("POST", "/issue", json={"fields": self._fields(fv, create=True)})
        data = resp.json() or {}
        key = str(data.get("key") or data.get("id"))
        return ExternalRef(external_id=key, external_url=self._browse(key),
                           status=None, category=CAT_NEW, display=key)

    async def _update(self, ref: ExternalRef, fv: FindingView, event: Event) -> ExternalRef:
        await self._call("PUT", f"/issue/{ref.external_id}", json={"fields": self._fields(fv, create=False)})
        return ref

    async def _transition(self, ref: ExternalRef, wanted: Optional[str], categories: tuple[str, ...]) -> ExternalRef:
        resp = await self._call("GET", f"/issue/{ref.external_id}/transitions")
        transitions = (resp.json() or {}).get("transitions") or []
        chosen = None
        if wanted:
            w = wanted.strip().lower()
            chosen = next((t for t in transitions if str(t.get("name", "")).lower() == w
                           or str((t.get("to") or {}).get("name", "")).lower() == w), None)
        for cat in categories:
            if chosen:
                break
            chosen = next((t for t in transitions
                           if ((t.get("to") or {}).get("statusCategory") or {}).get("key") == cat), None)
        if not chosen:
            raise RemoteError(f"no Jira transition from '{ref.status}' to "
                              f"{wanted or '/'.join(categories)} is available", retryable=False)
        payload: dict[str, Any] = {"transition": {"id": str(chosen["id"])}}
        if categories[0] == "done" and self.config.get("done_resolution"):
            payload["fields"] = {"resolution": {"name": self.config["done_resolution"]}}
        await self._call("POST", f"/issue/{ref.external_id}/transitions", json=payload)
        to = chosen.get("to") or {}
        cat = (to.get("statusCategory") or {}).get("key")
        return ExternalRef(ref.external_id, ref.external_url, to.get("name") or ref.status,
                           _CATEGORY.get(cat, CAT_DONE if categories[0] == "done" else CAT_NEW), ref.display)

    async def _close(self, ref: ExternalRef, fv: FindingView, event: Event) -> ExternalRef:
        new = await self._transition(ref, self.config.get("done_transition"), ("done",))
        await self._comment(new, f"{COMMENT_PREFIX} Paddock verified this finding as fixed.")
        return new

    async def _reopen(self, ref: ExternalRef, fv: FindingView, event: Event) -> ExternalRef:
        new = await self._transition(ref, self.config.get("reopen_transition"), ("new", "indeterminate"))
        await self._comment(new, f"{COMMENT_PREFIX} Paddock observed this finding again; reopened.")
        return new

    async def _comment(self, ref: ExternalRef, text: str) -> None:
        await self._call("POST", f"/issue/{ref.external_id}/comment", json={"body": self._body(text)})

    async def test(self) -> HealthResult:
        async def _run() -> HealthResult:
            me = (await self._call("GET", "/myself")).json() or {}
            key = self.config.get("project_key")
            if key:
                await self._call("GET", f"/project/{key}")
            who = me.get("displayName") or "the configured account"
            return HealthResult(ok=True, detail=f"authenticated as {who}; project {key} reachable")
        return await self._health(_run())

    # -- inbound -------------------------------------------------------------- #
    def delivery_id(self, headers: Mapping[str, str], body: bytes) -> Optional[str]:
        return lower_headers(headers).get("x-atlassian-webhook-identifier")

    def map_status(self, fields: Mapping[str, Any]) -> Optional[str]:
        status = fields.get("status") or {}
        name = status.get("name")
        override = self.status_override(name)
        if override:
            return override
        cat = (status.get("statusCategory") or {}).get("key")
        if cat == "done":
            res = str(((fields.get("resolution") or {}).get("name")) or "").strip().lower()
            if res in _IGNORE_RESOLUTIONS:
                return None
            if res in _ACCEPT_RESOLUTIONS:
                return "accepted"
            if res in _FP_RESOLUTIONS:
                return "false_positive"
            return "fixed"
        if cat == "indeterminate":
            return "triaged"
        if cat == "new":
            return "open"
        return None

    async def handle_inbound(self, headers: Mapping[str, str], body: bytes) -> list[TicketInboundUpdate]:
        h = lower_headers(headers)
        secret = self.secrets.get("webhook_secret")
        self.check_inbound_auth(
            verify_hmac_sha256(secret, body, h.get("x-hub-signature")) if secret else None
        )
        payload = parse_json(body)
        if not isinstance(payload, Mapping):
            raise ValueError("expected a JSON object")
        issue = payload.get("issue") or {}
        if not isinstance(issue, Mapping) or not (issue.get("key") or issue.get("id")):
            return []
        key = str(issue.get("key") or issue.get("id"))
        fields = issue.get("fields") or {}
        event = str(payload.get("webhookEvent") or "")
        if event in ("jira:issue_created", "jira:issue_deleted"):
            return []
        status: Optional[str] = None
        if event.startswith("jira:issue_updated") or not event:
            changelog = payload.get("changelog")
            changed = True
            if isinstance(changelog, Mapping):
                changed = any(str(i.get("field", "")).lower() in ("status", "resolution")
                              for i in changelog.get("items") or [])
            if changed:
                status = self.map_status(fields)
        comment_text: Optional[str] = None
        comment = payload.get("comment")
        if isinstance(comment, Mapping) and self.config.get("sync_comments", True) \
                and event not in ("comment_deleted", "comment_updated"):
            text = _text(comment.get("body")).strip()
            if text and not text.startswith(COMMENT_PREFIX):
                comment_text = text
        if status is None and comment_text is None:
            return []
        labels = fields.get("labels") or []
        fid = next((finding_id_from_marker(lbl) for lbl in labels
                    if str(lbl).startswith(MARKER_PREFIX) and finding_id_from_marker(lbl)), None)
        user = payload.get("user") or (comment or {}).get("author") or {}
        return [TicketInboundUpdate(
            external_id=key, finding_id=fid, status=status, comment=comment_text,
            actor=(user.get("displayName") if isinstance(user, Mapping) else None),
            external_status=(fields.get("status") or {}).get("name"),
            external_url=self._browse(key) if self._base else None,
        )]
