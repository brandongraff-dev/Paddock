"""Linear (GraphQL API), two-way.

Outbound: ``issueCreate`` / ``issueUpdate`` / ``commentCreate`` in one team.
The ticket body ends with a ``paddock-<finding>`` marker used to find the
issue again when no link row exists. Auth: secret ``api_key`` (a personal
API key ``lin_api_...`` is sent as-is; anything else as a Bearer token).

Inbound: a Linear webhook (Settings -> API -> Webhooks, resource types
Issues + Comments). Linear signs every delivery: ``Linear-Signature`` is the
hex HMAC-SHA256 of the raw body with the webhook's signing secret (secret
``webhook_secret``); ``webhookTimestamp`` must be within 60 s.
"""
from __future__ import annotations

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
    finding_id_from_marker,
    lower_headers,
    parse_json,
    summary_for,
    verify_hmac_sha256,
)

API_URL = "https://api.linear.app/graphql"
# Linear priority: 0 none, 1 urgent, 2 high, 3 medium, 4 low
DEFAULT_PRIORITIES = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 0}
_CATEGORY = {"triage": CAT_NEW, "backlog": CAT_NEW, "unstarted": CAT_NEW,
             "started": CAT_ACTIVE, "completed": CAT_DONE, "canceled": CAT_DONE}
_STATUS = {"triage": "open", "backlog": "open", "unstarted": "open",
           "started": "triaged", "completed": "fixed", "canceled": "accepted"}
MAX_SKEW_SEC = 60

_ISSUE_FIELDS = "id identifier url state { id name type }"


@register
class LinearConnector(TicketConnector):
    kind = "linear"
    display_name = "Linear"
    docs_url = "docs/INTEGRATIONS-TICKETING.md#linear"
    secret_fields = ("api_key", "webhook_secret")
    config_schema = {
        "type": "object",
        "required": ["team_id"],
        "properties": {
            "team_id": {"type": "string", "description": "Team UUID (Cmd-K -> 'Copy model UUID')"},
            "project_id": {"type": "string"},
            "label_ids": {"type": "array", "items": {"type": "string"}, "description": "Always applied"},
            "label_map": {"type": "object", "description": "severity -> label id",
                          "additionalProperties": {"type": "string"}},
            "priority_map": {"type": "object", "description": "severity -> 0..4",
                             "additionalProperties": {"type": "integer", "minimum": 0, "maximum": 4}},
            "done_state_id": {"type": "string", "description": "Default: first 'completed' state"},
            "reopen_state_id": {"type": "string", "description": "Default: first 'unstarted' state"},
            "canceled_status": {"type": "string", "enum": ["accepted", "false_positive", "fixed"],
                                "default": "accepted"},
            "status_map": {"type": "object", "description": "state name or type -> Paddock status"},
            "sync_comments": {"type": "boolean", "default": True},
        },
    }

    def __init__(self, config: Mapping[str, Any], secrets: Mapping[str, str], http: Any) -> None:
        super().__init__(config, secrets, http)
        self._states: Optional[list[dict[str, Any]]] = None

    # -- plumbing ------------------------------------------------------------ #
    def _headers(self) -> dict[str, str]:
        key = self.secrets.get("api_key") or ""
        auth = key if key.startswith("lin_api_") else f"Bearer {key}"
        return {"Authorization": auth, "Content-Type": "application/json"}

    async def gql(self, query: str, variables: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        if not self.secrets.get("api_key"):
            raise RemoteError("api_key is not configured", retryable=False)
        resp = await self._request("POST", API_URL, headers=self._headers(),
                                   json={"query": query, "variables": variables or {}})
        body = resp.json() or {}
        errors = body.get("errors") or []
        if errors:
            codes = {str((e.get("extensions") or {}).get("code") or "").upper() for e in errors}
            msg = "; ".join(str(e.get("message") or "") for e in errors)[:200]
            if "RATELIMITED" in codes:
                raise RemoteError("Linear rate limit hit", 429, retryable=True)
            if "AUTHENTICATION_ERROR" in codes:
                raise RemoteError("Linear rejected the API key", 401, retryable=False)
            if "not found" in msg.lower() or "ENTITY_NOT_FOUND" in codes:
                raise NotFound("Linear entity not found")
            raise RemoteError(f"Linear GraphQL error: {msg}", 400, retryable=False)
        return body.get("data") or {}

    def _ref(self, issue: Mapping[str, Any]) -> ExternalRef:
        state = issue.get("state") or {}
        return ExternalRef(
            external_id=str(issue.get("id")), external_url=issue.get("url"),
            status=state.get("name"), category=_CATEGORY.get(str(state.get("type") or "")),
            display=issue.get("identifier"),
        )

    async def _team_states(self) -> list[dict[str, Any]]:
        if self._states is None:
            data = await self.gql(
                "query($id: String!) { team(id: $id) { states { nodes { id name type position } } } }",
                {"id": self.config.get("team_id")},
            )
            nodes = (((data.get("team") or {}).get("states") or {}).get("nodes")) or []
            self._states = sorted(nodes, key=lambda n: float(n.get("position") or 0))
        return self._states

    async def _state_id(self, configured: Optional[str], types: tuple[str, ...]) -> str:
        if configured:
            return str(configured)
        states = await self._team_states()
        for t in types:
            for s in states:
                if s.get("type") == t:
                    return str(s["id"])
        raise RemoteError(f"Linear team has no workflow state of type {'/'.join(types)}", retryable=False)

    def _priority(self, fv: FindingView) -> int:
        pmap = {**DEFAULT_PRIORITIES, **(self.config.get("priority_map") or {})}
        try:
            return max(0, min(4, int(pmap.get(fv.severity, 0))))
        except (TypeError, ValueError):
            return 0

    # -- TicketConnector hooks ------------------------------------------------ #
    async def _find(self, fv: FindingView) -> Optional[ExternalRef]:
        data = await self.gql(
            f"query($team: ID!, $marker: String!) {{ issues(first: 1, filter: {{"
            f" team: {{ id: {{ eq: $team }} }}, description: {{ contains: $marker }} }}) "
            f"{{ nodes {{ {_ISSUE_FIELDS} }} }} }}",
            {"team": self.config.get("team_id"), "marker": fv.marker},
        )
        nodes = ((data.get("issues") or {}).get("nodes")) or []
        return self._ref(nodes[0]) if nodes else None

    async def _get(self, external_id: str) -> Optional[ExternalRef]:
        try:
            data = await self.gql(f"query($id: String!) {{ issue(id: $id) {{ {_ISSUE_FIELDS} }} }}",
                                  {"id": external_id})
        except NotFound:
            return None
        issue = data.get("issue")
        return self._ref(issue) if issue else None

    async def _create(self, fv: FindingView, event: Event) -> ExternalRef:
        labels = [str(x) for x in (self.config.get("label_ids") or [])]
        sev_label = (self.config.get("label_map") or {}).get(fv.severity)
        if sev_label:
            labels.append(str(sev_label))
        inp: dict[str, Any] = {
            "teamId": self.config.get("team_id"),
            "title": summary_for(fv, 250),
            "description": fv.markdown(),
            "priority": self._priority(fv),
        }
        if labels:
            inp["labelIds"] = sorted(set(labels))
        if self.config.get("project_id"):
            inp["projectId"] = self.config["project_id"]
        data = await self.gql(
            f"mutation($input: IssueCreateInput!) {{ issueCreate(input: $input) "
            f"{{ success issue {{ {_ISSUE_FIELDS} }} }} }}", {"input": inp},
        )
        res = data.get("issueCreate") or {}
        if not res.get("success") or not res.get("issue"):
            raise RemoteError("Linear did not create the issue", retryable=True)
        ref = self._ref(res["issue"])
        ref.category = ref.category or CAT_NEW
        return ref

    async def _issue_update(self, ref: ExternalRef, inp: dict[str, Any]) -> ExternalRef:
        data = await self.gql(
            f"mutation($id: String!, $input: IssueUpdateInput!) {{ issueUpdate(id: $id, input: $input) "
            f"{{ success issue {{ {_ISSUE_FIELDS} }} }} }}", {"id": ref.external_id, "input": inp},
        )
        res = data.get("issueUpdate") or {}
        if not res.get("success"):
            raise RemoteError("Linear did not update the issue", retryable=True)
        return self._ref(res["issue"]) if res.get("issue") else ref

    async def _update(self, ref: ExternalRef, fv: FindingView, event: Event) -> ExternalRef:
        return await self._issue_update(ref, {
            "title": summary_for(fv, 250), "description": fv.markdown(), "priority": self._priority(fv),
        })

    async def _close(self, ref: ExternalRef, fv: FindingView, event: Event) -> ExternalRef:
        sid = await self._state_id(self.config.get("done_state_id"), ("completed",))
        new = await self._issue_update(ref, {"stateId": sid})
        new.category = CAT_DONE
        await self._comment(new, f"{COMMENT_PREFIX} Paddock verified this finding as fixed.")
        return new

    async def _reopen(self, ref: ExternalRef, fv: FindingView, event: Event) -> ExternalRef:
        sid = await self._state_id(self.config.get("reopen_state_id"), ("unstarted", "backlog", "triage"))
        new = await self._issue_update(ref, {"stateId": sid})
        if new.category == CAT_DONE:
            new.category = CAT_NEW
        await self._comment(new, f"{COMMENT_PREFIX} Paddock observed this finding again; reopened.")
        return new

    async def _comment(self, ref: ExternalRef, text: str) -> None:
        await self.gql("mutation($input: CommentCreateInput!) { commentCreate(input: $input) { success } }",
                       {"input": {"issueId": ref.external_id, "body": text}})

    async def test(self) -> HealthResult:
        async def _run() -> HealthResult:
            data = await self.gql("query { viewer { id name } }")
            who = (data.get("viewer") or {}).get("name") or "the API key owner"
            team = self.config.get("team_id")
            if team:
                t = await self.gql("query($id: String!) { team(id: $id) { id key name } }", {"id": team})
                if not t.get("team"):
                    return HealthResult(ok=False, detail="team_id not found")
            return HealthResult(ok=True, detail=f"authenticated as {who}; team reachable")
        return await self._health(_run())

    # -- inbound -------------------------------------------------------------- #
    def delivery_id(self, headers: Mapping[str, str], body: bytes) -> Optional[str]:
        return lower_headers(headers).get("linear-delivery")

    def map_state(self, state: Mapping[str, Any]) -> Optional[str]:
        override = self.status_override(state.get("name"), state.get("type"))
        if override:
            return override
        st = str(state.get("type") or "")
        if st == "canceled":
            c = self.config.get("canceled_status") or "accepted"
            return c if c in ("accepted", "false_positive", "fixed") else "accepted"
        return _STATUS.get(st)

    async def handle_inbound(self, headers: Mapping[str, str], body: bytes) -> list[TicketInboundUpdate]:
        h = lower_headers(headers)
        secret = self.secrets.get("webhook_secret")
        verified = verify_hmac_sha256(secret, body, h.get("linear-signature")) if secret else None
        self.check_inbound_auth(verified)
        payload = parse_json(body)
        if not isinstance(payload, Mapping):
            raise ValueError("expected a JSON object")
        if verified:
            ts = payload.get("webhookTimestamp")
            try:
                skew = abs(time.time() * 1000 - float(ts)) / 1000
            except (TypeError, ValueError):
                raise PermissionError("missing webhookTimestamp") from None
            if skew > MAX_SKEW_SEC:
                raise PermissionError("webhook timestamp outside the allowed window")
        kind, action = payload.get("type"), payload.get("action")
        data = payload.get("data") or {}
        if not isinstance(data, Mapping):
            return []
        actor = (payload.get("actor") or {}).get("name") if isinstance(payload.get("actor"), Mapping) else None
        if kind == "Issue" and action == "update":
            if "stateId" not in (payload.get("updatedFrom") or {}):
                return []
            state = data.get("state") or {}
            status = self.map_state(state) if isinstance(state, Mapping) else None
            if status is None or not data.get("id"):
                return []
            return [TicketInboundUpdate(
                external_id=str(data["id"]), finding_id=finding_id_from_marker(data.get("description")),
                status=status, actor=actor, external_status=state.get("name"), external_url=data.get("url"),
            )]
        if kind == "Comment" and action == "create" and self.config.get("sync_comments", True):
            text = str(data.get("body") or "").strip()
            issue_id = data.get("issueId") or (data.get("issue") or {}).get("id")
            if not text or text.startswith(COMMENT_PREFIX) or not issue_id:
                return []
            user = data.get("user") or {}
            return [TicketInboundUpdate(
                external_id=str(issue_id), comment=text,
                actor=(user.get("name") if isinstance(user, Mapping) else None) or actor,
            )]
        return []
