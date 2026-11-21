"""Stateful fakes of the Jira / ServiceNow / Linear APIs on httpx.MockTransport.

Shared by test_ticketing_connectors.py and test_ticketing_inbound.py.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import uuid
from typing import Any
from urllib.parse import parse_qs

import httpx

from app.integrations import Event, netsafety

FID = "11111111-2222-4333-8444-555555555555"


def finding_event(type_: str = "finding.opened", fid: str = FID, **data: Any) -> Event:
    payload = {
        "finding_id": fid, "asset": {"value": "shop.example.com"}, "rule_id": "tls-weak",
        "description": "TLS 1.0 enabled", "impact": "Attackers can downgrade sessions.",
        "remediation": "Disable TLS 1.0/1.1.", "cvss": 5.3, **data,
    }
    return Event(type=type_, title="Weak TLS on shop", severity=data.pop("severity", "high"),
                 data=payload, url=f"https://paddock.example.com/findings/{fid}")


def sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


async def allow_all(url: str, *, allow_private: bool = False) -> str:
    """Stand-in for netsafety.validate_outbound_url without DNS. Keeps the
    real scheme/creds/metadata checks for IP-literal URLs."""
    if "blocked.invalid" in url:
        raise netsafety.UnsafeURL("blocked.invalid resolves to a private address")
    if url.startswith("http://") and not allow_private:
        raise netsafety.UnsafeURL("plain http is only allowed for private targets with allow_private")
    return url


# --------------------------------------------------------------------------- #
# Jira
# --------------------------------------------------------------------------- #

_JIRA_STATUSES = {
    "To Do": "new", "In Progress": "indeterminate", "Done": "done",
}


class FakeJira:
    def __init__(self, base: str = "https://acme.atlassian.net", version: str = "3") -> None:
        self.base = base
        self.v = version
        self.issues: dict[str, dict[str, Any]] = {}
        self.comments: dict[str, list[Any]] = {}
        self.requests: list[httpx.Request] = []
        self.fail_with: int | None = None
        self.fail_body: dict[str, Any] | None = None
        self._n = 0

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def _status(self, name: str) -> dict[str, Any]:
        return {"name": name, "statusCategory": {"key": _JIRA_STATUSES[name]}}

    def calls(self, method: str, frag: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method and frag in r.url.path]

    def handle(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if self.fail_with:
            return httpx.Response(self.fail_with, json=self.fail_body or {"errorMessages": ["boom"]})
        api = f"/rest/api/{self.v}"
        path = req.url.path
        if not path.startswith(api):
            return httpx.Response(404)
        p = path[len(api):]
        if p == "/myself":
            return httpx.Response(200, json={"displayName": "Paddock Bot"})
        if p.startswith("/project/"):
            return httpx.Response(200, json={"key": p.split("/")[-1]})
        if p in ("/search/jql", "/search"):
            jql = req.url.params.get("jql", "")
            m = re.search(r'labels = "([^"]+)"', jql)
            hits = [{"key": k, "fields": {"status": i["status"]}} for k, i in self.issues.items()
                    if m and m.group(1) in i["fields"].get("labels", [])]
            return httpx.Response(200, json={"issues": hits[:1]})
        if p == "/issue" and req.method == "POST":
            self._n += 1
            key = f"SEC-{self._n}"
            fields = json.loads(req.content)["fields"]
            self.issues[key] = {"fields": fields, "status": self._status("To Do")}
            return httpx.Response(201, json={"id": str(10000 + self._n), "key": key})
        m = re.fullmatch(r"/issue/([A-Z]+-\d+)(/transitions|/comment)?", p)
        if not m:
            return httpx.Response(404)
        key, sub = m.group(1), m.group(2)
        issue = self.issues.get(key)
        if issue is None:
            return httpx.Response(404, json={"errorMessages": ["Issue does not exist"]})
        if sub is None and req.method == "GET":
            return httpx.Response(200, json={"key": key, "fields": {"status": issue["status"]}})
        if sub is None and req.method == "PUT":
            issue["fields"].update(json.loads(req.content)["fields"])
            return httpx.Response(204)
        if sub == "/transitions" and req.method == "GET":
            return httpx.Response(200, json={"transitions": [
                {"id": "11", "name": "Back to To Do", "to": self._status("To Do")},
                {"id": "21", "name": "Start", "to": self._status("In Progress")},
                {"id": "31", "name": "Resolve", "to": self._status("Done")},
            ]})
        if sub == "/transitions" and req.method == "POST":
            tid = json.loads(req.content)["transition"]["id"]
            issue["status"] = self._status({"11": "To Do", "21": "In Progress", "31": "Done"}[tid])
            return httpx.Response(204)
        if sub == "/comment":
            self.comments.setdefault(key, []).append(json.loads(req.content)["body"])
            return httpx.Response(201, json={"id": "1"})
        return httpx.Response(405)


def jira_webhook(key: str = "SEC-1", status: str = "Done", *, resolution: str | None = None,
                 changelog_field: str | None = "status", fid: str | None = FID,
                 comment: str | None = None, event: str = "jira:issue_updated") -> bytes:
    cat = _JIRA_STATUSES.get(status, "indeterminate")
    fields: dict[str, Any] = {"status": {"name": status, "statusCategory": {"key": cat}},
                              "labels": ["paddock"] + ([f"paddock-{fid}"] if fid else [])}
    if resolution:
        fields["resolution"] = {"name": resolution}
    body: dict[str, Any] = {"webhookEvent": event, "user": {"displayName": "Alice"},
                            "issue": {"id": "10001", "key": key, "fields": fields}}
    if changelog_field:
        body["changelog"] = {"items": [{"field": changelog_field, "toString": status}]}
    else:
        body["changelog"] = {"items": [{"field": "summary"}]}
    if comment is not None:
        body["comment"] = {"body": {"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": comment}]}]},
            "author": {"displayName": "Bob"}}
    return json.dumps(body).encode()


# --------------------------------------------------------------------------- #
# ServiceNow
# --------------------------------------------------------------------------- #

class FakeServiceNow:
    def __init__(self, base: str = "https://acme.service-now.com", table: str = "incident") -> None:
        self.base = base
        self.table = table
        self.records: dict[str, dict[str, Any]] = {}
        self.requests: list[httpx.Request] = []
        self.token_calls = 0
        self._n = 0

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def calls(self, method: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method and "/api/now/" in r.url.path]

    def handle(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        path = req.url.path
        if path == "/oauth_token.do":
            self.token_calls += 1
            form = parse_qs(req.content.decode())
            if form.get("client_secret") != ["cs3cr3t"]:
                return httpx.Response(401, json={"error": "access_denied"})
            return httpx.Response(200, json={"access_token": "tok-abc", "expires_in": 1800})
        prefix = f"/api/now/table/{self.table}"
        if not path.startswith(prefix):
            return httpx.Response(404)
        rest = path[len(prefix):]
        if rest == "" and req.method == "GET":
            q = req.url.params.get("sysparm_query", "")
            m = re.fullmatch(r"correlation_id=(.+)", q)
            rows = [r for r in self.records.values() if m and r.get("correlation_id") == m.group(1)]
            if not m:
                rows = list(self.records.values())
            return httpx.Response(200, json={"result": rows[:1]})
        if rest == "" and req.method == "POST":
            self._n += 1
            sys_id = uuid.uuid4().hex
            rec = {**json.loads(req.content), "sys_id": sys_id, "number": f"INC00{self._n:05d}",
                   "state": "1"}
            self.records[sys_id] = rec
            return httpx.Response(201, json={"result": rec})
        sys_id = rest.lstrip("/")
        rec = self.records.get(sys_id)
        if rec is None:
            return httpx.Response(404, json={"error": {"message": "No Record found"}})
        if req.method == "GET":
            return httpx.Response(200, json={"result": rec})
        if req.method == "PATCH":
            patch = json.loads(req.content)
            for jf in ("work_notes", "comments"):
                if jf in patch:
                    rec.setdefault(f"_{jf}", []).append(patch.pop(jf))
            rec.update({k: str(v) if k == "state" else v for k, v in patch.items()})
            return httpx.Response(200, json={"result": rec})
        return httpx.Response(405)


def basic(user: str, pw: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


# --------------------------------------------------------------------------- #
# Linear
# --------------------------------------------------------------------------- #

class FakeLinear:
    STATES = [
        {"id": "st-backlog", "name": "Backlog", "type": "backlog", "position": 0},
        {"id": "st-todo", "name": "Todo", "type": "unstarted", "position": 1},
        {"id": "st-prog", "name": "In Progress", "type": "started", "position": 2},
        {"id": "st-done", "name": "Done", "type": "completed", "position": 3},
        {"id": "st-cancel", "name": "Canceled", "type": "canceled", "position": 4},
    ]

    def __init__(self) -> None:
        self.issues: dict[str, dict[str, Any]] = {}
        self.comments: list[dict[str, Any]] = []
        self.requests: list[httpx.Request] = []
        self.ops: list[str] = []
        self.rate_limited = False
        self._n = 0

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def _state(self, sid: str) -> dict[str, Any]:
        s = next(s for s in self.STATES if s["id"] == sid)
        return {"id": s["id"], "name": s["name"], "type": s["type"]}

    def _issue(self, i: dict[str, Any]) -> dict[str, Any]:
        return {"id": i["id"], "identifier": i["identifier"], "url": i["url"],
                "state": self._state(i["stateId"])}

    def handle(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if req.url.host != "api.linear.app" or req.url.path != "/graphql":
            return httpx.Response(404)
        if self.rate_limited:
            return httpx.Response(200, json={"errors": [{"message": "slow down",
                                                         "extensions": {"code": "RATELIMITED"}}]})
        body = json.loads(req.content)
        q, v = body["query"], body.get("variables") or {}
        if "issueCreate" in q:
            self.ops.append("create")
            self._n += 1
            iid = str(uuid.uuid4())
            inp = v["input"]
            self.issues[iid] = {"id": iid, "identifier": f"ENG-{self._n}",
                                "url": f"https://linear.app/acme/issue/ENG-{self._n}",
                                "stateId": "st-todo", **inp}
            return httpx.Response(200, json={"data": {"issueCreate": {
                "success": True, "issue": self._issue(self.issues[iid])}}})
        if "issueUpdate" in q:
            self.ops.append("update")
            i = self.issues.get(v["id"])
            if not i:
                return httpx.Response(200, json={"errors": [{"message": "Entity not found"}]})
            i.update(v["input"])
            return httpx.Response(200, json={"data": {"issueUpdate": {"success": True, "issue": self._issue(i)}}})
        if "commentCreate" in q:
            self.ops.append("comment")
            self.comments.append(v["input"])
            return httpx.Response(200, json={"data": {"commentCreate": {"success": True}}})
        if "issues(" in q:
            self.ops.append("search")
            hits = [self._issue(i) for i in self.issues.values()
                    if v["marker"] in (i.get("description") or "") and i.get("teamId") == v["team"]]
            return httpx.Response(200, json={"data": {"issues": {"nodes": hits[:1]}}})
        if "issue(" in q:
            self.ops.append("get")
            i = self.issues.get(v["id"])
            if not i:
                return httpx.Response(200, json={"errors": [{"message": "Entity not found: Issue"}]})
            return httpx.Response(200, json={"data": {"issue": self._issue(i)}})
        if "states" in q:
            return httpx.Response(200, json={"data": {"team": {"states": {"nodes": self.STATES}}}})
        if "team(" in q:
            return httpx.Response(200, json={"data": {"team": {"id": v["id"], "key": "ENG", "name": "Eng"}}})
        if "viewer" in q:
            return httpx.Response(200, json={"data": {"viewer": {"id": "u1", "name": "Paddock Bot"}}})
        return httpx.Response(400)


def linear_webhook(issue_id: str, state_type: str = "completed", state_name: str = "Done", *,
                   ts_ms: float | None = None, state_changed: bool = True,
                   description: str = "") -> bytes:
    import time

    body = {
        "action": "update", "type": "Issue",
        "actor": {"name": "Carol"},
        "data": {"id": issue_id, "identifier": "ENG-1", "url": "https://linear.app/acme/issue/ENG-1",
                 "description": description, "state": {"id": "x", "name": state_name, "type": state_type}},
        "updatedFrom": {"stateId": "st-todo"} if state_changed else {"title": "old"},
        "webhookTimestamp": ts_ms if ts_ms is not None else time.time() * 1000,
    }
    return json.dumps(body).encode()
