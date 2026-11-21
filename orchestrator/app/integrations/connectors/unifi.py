"""UniFi Network (ACTION): quarantine / release a client for Paddock Sentry.

Two quarantine modes (``quarantine_mode``):

* ``block`` (default) -- ``cmd/stamgr block-sta``; release is ``unblock-sta``.
  Works on any UniFi Network controller, wired and wireless.
* ``network`` -- move the client to a quarantine network with UniFi's
  per-client *virtual network override* (``rest/user/<id>``), then
  ``kick-sta`` so a wireless client re-associates into it. Release restores
  the client's previous override values. (Wired clients pick up the VLAN on
  their next link/DHCP cycle.)

Controller flavours (``controller_type``): ``unifi_os`` (UDM / UCG / Cloud Key
Gen2+ / UniFi OS Server; API under ``/proxy/network``) or ``classic``
(self-hosted Network application on :8443).

Auth: an API key (``X-API-KEY``, UniFi Network 9+) or a dedicated LOCAL
admin account limited to the Network application with the *Site Admin* role
(username/password; cookie + CSRF token). Logs out after every call.

``test()`` reads the site list only. ``act()`` is called ONLY by the approve
gate; see ``_network.py`` for the invariants. A LAN controller needs the
integration's ``allow_private`` opt-in.
"""
from __future__ import annotations

from typing import Any, Mapping

from ..base import HealthResult, register
from ._common import ActionResult, SourceError, checked_url, request_json
from ._network import NetworkActionConnector


@register
class UniFiConnector(NetworkActionConnector):
    kind = "unifi"
    display_name = "UniFi Network"
    config_schema = {
        "type": "object",
        "required": ["base_url"],
        "properties": {
            "base_url": {"type": "string", "title": "Controller URL, e.g. https://192.168.1.1"},
            "controller_type": {"type": "string", "enum": ["unifi_os", "classic"],
                                "default": "unifi_os"},
            "site": {"type": "string", "default": "default",
                     "description": "Site *name* (the short id in the URL), not its description"},
            "quarantine_mode": {"type": "string", "enum": ["block", "network"], "default": "block"},
            "quarantine_network_id": {"type": "string",
                                      "description": "_id of the quarantine network (mode=network)"},
            "kick_after_move": {"type": "boolean", "default": True},
            "protected_macs": {"type": "array", "items": {"type": "string"},
                               "description": "Never quarantine these (gateway, Sentry sensor...)"},
            "verify_tls": {"type": "boolean", "default": True},
        },
    }
    secret_fields = ("api_key", "username", "password")
    docs_url = "docs/INTEGRATIONS-CONTEXT.md#unifi-network"

    # ------------------------------------------------------------------ #
    def _prefix(self, base: str) -> str:
        return f"{base}/proxy/network" if self._os() else base

    def _os(self) -> bool:
        return str(self.config.get("controller_type") or "unifi_os") == "unifi_os"

    def _site(self) -> str:
        site = str(self.config.get("site") or "default")
        if not site.replace("-", "").replace("_", "").isalnum():
            raise SourceError("invalid site name", retryable=False)
        return site

    async def _session(self) -> tuple[str, dict[str, str]]:
        """Return (network API prefix, headers). Logs in when using a password."""
        base = await checked_url(str(self.config.get("base_url") or ""),
                                 allow_private=self._allow_private())
        hdr = {"Accept": "application/json"}
        if self.secrets.get("api_key"):
            hdr["X-API-KEY"] = self.secrets["api_key"]
            return self._prefix(base), hdr
        user, pw = self.secrets.get("username"), self.secrets.get("password")
        if not user or not pw:
            raise SourceError("api_key or username/password is required", retryable=False)
        login = f"{base}/api/auth/login" if self._os() else f"{base}/api/login"
        try:
            resp = await self.http.request("POST", login, json={"username": user, "password": pw,
                                                                "remember": False})
        except Exception as exc:  # noqa: BLE001 - transport errors: safe, typed message only
            raise SourceError(f"UniFi login: {type(exc).__name__}") from exc
        if resp.status_code >= 400:
            raise SourceError(f"UniFi login: HTTP {resp.status_code} (check the credential)",
                              status_code=resp.status_code, retryable=resp.status_code >= 500)
        csrf = resp.headers.get("x-csrf-token") or resp.headers.get("x-updated-csrf-token")
        if not csrf:
            csrf = self.http.cookies.get("csrf_token") if hasattr(self.http, "cookies") else None
        if csrf:
            hdr["X-CSRF-Token"] = csrf
        return self._prefix(base), hdr

    async def _logout(self, hdr: dict[str, str]) -> None:
        if "X-API-KEY" in hdr:
            return
        try:
            base = str(self.config.get("base_url") or "").rstrip("/")
            url = f"{base}/api/auth/logout" if self._os() else f"{base}/api/logout"
            await self.http.request("POST", url, headers=hdr)
        except Exception:  # noqa: BLE001 - best effort
            pass

    @staticmethod
    def _data(body: Any, what: str) -> list[dict[str, Any]]:
        meta = (body or {}).get("meta") or {}
        if meta.get("rc") not in (None, "ok"):
            msg = str(meta.get("msg") or "error")[:120]
            raise SourceError(f"{what}: controller returned {msg}", status_code=200,
                              retryable=False)
        return [d for d in (body or {}).get("data") or [] if isinstance(d, dict)]

    async def _call(self, method: str, url: str, hdr: dict[str, str], what: str,
                    json: Any = None) -> list[dict[str, Any]]:
        body = await request_json(self.http, method, url, what=what, headers=hdr, json=json,
                                  allow_private=self._allow_private())
        return self._data(body, what)

    # ------------------------------------------------------------------ #
    async def test(self) -> HealthResult:
        hdr: dict[str, str] = {}
        try:
            prefix, hdr = await self._session()
            sites = await self._call("GET", f"{prefix}/api/self/sites", hdr, "UniFi sites")
        except SourceError as exc:
            return HealthResult(ok=False, detail=str(exc))
        finally:
            await self._logout(hdr)
        site = self._site()
        match = next((s for s in sites if s.get("name") == site), None)
        if match is None:
            return HealthResult(ok=False, detail=f"site {site!r} not found on the controller")
        return HealthResult(ok=True, detail=f"UniFi site {match.get('desc') or site!r} reachable")

    async def _act(self, typ: str, mac: str, dry_run: bool,
                   action: Mapping[str, Any]) -> ActionResult:
        mode = str(self.config.get("quarantine_mode") or "block")
        revert_plan = dict(action.get("revert") or {})
        if typ == "release_device" and revert_plan.get("mode"):
            mode = str(revert_plan["mode"])
        hdr: dict[str, str] = {}
        try:
            prefix, hdr = await self._session()
            api = f"{prefix}/api/s/{self._site()}"
            try:
                clients = await self._call("GET", f"{api}/stat/user/{mac}", hdr,
                                           "UniFi client lookup")
            except SourceError as exc:
                if exc.status_code not in (200, 400, 404):
                    raise
                clients = []   # controller has never seen this MAC
            client = clients[0] if clients else None
            if mode == "block":
                cmd = "block-sta" if typ == "quarantine_device" else "unblock-sta"
                planned = [f"POST /api/s/{self._site()}/cmd/stamgr {cmd} {mac}"]
                if dry_run:
                    return ActionResult(ok=True, dry_run=True, planned=planned,
                                        detail=f"dry run: would {cmd} {mac}"
                                               + ("" if client else " (client not yet seen)"))
                await self._call("POST", f"{api}/cmd/stamgr", hdr, f"UniFi {cmd}",
                                 json={"cmd": cmd, "mac": mac})
                return ActionResult(ok=True, planned=planned, detail=f"{cmd} {mac} done",
                                    external_id=mac, revert={"mode": "block", "mac": mac})
            if mode != "network":
                raise SourceError(f"unknown quarantine_mode {mode!r}", retryable=False)
            return await self._network_mode(typ, mac, dry_run, api, hdr, client, revert_plan)
        finally:
            await self._logout(hdr)

    async def _network_mode(self, typ: str, mac: str, dry_run: bool, api: str,
                            hdr: dict[str, str], client: dict[str, Any] | None,
                            revert_plan: dict[str, Any]) -> ActionResult:
        if client is None or not client.get("_id"):
            raise SourceError(f"client {mac} is not known to the controller", retryable=False)
        uid = str(client["_id"])
        site = self._site()
        if typ == "quarantine_device":
            qnet = str(self.config.get("quarantine_network_id") or "")
            if not qnet:
                raise SourceError("quarantine_network_id is required for mode=network",
                                  retryable=False)
            body = {"virtual_network_override_enabled": True, "virtual_network_override_id": qnet}
            prior = {"virtual_network_override_enabled":
                     bool(client.get("virtual_network_override_enabled", False)),
                     "virtual_network_override_id": client.get("virtual_network_override_id") or ""}
        else:
            prior = {}
            body = dict(revert_plan.get("prior") or {"virtual_network_override_enabled": False})
        planned = [f"PUT /api/s/{site}/rest/user/{uid} {sorted(body)}"]
        kick = bool(self.config.get("kick_after_move", True))
        if kick:
            planned.append(f"POST /api/s/{site}/cmd/stamgr kick-sta {mac}")
        if dry_run:
            return ActionResult(ok=True, dry_run=True, planned=planned,
                                detail=f"dry run: would set network override on {mac}")
        await self._call("PUT", f"{api}/rest/user/{uid}", hdr, "UniFi client override", json=body)
        if kick:
            try:
                await self._call("POST", f"{api}/cmd/stamgr", hdr, "UniFi kick-sta",
                                 json={"cmd": "kick-sta", "mac": mac})
            except SourceError:
                pass   # wired / offline clients cannot be kicked; the override still applies
        revert = {"mode": "network", "user_id": uid, "prior": prior} if typ == "quarantine_device" else {}
        return ActionResult(ok=True, planned=planned, external_id=uid, revert=revert,
                            detail=("moved" if typ == "quarantine_device" else "restored")
                            + f" {mac} network override")
