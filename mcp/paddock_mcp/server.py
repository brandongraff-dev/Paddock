"""The MCP server: stdio and streamable HTTP.

Config (env, or flags):

* ``PADDOCK_URL``       base URL of the Paddock API (required)
* ``PADDOCK_API_KEY``   API key (``pak_...``); its capabilities bound what the model can do
* ``PADDOCK_MCP_ALLOW_WRITE=1`` / ``--allow-write``  expose the write tools (``trigger_scan``,
  ``propose_remediation``). Even then a tool is only registered when the key itself holds the
  capability it needs (``scan`` / ``admin``), so a read-only key can never act.
* ``PADDOCK_MCP_HTTP_TOKEN``  bearer token required on the HTTP transport (mandatory off loopback)
"""
from __future__ import annotations

import argparse
import asyncio
import inspect
import ipaddress
import os
import sys
import typing
from typing import Any, Optional

from . import __version__
from .client import PaddockClient, PaddockError
from .tools import INSTRUCTIONS, TOOLS, ToolDef

try:                                                    # mcp >= 2
    from mcp.server.mcpserver import MCPServer as _Server
    from mcp.server.mcpserver.exceptions import ToolError
except ImportError:                                     # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server   # type: ignore[assignment]
    from mcp.server.fastmcp.exceptions import ToolError  # type: ignore[assignment]


def _annotations(read_only: bool) -> Any:
    try:
        from mcp.types import ToolAnnotations
        return ToolAnnotations(readOnlyHint=read_only, destructiveHint=False, openWorldHint=False)
    except Exception:  # noqa: BLE001
        return None


def _bind(client: PaddockClient, t: ToolDef):
    """Wrap ``t.fn(client, **args)`` as ``fn(**args)`` keeping a real typed signature
    (the SDK derives the tool's JSON schema from it)."""
    sig = inspect.signature(t.fn)
    hints = typing.get_type_hints(t.fn)
    params = [p.replace(annotation=hints.get(p.name, p.annotation)) for p in list(sig.parameters.values())[1:]]

    async def run(**kwargs: Any) -> Any:
        try:
            return await t.fn(client, **kwargs)
        except PaddockError as exc:
            raise ToolError(f"Paddock refused or failed the request ({exc.status}): {exc.detail}") from None
        except ValueError as exc:
            raise ToolError(f"invalid argument: {exc}") from None

    run.__name__, run.__doc__ = t.name, t.description
    run.__signature__ = sig.replace(parameters=params)           # type: ignore[attr-defined]
    run.__annotations__ = {p.name: p.annotation for p in params}
    return run


def enabled_tools(caps: frozenset[str], allow_write: bool) -> list[ToolDef]:
    out = []
    for t in TOOLS:
        if t.capability not in caps:
            continue
        if t.write and not allow_write:
            continue
        out.append(t)
    return out


def build_server(client: PaddockClient, caps: frozenset[str], *, allow_write: bool = False,
                 host: str = "127.0.0.1", port: int = 8765) -> Any:
    kwargs: dict[str, Any] = {"instructions": INSTRUCTIONS}
    try:
        server = _Server("paddock", version=__version__, **kwargs)          # mcp 2
    except TypeError:
        server = _Server("paddock", **kwargs)                               # mcp 1
    for attr, val in (("host", host), ("port", port)):                      # mcp 1.x keeps HTTP bind in settings
        settings = getattr(server, "settings", None)
        if settings is not None and hasattr(settings, attr):
            setattr(settings, attr, val)
    for t in enabled_tools(caps, allow_write):
        ann = _annotations(not t.write)
        kw = {"name": t.name, "description": t.description}
        if ann is not None:
            kw["annotations"] = ann
        server.tool(**kw)(_bind(client, t))
    return server


# --------------------------------------------------------------------------- #
# HTTP transport guard
# --------------------------------------------------------------------------- #

def _is_loopback(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class BearerGuard:
    """ASGI middleware: require ``Authorization: Bearer <token>`` (constant time)."""

    def __init__(self, app: Any, token: str):
        self.app, self.token = app, token.encode()

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            import hmac
            auth = dict(scope["headers"]).get(b"authorization", b"")
            ok = auth[:7].lower() == b"bearer " and hmac.compare_digest(auth[7:].strip(), self.token)
            if not ok:
                body = b'{"error":"unauthorized"}'
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"www-authenticate", b"Bearer"),
                                        (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


def http_app(server: Any, token: Optional[str], host: str) -> Any:
    if not token and not _is_loopback(host):
        raise SystemExit("refusing to serve HTTP on a non-loopback address without PADDOCK_MCP_HTTP_TOKEN")
    app = server.streamable_http_app()
    return BearerGuard(app, token) if token else app


# --------------------------------------------------------------------------- #

def _parse(argv: Optional[list[str]]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="paddock-mcp", description=__doc__.split("\n\n")[0])
    p.add_argument("--transport", choices=("stdio", "http"), default=os.environ.get("PADDOCK_MCP_TRANSPORT", "stdio"))
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--url", default=os.environ.get("PADDOCK_URL", ""), help="Paddock base URL (or PADDOCK_URL)")
    p.add_argument("--allow-write", action="store_true",
                   default=os.environ.get("PADDOCK_MCP_ALLOW_WRITE", "").lower() in ("1", "true", "yes"),
                   help="expose trigger_scan / propose_remediation (only if the API key allows them)")
    p.add_argument("--list-tools", action="store_true", help="print the tools this key would expose and exit")
    p.add_argument("--version", action="version", version=f"paddock-mcp {__version__}")
    return p.parse_args(argv)


async def _discover(url: str, key: str) -> frozenset[str]:
    c = PaddockClient(url, key)
    try:
        return await c.capabilities()
    finally:
        await c.aclose()


def main(argv: Optional[list[str]] = None) -> None:
    a = _parse(argv)
    key = os.environ.get("PADDOCK_API_KEY", "")
    if not a.url or not key:
        sys.exit("paddock-mcp: set PADDOCK_URL and PADDOCK_API_KEY (an API key from Settings > API keys)")
    try:
        caps = asyncio.run(_discover(a.url, key))
    except PaddockError as exc:
        sys.exit(f"paddock-mcp: cannot use this Paddock server/key: {exc}")
    tools = enabled_tools(caps, a.allow_write)
    if a.list_tools:
        for t in tools:
            print(f"{t.name}\t{'write' if t.write else 'read'}")
        return
    print(f"paddock-mcp {__version__}: {a.url} as key with [{', '.join(sorted(caps))}]; "
          f"tools: {', '.join(t.name for t in tools)}", file=sys.stderr)
    server = build_server(PaddockClient(a.url, key), caps, allow_write=a.allow_write, host=a.host, port=a.port)
    if a.transport == "stdio":
        server.run("stdio")
        return
    import uvicorn
    uvicorn.run(http_app(server, os.environ.get("PADDOCK_MCP_HTTP_TOKEN"), a.host), host=a.host, port=a.port,
                log_level="warning")


if __name__ == "__main__":
    main()
