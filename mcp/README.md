# paddock-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server that lets AI
assistants (Claude Desktop, Claude Code, Cursor, ...) work with a Paddock server.
It talks to the normal `/v1` API with **your API key**, so auth, RBAC, ABAC,
scope and audit all apply: the assistant can never do more than the key can.

```bash
pip install paddock-mcp            # from this directory: pip install .
export PADDOCK_URL=https://paddock.example.com
export PADDOCK_API_KEY=pak_xxxxxxxx_...
paddock-mcp                        # stdio (what desktop clients launch)
paddock-mcp --transport http --port 8765   # streamable HTTP at /mcp
```

## Tools

| tool | needs | what it does |
|---|---|---|
| `list_findings`, `search_findings`, `get_finding` | `read` | browse, search, full evidence |
| `explain_priority` | `read` | why a finding scores what it does (KEV, EPSS, exposure, SLA) |
| `list_assets` | `read` | discovered assets |
| `check_scope` | `read` | is a host in the authorised scope (sends nothing to it) |
| `get_posture_summary` | `read` | executive summary + open counts by severity |
| `suggest_remediation` | `read` | recorded fix guidance |
| `trigger_scan` | `scan` **and** `--allow-write` | queue a scan of an in-scope target |
| `propose_remediation` | `admin` **and** `--allow-write` | ask the remediation service to draft a fix |

**Read-only by default.** Write tools appear only when the operator passes
`--allow-write` (or `PADDOCK_MCP_ALLOW_WRITE=1`) *and* the key holds the
capability. Out-of-scope scans are refused by Paddock and by the tool before
anything is queued.

## HTTP transport

Binds to loopback by default. Binding anywhere else requires
`PADDOCK_MCP_HTTP_TOKEN`; clients must send `Authorization: Bearer <token>`.

## Prompt-injection note

Finding text comes from scanned systems and third-party tools. The server
instructions tell the model to treat it as data, titles/evidence are
length-capped, and no tool can change scope, delete data or merge code.

## Tests

```bash
pip install -e '.[test]' && python -m pytest -q
```

Works with the `mcp` SDK 1.x (`FastMCP`) and 2.x (`MCPServer`).
