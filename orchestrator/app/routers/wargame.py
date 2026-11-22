"""Wargame assessment read API + recompute trigger.

A wargame assessment is one backward-search-from-crown-jewels run over the
modelled environment. Assessments are *computed* by the correlation service
(which writes the `wargame_*` tables directly, schema 041); this router only
reads the persisted artifacts and exposes a recompute trigger.

- `GET  /v1/wargame/assessments` -- paged `{items,total,limit,offset}` of
  scorecard summaries, newest first.
- `GET  /v1/wargame/assessments/{id}` -- one summary (404 if absent).
- `GET  /v1/wargame/assessments/{id}/routes` -- paged open routes to a jewel.
- `GET  /v1/wargame/assessments/{id}/boundaries` -- per-boundary verdicts.
- `GET  /v1/wargame/assessments/{id}/certificates` -- closed-boundary certs.
- `GET  /v1/wargame/assessments/{id}/fix-set` -- the minimum-cost fix set.
- `GET  /v1/wargame/assessments/{id}/evidence` -- hash-chained evidence items.
- `GET  /v1/wargame/twin` -- row counts of the persisted twin (read-only).
- `POST /v1/wargame/twin/config` -- forward one read-only vendor config to the
  correlation service for ingest into the twin (nothing is applied anywhere).
- `POST /v1/wargame/twin/topology` -- forward segments/edges to correlation.
- `POST /v1/wargame/twin/flows` -- forward observed flow logs (the customer's
  own firewall / Zeek / generic logs) to correlation for the twin's evidence.
- `POST /v1/wargame/twin/probes` -- forward RECORDED probe results (from the
  customer's own probe / scanner) to correlation. Nothing is sent to any host.
- `POST /v1/wargame/change-impact` -- evaluate a Terraform plan against the
  tenant's twin (synchronous proxy to correlation; read-only, nothing applied).
- `POST /v1/wargame/recompute` -- prefer a synchronous call to the correlation
  service; fall back to a Redis job. Never fails hard when correlation is down.

No endpoint here aids exploitation: routes, boundary notes and narratives are
impact-only and are returned exactly as the compute service wrote them; nothing
is probed, launched, or turned into an exploitation recipe.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.routing import APIRoute

from ..config import settings
from ..db import get_pool
from ..models import (
    WargameAssessmentOut,
    WargameAssessmentPage,
    WargameBoundaryOut,
    WargameCertificateOut,
    WargameChangeImpact,
    WargameChangeImpactRequest,
    WargameEvidenceOut,
    WargameFixSetOut,
    WargameRecomputeOut,
    WargameRouteOut,
    WargameRoutePage,
    WargameTwinConfigRequest,
    WargameTwinFlowsOut,
    WargameTwinFlowsRequest,
    WargameTwinIngestOut,
    WargameTwinProbesOut,
    WargameTwinProbesRequest,
    WargameTwinSummaryOut,
    WargameTwinTopologyOut,
    WargameTwinTopologyRequest,
)
from ..queue import get_redis
from .. import tenancy
from ..service_client import service_headers

logger = logging.getLogger(__name__)

# Raw request-body caps in bytes, enforced BEFORE the body is parsed: a huge
# config / plan is a 413, never an OOM. Keyed by full path.
_BODY_CAPS = {
    "/v1/wargame/twin/config": 16 * 1024 * 1024,
    "/v1/wargame/twin/topology": 8 * 1024 * 1024,
    "/v1/wargame/twin/flows": 16 * 1024 * 1024,
    "/v1/wargame/twin/probes": 4 * 1024 * 1024,
    "/v1/wargame/change-impact": 32 * 1024 * 1024,
}


class _CappedBodyRoute(APIRoute):
    """Rejects an oversize request body (by Content-Length, and by counting
    streamed bytes when there is none) before FastAPI buffers and parses it."""

    def get_route_handler(self):
        inner = super().get_route_handler()

        async def handler(request: Request):
            cap = _BODY_CAPS.get(request.url.path)
            if cap is not None and request.method == "POST":
                cl = request.headers.get("content-length")
                if cl is not None:
                    try:
                        declared = int(cl)
                    except ValueError:
                        raise HTTPException(status_code=400, detail="bad Content-Length") from None
                    if declared > cap:
                        raise HTTPException(
                            status_code=413, detail=f"request body exceeds {cap} bytes"
                        )
                buf = bytearray()
                async for chunk in request.stream():
                    buf.extend(chunk)
                    if len(buf) > cap:
                        raise HTTPException(
                            status_code=413, detail=f"request body exceeds {cap} bytes"
                        )
                body = bytes(buf)
                sent = False

                async def receive():
                    nonlocal sent
                    if sent:
                        return {"type": "http.disconnect"}
                    sent = True
                    return {"type": "http.request", "body": body, "more_body": False}

                request = Request(request.scope, receive)
            return await inner(request)

        return handler


router = APIRouter(prefix="/v1/wargame", tags=["wargame"], route_class=_CappedBodyRoute)


_ASSESS_COLS = (
    "id, label, crownjewel_total, crownjewel_open, crownjewel_closed, "
    "crownjewel_conditional, closure_pct, coverage_pct, false_closed_rate, "
    "board_line, blind_spots, computed_at, metadata"
)
_ROUTE_COLS = (
    "id, entry, jewel, length, weakest_label, hops, fingerprint"
)
_BOUNDARY_COLS = (
    "id, boundary_src, boundary_dst, port, verdict, disagreements, note"
)
_CERT_COLS = (
    "id, boundary_src, boundary_dst, port, claim, assumptions, config_hashes, "
    "status, issued_at, expires_at, fingerprint, key_id, corroboration"
)
#: A probe result older than this does not count toward a verdict (= the
#: certificate TTL; correlation app/engine/wargame/evidence.py).
_PROBE_MAX_AGE_HOURS = 24
#: Key ids whose fingerprint is not a real signature (schema 043).
_UNSIGNED_KEY_IDS = ("", "unsigned-dev")
_FIX_COLS = "id, total_cost, optimality, cuts_all, selected, metadata"
_EVID_COLS = (
    "id, framework, control_id, status, statement, evidence, item_hash, ordinal"
)


# --------------------------------------------------------------------------- #
# Row helpers
# --------------------------------------------------------------------------- #

def _jsonb(v: Any) -> Any:
    """JSONB columns come back as Python objects, or JSON strings via some
    drivers -- normalize exactly as attackpaths handles its `hops`."""
    if isinstance(v, str):
        try:
            return json.loads(v)
        except (ValueError, TypeError):
            return v
    return v


def _jsonb_list(v: Any) -> list[Any]:
    v = _jsonb(v)
    return v if isinstance(v, list) else []


def _jsonb_obj(v: Any) -> dict[str, Any]:
    v = _jsonb(v)
    return v if isinstance(v, dict) else {}


def _float(v: Any) -> float | None:
    return float(v) if v is not None else None


def _assessment(row) -> WargameAssessmentOut:
    d = dict(row)
    return WargameAssessmentOut(
        id=d["id"],
        label=d["label"],
        crownjewel_total=int(d["crownjewel_total"]),
        crownjewel_open=int(d["crownjewel_open"]),
        crownjewel_closed=int(d["crownjewel_closed"]),
        crownjewel_conditional=int(d["crownjewel_conditional"]),
        closure_pct=float(d["closure_pct"]),
        coverage_pct=_float(d["coverage_pct"]),
        false_closed_rate=_float(d["false_closed_rate"]),
        board_line=d["board_line"],
        blind_spots=_jsonb_list(d["blind_spots"]),
        computed_at=d["computed_at"],
        metadata=_jsonb_obj(d["metadata"]),
    )


def _route(row) -> WargameRouteOut:
    d = dict(row)
    return WargameRouteOut(
        id=d["id"],
        entry=d["entry"],
        jewel=d["jewel"],
        length=int(d["length"]),
        weakest_label=d["weakest_label"],
        hops=_jsonb_list(d["hops"]),
        fingerprint=d["fingerprint"],
    )


def _boundary(row) -> WargameBoundaryOut:
    d = dict(row)
    return WargameBoundaryOut(
        id=d["id"],
        boundary_src=d["boundary_src"],
        boundary_dst=d["boundary_dst"],
        port=d["port"],
        verdict=d["verdict"],
        disagreements=_jsonb_list(d["disagreements"]),
        note=d["note"],
    )


def _certificate(row) -> WargameCertificateOut:
    d = dict(row)
    return WargameCertificateOut(
        id=d["id"],
        boundary_src=d["boundary_src"],
        boundary_dst=d["boundary_dst"],
        port=d["port"],
        claim=d["claim"],
        assumptions=_jsonb_list(d["assumptions"]),
        config_hashes=_jsonb_list(d["config_hashes"]),
        status=d["status"],
        issued_at=d["issued_at"],
        expires_at=d["expires_at"],
        fingerprint=d["fingerprint"],
        key_id=d.get("key_id") or "",
        signed=(d.get("key_id") or "") not in _UNSIGNED_KEY_IDS,
        corroboration=_jsonb_obj(d.get("corroboration")),
    )


def _fix_set(row) -> WargameFixSetOut:
    d = dict(row)
    return WargameFixSetOut(
        id=d["id"],
        total_cost=float(d["total_cost"]),
        optimality=d["optimality"],
        cuts_all=bool(d["cuts_all"]),
        selected=_jsonb_list(d["selected"]),
        metadata=_jsonb_obj(d["metadata"]),
    )


def _evidence(row) -> WargameEvidenceOut:
    d = dict(row)
    return WargameEvidenceOut(
        id=d["id"],
        framework=d["framework"],
        control_id=d["control_id"],
        status=d["status"],
        statement=d["statement"],
        evidence=_jsonb_obj(d["evidence"]),
        item_hash=d["item_hash"],
        ordinal=int(d["ordinal"]),
    )


async def _assessment_exists(con, assessment_id: UUID) -> bool:
    return bool(
        await con.fetchval(
            "SELECT 1 FROM wargame_assessments WHERE id = $1", assessment_id
        )
    )


# --------------------------------------------------------------------------- #
# Assessments: list + detail
# --------------------------------------------------------------------------- #

@router.get("/assessments", response_model=WargameAssessmentPage)
async def list_assessments(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    async with pool.acquire() as con:
        total = await con.fetchval("SELECT COUNT(*) FROM wargame_assessments")
        rows = await con.fetch(
            f"""
            SELECT {_ASSESS_COLS}
              FROM wargame_assessments
             ORDER BY computed_at DESC, id DESC
             LIMIT $1 OFFSET $2
            """,
            limit,
            offset,
        )
    items = [_assessment(r) for r in rows]
    return WargameAssessmentPage(
        items=items, total=int(total or 0), limit=limit, offset=offset
    )


@router.get("/assessments/{assessment_id}", response_model=WargameAssessmentOut)
async def get_assessment(assessment_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            f"SELECT {_ASSESS_COLS} FROM wargame_assessments WHERE id = $1",
            assessment_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="wargame assessment not found")
    return _assessment(row)


# --------------------------------------------------------------------------- #
# Child artifacts
# --------------------------------------------------------------------------- #

@router.get("/assessments/{assessment_id}/routes", response_model=WargameRoutePage)
async def list_routes(
    assessment_id: UUID,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    async with pool.acquire() as con:
        if not await _assessment_exists(con, assessment_id):
            raise HTTPException(
                status_code=404, detail="wargame assessment not found"
            )
        total = await con.fetchval(
            "SELECT COUNT(*) FROM wargame_routes WHERE assessment_id = $1",
            assessment_id,
        )
        rows = await con.fetch(
            f"""
            SELECT {_ROUTE_COLS}
              FROM wargame_routes
             WHERE assessment_id = $1
             ORDER BY length ASC, jewel ASC, id ASC
             LIMIT $2 OFFSET $3
            """,
            assessment_id,
            limit,
            offset,
        )
    items = [_route(r) for r in rows]
    return WargameRoutePage(
        items=items, total=int(total or 0), limit=limit, offset=offset
    )


@router.get(
    "/assessments/{assessment_id}/boundaries",
    response_model=list[WargameBoundaryOut],
)
async def list_boundaries(
    assessment_id: UUID,
    limit: int = Query(1000, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    async with pool.acquire() as con:
        if not await _assessment_exists(con, assessment_id):
            raise HTTPException(
                status_code=404, detail="wargame assessment not found"
            )
        rows = await con.fetch(
            f"""
            SELECT {_BOUNDARY_COLS}
              FROM wargame_boundaries
             WHERE assessment_id = $1
             ORDER BY boundary_src ASC, boundary_dst ASC, port ASC, id ASC
             LIMIT $2 OFFSET $3
            """,
            assessment_id,
            limit,
            offset,
        )
    return [_boundary(r) for r in rows]


@router.get(
    "/assessments/{assessment_id}/certificates",
    response_model=list[WargameCertificateOut],
)
async def list_certificates(
    assessment_id: UUID,
    limit: int = Query(1000, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    async with pool.acquire() as con:
        if not await _assessment_exists(con, assessment_id):
            raise HTTPException(
                status_code=404, detail="wargame assessment not found"
            )
        rows = await con.fetch(
            f"""
            SELECT {_CERT_COLS}
              FROM wargame_certificates
             WHERE assessment_id = $1
             ORDER BY boundary_src ASC, boundary_dst ASC, port ASC, id ASC
             LIMIT $2 OFFSET $3
            """,
            assessment_id,
            limit,
            offset,
        )
    return [_certificate(r) for r in rows]


@router.get(
    "/assessments/{assessment_id}/fix-set", response_model=WargameFixSetOut
)
async def get_fix_set(assessment_id: UUID, pool=Depends(get_pool)):
    async with pool.acquire() as con:
        if not await _assessment_exists(con, assessment_id):
            raise HTTPException(
                status_code=404, detail="wargame assessment not found"
            )
        row = await con.fetchrow(
            f"""
            SELECT {_FIX_COLS}
              FROM wargame_fix_sets
             WHERE assessment_id = $1
             ORDER BY id ASC
             LIMIT 1
            """,
            assessment_id,
        )
    if row is None:
        raise HTTPException(status_code=404, detail="no fix set for assessment")
    return _fix_set(row)


@router.get(
    "/assessments/{assessment_id}/evidence",
    response_model=list[WargameEvidenceOut],
)
async def list_evidence(
    assessment_id: UUID,
    framework: str | None = Query(None, max_length=64),
    limit: int = Query(1000, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    pool=Depends(get_pool),
):
    clauses = ["assessment_id = $1"]
    args: list[Any] = [assessment_id]
    if framework is not None:
        args.append(framework)
        clauses.append(f"framework = ${len(args)}")
    where = " AND ".join(clauses)
    args.extend([limit, offset])
    lim_ph, off_ph = f"${len(args) - 1}", f"${len(args)}"
    async with pool.acquire() as con:
        if not await _assessment_exists(con, assessment_id):
            raise HTTPException(
                status_code=404, detail="wargame assessment not found"
            )
        rows = await con.fetch(
            f"""
            SELECT {_EVID_COLS}
              FROM wargame_evidence
             WHERE {where}
             ORDER BY framework ASC, ordinal ASC, id ASC
             LIMIT {lim_ph} OFFSET {off_ph}
            """,
            *args,
        )
    return [_evidence(r) for r in rows]


# --------------------------------------------------------------------------- #
# Calling correlation
# --------------------------------------------------------------------------- #

def _corr_url(path: str) -> str:
    return settings.correlation_url.rstrip("/") + path


def _client_error(status_code: int, resp) -> HTTPException:
    """Surface a correlation 4xx (the caller's input was refused) as the same
    4xx. Only the short `detail` string correlation wrote for the caller is
    passed on; anything else is dropped so nothing internal leaks."""
    detail = "request rejected by the wargame service"
    try:
        body = resp.json()
        d = body.get("detail") if isinstance(body, dict) else None
        if isinstance(d, str) and d:
            detail = d[:500]
    except Exception:  # noqa: BLE001
        pass
    return HTTPException(status_code=status_code, detail=detail)


# --------------------------------------------------------------------------- #
# Recompute trigger
# --------------------------------------------------------------------------- #

@router.post("/recompute", response_model=WargameRecomputeOut)
async def recompute_wargame(r=Depends(get_redis)):
    """Trigger a recompute of wargame assessments.

    Preferred path: a synchronous POST to the correlation service's
    `/compute-wargame` (connect fails fast, the read allows a real compute).
    If that is unreachable or errors, fall back to publishing a
    `correlate:recompute_wargame` job on Redis. The request never fails hard
    when correlation is down -- the worst case is `status=unavailable`
    (correlation unreachable *and* the enqueue failed). Failures are logged;
    the response carries a generic note, never the exception text.
    """
    url = _corr_url("/compute-wargame")

    # 1) Try the synchronous correlation call.
    try:
        import httpx

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30.0, connect=3.0)
        ) as http:
            resp = await http.post(url, json={}, headers=service_headers())
        if resp.status_code < 400:
            computed = None
            try:
                body = resp.json()
                if isinstance(body, dict):
                    val = body.get("assessments", body.get("computed", body.get("count")))
                    if val is not None:
                        computed = int(val)
            except Exception:  # noqa: BLE001
                computed = None
            detail = (
                f"correlation computed {computed} assessment(s)"
                if computed is not None
                else "correlation ran the assessment"
            )
            return WargameRecomputeOut(status="computed", detail=detail)
        logger.warning(
            "correlation_compute_wargame_http_error",
            extra={"status": resp.status_code},
        )
    except Exception as exc:  # noqa: BLE001
        # Connection refused / DNS / timeout / httpx missing -> fall back.
        logger.info(
            "correlation_unreachable_falling_back", extra={"error": str(exc)}
        )

    # 2) Fall back to a Redis job on the correlate queue.
    try:
        await r.xadd(
            settings.queue_correlate,
            {
                "job": json.dumps(
                    {
                        "kind": "correlate_recompute_wargame",
                        "op": "recompute_wargame",
                        # every queued unit of work names its tenant
                        "tenant_id": tenancy.current_tenant_id(),
                    }
                )
            },
        )
        return WargameRecomputeOut(
            status="queued", detail="recompute job enqueued on correlate queue"
        )
    except Exception:  # noqa: BLE001
        logger.exception("wargame_recompute_enqueue_failed")
        return WargameRecomputeOut(
            status="unavailable", detail="correlation is unreachable; try again shortly"
        )


# --------------------------------------------------------------------------- #
# Twin management: read-only summary + ingest triggers
# --------------------------------------------------------------------------- #

@router.get("/twin", response_model=WargameTwinSummaryOut)
async def get_twin_summary(pool=Depends(get_pool)):
    """Row counts of the persisted twin. Read-only; tenant scoping is applied
    by the pool's RLS session, exactly like the other reads here."""
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            SELECT (SELECT COUNT(*) FROM wargame_rulesets)         AS rulesets,
                   (SELECT COUNT(*) FROM wargame_rules)            AS rules,
                   (SELECT COUNT(*) FROM wargame_segments)         AS segments,
                   (SELECT COUNT(*) FROM wargame_edges)            AS edges,
                   (SELECT COUNT(*) FROM wargame_config_snapshots) AS snapshots,
                   (SELECT COUNT(*) FROM wargame_observed_flows)   AS flows,
                   (SELECT COUNT(*) FROM wargame_probe_results)    AS probes,
                   (SELECT COUNT(*) FROM wargame_probe_results
                     WHERE result <> 'error'
                       AND observed_at >= NOW() - make_interval(hours => $1)
                       AND observed_at <= NOW() + INTERVAL '5 minutes') AS probes_fresh
            """,
            _PROBE_MAX_AGE_HOURS,
        )
    d = dict(row) if row is not None else {}
    rulesets = int(d.get("rulesets") or 0)
    rules = int(d.get("rules") or 0)
    segments = int(d.get("segments") or 0)
    edges = int(d.get("edges") or 0)
    snapshots = int(d.get("snapshots") or 0)
    return WargameTwinSummaryOut(
        ruleset_count=rulesets,
        rule_count=rules,
        segment_count=segments,
        edge_count=edges,
        snapshot_count=snapshots,
        has_twin=bool(rulesets or segments or edges),
        flow_count=int(d.get("flows") or 0),
        probe_count=int(d.get("probes") or 0),
        probe_fresh_count=int(d.get("probes_fresh") or 0),
    )


async def _trigger_twin(
    r, path: str, op: str, payload: dict[str, Any]
) -> tuple[str, str | None, dict[str, Any]]:
    """Mirror of the recompute trigger for twin ingest.

    Returns `(status, detail, sync_body)`. Tries a short synchronous POST to
    the correlation service; on connection failure / 5xx falls back to a Redis
    job on the correlate queue. A correlation **4xx** (the config was refused:
    bad vendor payload, too large) is the caller's error, not an outage: it is
    raised as that 4xx and never queued (a queued bad payload could only
    poison the queue).
    """
    url = _corr_url(path)

    # 1) Synchronous correlation call.
    try:
        import httpx

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(20.0, connect=3.0)
        ) as http:
            resp = await http.post(url, json=payload, headers=service_headers())
        if resp.status_code < 400:
            body: dict[str, Any] = {}
            try:
                parsed = resp.json()
                if isinstance(parsed, dict):
                    body = parsed
            except Exception:  # noqa: BLE001
                body = {}
            return "ingested", None, body
        if 400 <= resp.status_code < 500 and resp.status_code not in (408, 429):
            raise _client_error(resp.status_code, resp)
        logger.warning(
            "correlation_twin_http_error",
            extra={"path": path, "status": resp.status_code},
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.info(
            "correlation_unreachable_falling_back", extra={"error": str(exc)}
        )

    # 2) Fall back to a Redis job on the correlate queue.
    try:
        await r.xadd(
            settings.queue_correlate,
            {
                "job": json.dumps(
                    {
                        "kind": f"correlate_{op}",
                        "op": op,
                        "payload": payload,
                        "tenant_id": tenancy.current_tenant_id(),
                    }
                )
            },
        )
        return "queued", f"{op} job enqueued on correlate queue", {}
    except Exception:  # noqa: BLE001
        logger.exception("wargame_twin_enqueue_failed")
        return "unavailable", "correlation is unreachable; try again shortly", {}


def _opt_int(body: dict[str, Any], *keys: str) -> int | None:
    for k in keys:
        v = body.get(k)
        if v is not None:
            try:
                return int(v)
            except (TypeError, ValueError):
                return None
    return None


@router.post("/twin/config", response_model=WargameTwinIngestOut)
async def ingest_twin_config(
    req: WargameTwinConfigRequest, r=Depends(get_redis)
):
    """Ingest one read-only vendor config into the twin (compute-side).

    Forwards to correlation `POST /ingest-config`; falls back to a
    `correlate:twin_ingest_config` Redis job when correlation is down. The
    config is parsed, never applied to any device. Vendor is an allowlist,
    size is capped (413 / 422), and a config correlation cannot parse is a
    422, not a queued job.
    """
    status, detail, body = await _trigger_twin(
        r, "/ingest-config", "twin_ingest_config", req.model_dump()
    )
    rulesets = _opt_int(body, "rulesets", "count")
    if status == "ingested":
        detail = (
            f"correlation ingested {rulesets} ruleset(s)"
            if rulesets is not None
            else "correlation ingested the config"
        )
    return WargameTwinIngestOut(status=status, detail=detail, rulesets=rulesets)


@router.post("/twin/topology", response_model=WargameTwinTopologyOut)
async def set_twin_topology(
    req: WargameTwinTopologyRequest, r=Depends(get_redis)
):
    """Set the twin's segments/edges (compute-side).

    Forwards to correlation `POST /set-topology`; falls back to a
    `correlate:twin_set_topology` Redis job. Malformed segments/edges are a
    422 from correlation, passed through.
    """
    status, detail, body = await _trigger_twin(
        r, "/set-topology", "twin_set_topology", req.model_dump()
    )
    segments = _opt_int(body, "segments")
    edges = _opt_int(body, "edges")
    if status == "ingested":
        detail = "correlation set the topology"
    return WargameTwinTopologyOut(
        status=status, detail=detail, segments=segments, edges=edges
    )


@router.post("/twin/flows", response_model=WargameTwinFlowsOut)
async def ingest_twin_flows(req: WargameTwinFlowsRequest, r=Depends(get_redis)):
    """Store observed flows (the customer's own firewall / Zeek / generic
    logs) as twin evidence.

    Forwards to correlation `POST /ingest-flows`; falls back to a
    `correlate:twin_ingest_flows` Redis job when correlation is down. Only rows
    that parse are stored (rolling 30-day window, capped per tenant). On the
    next recompute a real flow from an entry to a crown jewel the config proves
    closed makes that pair `fail_open`, and one across a still-valid
    certificate raises an impossible-traffic alert. Nothing is probed.
    """
    status, detail, body = await _trigger_twin(
        r, "/ingest-flows", "twin_ingest_flows", req.model_dump()
    )
    out = WargameTwinFlowsOut(status=status, detail=detail)
    if status == "ingested":
        out.flows_parsed = _opt_int(body, "flows_parsed")
        out.flows_skipped = _opt_int(body, "flows_skipped")
        out.flows_stored = _opt_int(body, "flows_stored")
        out.warnings = _str_list(body.get("warnings"))
        out.detail = (
            f"correlation stored {out.flows_stored} flow(s)"
            if out.flows_stored is not None
            else "correlation ingested the flows"
        )
    return out


@router.post("/twin/probes", response_model=WargameTwinProbesOut)
async def ingest_twin_probes(req: WargameTwinProbesRequest, r=Depends(get_redis)):
    """Record probe results produced by the customer's own probe or scanner.

    Paddock sends NO packets here: each result is a recorded fact (a connect
    from segment `src` to segment `dst` on `proto`/`port` `crossed`, was
    `blocked`, or hit an `error`). Forwards to correlation `POST /ingest-probes`;
    falls back to a `correlate:twin_ingest_probes` Redis job. A result naming a
    segment the twin does not hold is rejected (counted); no topology is a 409.
    A probe counts for an (entry, crown jewel) pair only if it ran from that
    entry segment to that jewel segment, within the certificate TTL (24 h);
    `error` never counts. A blocked one turns a config-proved pair into `pass`.
    """
    status, detail, body = await _trigger_twin(
        r, "/ingest-probes", "twin_ingest_probes", req.model_dump(mode="json")
    )
    out = WargameTwinProbesOut(status=status, detail=detail)
    if status == "ingested":
        out.stored = _opt_int(body, "stored")
        out.rejected = _opt_int(body, "rejected")
        out.warnings = _str_list(body.get("warnings"))
        out.detail = (
            f"correlation stored {out.stored} probe result(s)"
            if out.stored is not None
            else "correlation recorded the probe results"
        )
    return out


def _str_list(v: Any, limit: int = 50) -> list[str]:
    if not isinstance(v, list):
        return []
    return [str(x)[:300] for x in v[:limit] if isinstance(x, (str, int, float))]


# --------------------------------------------------------------------------- #
# Change gate
# --------------------------------------------------------------------------- #

@router.post("/change-impact", response_model=WargameChangeImpact)
async def change_impact(req: WargameChangeImpactRequest):
    """Say what a proposed Terraform plan would do, BEFORE it is applied.

    Proxies synchronously to correlation `POST /change-impact`, which loads
    this tenant's twin, evaluates the plan before/after against it, and
    returns routes opened/closed to crown jewels and live flows broken. Strictly
    read-only: nothing is persisted, applied, or sent anywhere. There is no
    queue fallback (the caller needs the answer): correlation down is a 503,
    no twin is a 409, a bad plan is a 422, an oversize body a 413.
    """
    try:
        import httpx

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=3.0)
        ) as http:
            resp = await http.post(
                _corr_url("/change-impact"),
                json=req.model_dump(exclude_none=True),
                headers=service_headers(),
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("correlation_change_impact_unreachable", extra={"error": str(exc)})
        raise HTTPException(
            status_code=503, detail="wargame service is unreachable; try again shortly"
        ) from None
    if resp.status_code >= 500 or resp.status_code in (408, 429):
        logger.warning(
            "correlation_change_impact_http_error", extra={"status": resp.status_code}
        )
        raise HTTPException(
            status_code=503, detail="wargame service could not evaluate the change"
        )
    if resp.status_code >= 400:
        raise _client_error(resp.status_code, resp)
    try:
        return WargameChangeImpact.model_validate(resp.json())
    except Exception:  # noqa: BLE001
        logger.warning("correlation_change_impact_bad_body")
        raise HTTPException(
            status_code=502, detail="wargame service returned an unreadable result"
        ) from None
