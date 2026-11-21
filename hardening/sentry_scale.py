#!/usr/bin/env python3
"""Sentry scale test: 100 simulated sensors through the REAL ingest path.

    sensor (HTTP, gzip, Idempotency-Key)
      -> otdiscovery  /enroll /heartbeat /ingest        (separate process)
      -> orchestrator /v1/sensors/* + /v1/assets|edges|findings/bulk   (uvicorn, in this process)
      -> Postgres 16  (a fresh scratch database that this script creates and drops)

Default load = 1,000,000 flows/day equivalent (11.6 flows/s sustained) from 100
sensors, one batch per 30 s window each, with a 50x burst for a minute in the
middle (580 flows/s), then a recovery phase. A fraction of batches is re-sent
with the same batch id (a retry after a lost reply) to prove idempotency under
load. It reports, per phase and overall: accepted flows/s, batches/s, p50/p95/
p99/max request latency, errors, otdiscovery CPU, and database growth (total and
per table, plus a projection per day). It ends by reconciling what the server
counted against what was sent.

    pip install -e "orchestrator[dev]"
    python -m venv /tmp/otd && /tmp/otd/bin/pip install ./otdiscovery
    python hardening/sentry_scale.py \\
        --admin-dsn postgresql://postgres@127.0.0.1:5432/postgres \\
        --otd-python /tmp/otd/bin/python

Quick local run:  --window-s 10 --steady-s 30 --burst-s 20 --recover-s 20
Never point --admin-dsn at a production server (it creates and drops a database).
"""
from __future__ import annotations

import argparse
import asyncio
import gzip
import json
import os
import random
import socket
import statistics
import subprocess
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "orchestrator"))
SERVICE_KEY = "sentry-scale-service-key"
os.environ.setdefault("AUTH_MODE", "dev")
os.environ["SERVICE_API_KEY"] = SERVICE_KEY
os.environ.setdefault("MIGRATE_ON_STARTUP", "false")
os.environ.setdefault("SCHEDULER_ENABLED", "false")
# 100 sensors enroll from one address: lift the per-address limits for the run
os.environ["SENSOR_ENROLL_PER_MIN"] = "100000"
os.environ["SENSOR_HEARTBEAT_PER_MIN"] = "100000"

import asyncpg  # noqa: E402
import httpx  # noqa: E402


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def cpu_seconds(pid: int) -> float:
    try:
        parts = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return (int(parts[11]) + int(parts[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError, ValueError):
        return float("nan")


# --------------------------------------------------------------------------- #
# synthetic site traffic
# --------------------------------------------------------------------------- #

VENDOR_CLASSES = ["udhcp 1.30.1", "dhcpcd-9.4.1:Linux", "MSFT 5.0", "android-dhcp-13", "Axis"]
HOST_PREFIX = ["HP-Printer", "Axis-cam", "Nest-Thermostat", "Sonos", "Hue-Bridge", "ESP32", "Roku"]
SERVICES = ["_ipp._tcp.local", "_hap._tcp.local", "_googlecast._tcp.local", "_airplay._tcp.local"]
CLOUD = ["52.84.10.11", "34.120.5.9", "151.101.1.69", "17.253.144.10", "104.18.2.35"]


class SimSensor:
    def __init__(self, idx: int, devices: int, rng: random.Random) -> None:
        self.idx = idx
        self.name = f"sim-{idx:03d}"
        self.site = f"site-{idx // 5:02d}"
        self.rng = rng
        self.net = f"10.{1 + idx // 250}.{idx % 250}"
        self.devs = [(f"{self.net}.{10 + d}", f"02:5e:{idx:02x}:00:{d // 256:02x}:{d % 256:02x}") for d in range(devices)]
        self.gw = f"{self.net}.1"
        self.gw_mac = f"02:5e:{idx:02x}:ff:ff:01"
        self.credential = ""
        self.sent_batches = 0
        self.sent_flows = 0
        self.dup_sent = 0

    def announcements(self, full: bool) -> list[dict]:
        out: list[dict] = []
        picks = self.devs if full else self.rng.sample(self.devs, min(4, len(self.devs)))
        for ip, mac in picks:
            n = int(ip.rsplit(".", 1)[1])
            out.append({"kind": "dhcp", "mac": mac, "src_mac": mac, "ip": ip, "src_ip": ip,
                        "vendor_class": VENDOR_CLASSES[n % len(VENDOR_CLASSES)],
                        "hostname": f"{HOST_PREFIX[n % len(HOST_PREFIX)]}-{n}"})
            out.append({"kind": "mdns", "src_ip": ip, "src_mac": mac,
                        "service": SERVICES[n % len(SERVICES)], "name": f"{HOST_PREFIX[n % len(HOST_PREFIX)]}-{n}"})
        return out

    def flows(self, n: int) -> list[dict]:
        now = time.time()
        out = []
        for _ in range(n):
            ip, mac = self.rng.choice(self.devs)
            r = self.rng.random()
            if r < 0.55:
                dst, dmac, port, proto = self.rng.choice(CLOUD), self.gw_mac, 443, "tcp"
            elif r < 0.75:
                dst, dmac, port, proto = self.gw, self.gw_mac, 53, "udp"
            elif r < 0.85:
                dst, dmac, port, proto = "162.159.200.1", self.gw_mac, 123, "udp"
            else:
                pip, pmac = self.rng.choice(self.devs)
                dst, dmac, port, proto = pip, pmac, self.rng.choice([80, 443, 554, 8080]), "tcp"
            out.append({"kind": "flow", "proto": proto, "src_ip": ip, "dst_ip": dst, "src_mac": mac,
                        "dst_mac": dmac, "dst_port": port, "packets": self.rng.randint(2, 400),
                        "bytes": self.rng.randint(200, 90_000), "first_seen": round(now - 20, 3),
                        "last_seen": round(now, 3), "tcp_syn": proto == "tcp"})
        return out


# --------------------------------------------------------------------------- #
# processes
# --------------------------------------------------------------------------- #

async def wait_http(url: str, timeout: float = 40.0) -> None:
    deadline = time.time() + timeout
    async with httpx.AsyncClient() as c:
        while time.time() < deadline:
            try:
                if (await c.get(url, timeout=2)).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.2)
    raise RuntimeError(f"{url} did not come up")


@asynccontextmanager
async def orchestrator(dsn: str, port: int):
    import fakeredis.aioredis
    import uvicorn

    from app import main as main_mod

    @asynccontextmanager
    async def _noop(app):
        yield

    main_mod.lifespan = _noop
    app = main_mod.create_app()
    pool = await asyncpg.create_pool(dsn, min_size=4, max_size=24)
    app.state.pool = pool
    app.state.redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning",
                                           access_log=False, lifespan="off"))
    task = asyncio.create_task(server.serve())
    try:
        await wait_http(f"http://127.0.0.1:{port}/healthz")
        yield pool
    finally:
        server.should_exit = True
        await task
        await pool.close()


@asynccontextmanager
async def otdiscovery(python: str, orch_url: str, port: int):
    env = {**os.environ, "ORCHESTRATOR_URL": orch_url, "OTDISCOVERY_HTTP_PORT": str(port),
           "ENABLE_DB": "false", "SERVICE_API_KEY": SERVICE_KEY, "LOG_LEVEL": "WARNING",
           "REQUIRE_SENTRY_TOKEN": "true", "PYTHONPATH": ""}
    proc = subprocess.Popen([python, "-m", "app.main"], cwd=ROOT / "otdiscovery", env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        await wait_http(f"http://127.0.0.1:{port}/healthz")
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


# --------------------------------------------------------------------------- #
# load
# --------------------------------------------------------------------------- #

class Phase:
    def __init__(self, name: str, seconds: float, factor: float) -> None:
        self.name, self.seconds, self.factor = name, seconds, factor
        self.lat: list[float] = []
        self.flows = 0
        self.batches = 0
        self.dups = 0
        self.errors: dict[str, int] = {}
        self.cpu0 = self.cpu1 = 0.0
        self.t0 = self.t1 = 0.0


async def sensor_loop(sim: SimSensor, client: httpx.AsyncClient, otd: str, phases: list[Phase],
                      clock: dict, args: argparse.Namespace) -> None:
    rng = sim.rng
    await asyncio.sleep(rng.uniform(0, args.window_s))  # spread the sensors across the window
    batch_no = 0
    base_rate = args.flows_per_day / 86400.0 / args.sensors     # flows/s per sensor
    last_hb = 0.0
    while not clock["stop"]:
        started = time.monotonic()
        phase: Phase = clock["phase"]
        n_flows = max(0, int(round(rng.gauss(base_rate * args.window_s * phase.factor,
                                             (base_rate * args.window_s * phase.factor) ** 0.5))))
        obs = sim.announcements(full=batch_no == 0) + sim.flows(n_flows)
        batch_no += 1
        bid = f"{sim.name}-{uuid.uuid4().hex[:20]}"
        body = gzip.compress(json.dumps({
            "observations": obs,
            "sensor": {"id": sim.name, "site": sim.site, "version": "0.2.0",
                       "window": {"packets": n_flows * 20, "flows": n_flows}}}).encode())
        hdr = {"Authorization": f"Bearer {sim.credential}", "Idempotency-Key": bid,
               "Content-Type": "application/json", "Content-Encoding": "gzip"}
        sends = 2 if rng.random() < args.duplicate_rate else 1
        for attempt in range(sends):
            t0 = time.perf_counter()
            try:
                r = await client.post(f"{otd}/ingest", content=body, headers=hdr, timeout=60)
                code = r.status_code
            except httpx.HTTPError as exc:
                code = type(exc).__name__
            dt = (time.perf_counter() - t0) * 1000
            phase.lat.append(dt)
            if code == 200:
                if attempt == 0:
                    phase.batches += 1
                    phase.flows += n_flows
                    sim.sent_batches += 1
                    sim.sent_flows += n_flows
                else:
                    phase.dups += 1
                    sim.dup_sent += 1
            else:
                phase.errors[str(code)] = phase.errors.get(str(code), 0) + 1
                if attempt == 0:
                    await asyncio.sleep(2)  # the sensor's backoff; the same batch id is retried
                    r = await client.post(f"{otd}/ingest", content=body, headers=hdr, timeout=60)
                    if r.status_code == 200:
                        phase.batches += 1
                        phase.flows += n_flows
                        sim.sent_batches += 1
                        sim.sent_flows += n_flows
        if time.monotonic() - last_hb > 60:
            last_hb = time.monotonic()
            try:
                await client.post(f"{otd}/heartbeat", headers={"Authorization": f"Bearer {sim.credential}"},
                                  json={"version": "0.2.0", "health": {"packets_seen": batch_no * 100,
                                                                       "sent_at": time.time()}}, timeout=30)
            except httpx.HTTPError:
                pass
        await asyncio.sleep(max(0.0, args.window_s - (time.monotonic() - started)))


async def run_phases(phases: list[Phase], clock: dict, otd_pid: int) -> None:
    for ph in phases:
        clock["phase"] = ph
        ph.t0, ph.cpu0 = time.monotonic(), cpu_seconds(otd_pid)
        print(f"  phase {ph.name:<8} {ph.seconds:>5.0f}s  x{ph.factor:g}", flush=True)
        await asyncio.sleep(ph.seconds)
        ph.t1, ph.cpu1 = time.monotonic(), cpu_seconds(otd_pid)
    clock["stop"] = True


TABLES = ["assets", "asset_edges", "findings", "sensor_batches", "sensors", "audit_log",
          "integration_deliveries", "agent_actions"]


async def sizes(pool: asyncpg.Pool) -> dict[str, tuple[int, int]]:
    out = {}
    async with pool.acquire() as con:
        out["__db__"] = (int(await con.fetchval("SELECT pg_database_size(current_database())")), 0)
        for t in TABLES:
            if await con.fetchval("SELECT to_regclass($1)", t) is None:
                continue
            out[t] = (int(await con.fetchval("SELECT pg_total_relation_size($1::regclass)", t)),
                      int(await con.fetchval(f"SELECT count(*) FROM {t}")))
    return out


def human(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(n) < 1024 or unit == "GiB":
            return f"{n:,.1f} {unit}"
        n /= 1024
    return str(n)


async def amain(args: argparse.Namespace) -> int:
    from app import migrate

    base = args.admin_dsn.rsplit("/", 1)[0]
    name = f"sentryscale_{uuid.uuid4().hex[:8]}"
    admin = await asyncpg.connect(args.admin_dsn)
    await admin.execute(f'CREATE DATABASE "{name}"')
    await admin.close()
    dsn = f"{base}/{name}"
    print(f"database {name}", flush=True)
    rc = 0
    try:
        con = await asyncpg.connect(dsn, command_timeout=None)
        try:
            res = await migrate.migrate_up(con, schema_dir=ROOT / "schema")
            print(f"  migrated {len(res.applied)} files", flush=True)
        finally:
            await con.close()
        oport, tport = free_port(), free_port()
        orch_url, otd = f"http://127.0.0.1:{oport}", f"http://127.0.0.1:{tport}"
        async with orchestrator(dsn, oport) as pool, otdiscovery(args.otd_python, orch_url, tport) as proc:
            rc = await drive(args, pool, orch_url, otd, proc.pid)
    finally:
        if args.keep:
            print(f"kept database {name}")
        else:
            admin = await asyncpg.connect(args.admin_dsn)
            await admin.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                                "WHERE datname = $1 AND pid <> pg_backend_pid()", name)
            await admin.execute(f'DROP DATABASE "{name}"')
            await admin.close()
    return rc


async def drive(args: argparse.Namespace, pool: asyncpg.Pool, orch: str, otd: str, otd_pid: int) -> int:
    rng = random.Random(args.seed)
    sims = [SimSensor(i, args.devices, random.Random(rng.random())) for i in range(args.sensors)]
    limits = httpx.Limits(max_connections=400, max_keepalive_connections=200)
    async with httpx.AsyncClient(limits=limits) as client:
        # -- enroll 100 sensors through the real path (token -> /enroll proxy) ------
        t0 = time.perf_counter()
        for sim in sims:
            tok = (await client.post(f"{orch}/v1/sensors/tokens",
                                     json={"site": sim.site, "ttl_minutes": 30})).json()["token"]
            r = await client.post(f"{otd}/enroll", json={"token": tok, "hostname": sim.name, "name": sim.name})
            r.raise_for_status()
            sim.credential = r.json()["credential"]
        print(f"  enrolled {len(sims)} sensors in {time.perf_counter() - t0:.1f}s", flush=True)

        before = await sizes(pool)
        phases = [Phase("steady", args.steady_s, 1.0), Phase("burst", args.burst_s, args.burst_factor),
                  Phase("recover", args.recover_s, 1.0)]
        clock = {"stop": False, "phase": phases[0]}
        t_start = time.monotonic()
        tasks = [asyncio.create_task(sensor_loop(s, client, otd, phases, clock, args)) for s in sims]
        await run_phases(phases, clock, otd_pid)
        await asyncio.gather(*tasks, return_exceptions=True)
        wall = time.monotonic() - t_start

        # -- reconcile: server counters vs what we sent ----------------------------
        async with pool.acquire() as con:
            row = await con.fetchrow("SELECT COALESCE(sum(flows_total),0) f, COALESCE(sum(batches_total),0) b, "
                                     "COALESCE(sum(duplicates_total),0) d, count(*) n FROM sensors")
            online = await con.fetchval("SELECT count(*) FROM sensors WHERE online AND status = 'active'")
        stats = (await client.get(f"{otd}/stats", timeout=300)).json()
        await asyncio.sleep(0.5)
        after = await sizes(pool)

    sent_flows = sum(s.sent_flows for s in sims)
    sent_batches = sum(s.sent_batches for s in sims)
    sent_dups = sum(s.dup_sent for s in sims)
    ok = (row["f"] == sent_flows and row["b"] == sent_batches and row["d"] == sent_dups)
    result = report(args, phases, wall, before, after, otd_pid)
    result["reconcile"] = {"flows_sent": sent_flows, "flows_counted": int(row["f"]),
                           "batches_sent": sent_batches, "batches_counted": int(row["b"]),
                           "duplicates_sent": sent_dups, "duplicates_acknowledged": int(row["d"]),
                           "sensors_online": int(online), "exact": ok}
    result["otdiscovery"] = {"devices": stats["service"].get("devices"), "observations_stored": stats.get(
        "observations_stored"), "tenant_engines": "n/a"}
    print(f"\nreconcile: sent {sent_flows:,} flows / {sent_batches:,} batches / {sent_dups} replays; "
          f"server counted {int(row['f']):,} / {int(row['b']):,} / {int(row['d'])}  -> "
          f"{'EXACT' if ok else 'MISMATCH'}; sensors online {int(online)}/{args.sensors}")
    md = markdown(result, args)
    print("\n" + md)
    if args.markdown:
        Path(args.markdown).write_text(md)
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2, default=str))
    worst = max((r["p95_ms"] for r in result["phases"]), default=0)
    failures = []
    if not ok:
        failures.append("reconciliation mismatch (a batch was lost or double counted)")
    if worst > args.budget_p95_ms:
        failures.append(f"p95 {worst:.0f} ms over budget {args.budget_p95_ms:.0f} ms")
    if sum(sum(p.errors.values()) for p in phases) > args.max_error_rate * max(1, sum(len(p.lat) for p in phases)):
        failures.append("error rate over budget")
    if failures:
        print("FAIL: " + "; ".join(failures))
        return 1 if args.fail_over_budget else 0
    return 0


def report(args, phases: list[Phase], wall: float, before: dict, after: dict, otd_pid: int) -> dict:
    rows = []
    for ph in phases:
        dur = max(0.001, ph.t1 - ph.t0)
        rows.append({
            "phase": ph.name, "seconds": round(dur, 1), "factor": ph.factor,
            "flows_per_s": round(ph.flows / dur, 1), "batches_per_s": round(ph.batches / dur, 2),
            "requests": len(ph.lat), "errors": dict(ph.errors),
            "p50_ms": round(statistics.median(ph.lat), 1) if ph.lat else None,
            "p95_ms": round(pct(ph.lat, 0.95), 1) if ph.lat else 0.0,
            "p99_ms": round(pct(ph.lat, 0.99), 1) if ph.lat else None,
            "max_ms": round(max(ph.lat), 1) if ph.lat else None,
            "otd_cpu_pct": round(100 * (ph.cpu1 - ph.cpu0) / dur, 1),
        })
    growth = {k: {"bytes": after[k][0] - before.get(k, (0, 0))[0], "rows": after[k][1] - before.get(k, (0, 0))[1]}
              for k in after}
    total_batches = sum(p.batches for p in phases)
    per_day_batches = args.sensors * 86400 / args.window_s
    projection = {}
    if total_batches:
        projection["batch_rows_per_day"] = int(per_day_batches)
        for t in ("sensor_batches", "audit_log"):
            if t in growth:
                projection[f"{t}_bytes_per_day"] = int(growth[t]["bytes"] / total_batches * per_day_batches)
        projection["db_bytes_per_day_total"] = int(growth["__db__"]["bytes"] / total_batches * per_day_batches)
    return {"phases": rows, "growth": growth, "projection_per_day": projection,
            "wall_s": round(wall, 1), "sensors": args.sensors, "flows_per_day": args.flows_per_day}


def markdown(res: dict, args: argparse.Namespace) -> str:
    lines = [
        f"{args.sensors} simulated sensors, {args.devices} devices each, {args.flows_per_day:,} flows/day "
        f"equivalent ({args.flows_per_day / 86400:.1f}/s), {args.window_s:g}s windows, burst x{args.burst_factor:g}, "
        f"{args.duplicate_rate:.0%} of batches replayed with the same batch id.",
        "",
        "| Phase | Flows/s | Batches/s | Requests | p50 ms | p95 ms | p99 ms | max ms | Errors | otdiscovery CPU |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|---:|",
    ]
    for r in res["phases"]:
        lines.append(f"| {r['phase']} x{r['factor']:g} | {r['flows_per_s']} | {r['batches_per_s']} | {r['requests']} | "
                     f"{r['p50_ms']} | {r['p95_ms']} | {r['p99_ms']} | {r['max_ms']} | {r['errors'] or 'none'} | "
                     f"{r['otd_cpu_pct']}% |")
    lines += ["", "| Table | Rows added | Size added |", "|---|---:|---:|"]
    for k, v in sorted(res["growth"].items(), key=lambda kv: -kv[1]["bytes"]):
        label = "database total" if k == "__db__" else k
        rows_txt = "" if k == "__db__" else format(v["rows"], ",")
        lines.append(f"| {label} | {rows_txt} | {human(v['bytes'])} |")
    p = res["projection_per_day"]
    if p:
        parts = []
        for k, v in p.items():
            txt = human(v) if "bytes" in k else format(v, ",")
            parts.append(k.replace("_", " ") + " " + txt)
        lines += ["", "Projection at this batch rate (per day): " + ", ".join(parts)]
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--admin-dsn", default=os.environ.get("SCALE_ADMIN_DSN",
                                                        "postgresql://postgres@127.0.0.1:5432/postgres"))
    p.add_argument("--otd-python", default=os.environ.get("OTD_PYTHON", sys.executable),
                   help="python of an env with otdiscovery's deps (aiohttp, asyncpg); its package is also named 'app'")
    p.add_argument("--sensors", type=int, default=100)
    p.add_argument("--devices", type=int, default=30, help="devices per simulated site")
    p.add_argument("--flows-per-day", type=int, default=1_000_000)
    p.add_argument("--burst-factor", type=float, default=50.0)
    p.add_argument("--window-s", type=float, default=30.0)
    p.add_argument("--steady-s", type=float, default=90.0)
    p.add_argument("--burst-s", type=float, default=60.0)
    p.add_argument("--recover-s", type=float, default=60.0)
    p.add_argument("--duplicate-rate", type=float, default=0.02)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--budget-p95-ms", type=float, default=2000.0)
    p.add_argument("--max-error-rate", type=float, default=0.01)
    p.add_argument("--fail-over-budget", action="store_true")
    p.add_argument("--markdown", default=None)
    p.add_argument("--json", default=None)
    p.add_argument("--keep", action="store_true")
    return asyncio.run(amain(p.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
