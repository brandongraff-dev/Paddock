"""``paddock-sentry`` command line.

    paddock-sentry run --iface eth1 --server https://paddock.example:8101 --token $TOKEN
    paddock-sentry run --pcap capture.pcap --dry-run          # print what would be sent
    paddock-sentry run --spool /var/spool/paddock --server ...
    paddock-sentry doctor --iface eth1 --server ...           # pre-flight checks
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import socket
import sys
import urllib.request
from typing import Any, Iterable

from . import __version__, install_egress_guard
from .aggregate import Aggregator
from .ship import Shipper
from .sources import Record, from_file, from_spool, live

log = logging.getLogger("paddock_sentry")


def pump(records: Iterable[Record], agg: Aggregator, emit) -> int:  # type: ignore[no-untyped-def]
    """Feed records through the aggregator, emitting a batch per window."""
    batches = 0
    for ts, wire_len, obs in records:
        if agg.due(ts):
            emit(agg.flush())
            batches += 1
        agg.add(ts, wire_len, obs)
    if agg.window_start is not None:
        emit(agg.flush())
        batches += 1
    return batches


def _cmd_run(a: argparse.Namespace) -> int:
    token = a.token or os.environ.get("PADDOCK_SENTRY_TOKEN")
    if not a.dry_run:
        if not a.server:
            print("error: --server is required (or use --dry-run)", file=sys.stderr)
            return 2
        install_egress_guard(a.server)
    agg = Aggregator(window_s=a.window)
    if a.dry_run:
        def emit(batch: dict[str, Any]) -> None:
            print(json.dumps({"window": batch["window"], "observations": batch["observations"]}))
    else:
        shipper = Shipper(a.server, token, sensor_id=a.sensor_id, site=a.site, outbox=a.outbox)

        def emit(batch: dict[str, Any]) -> None:
            ok = shipper.send(batch)
            w = batch["window"]
            log.info("window: %d pkts %d flows %d announcements -> %s",
                     w["packets"], w["flows"], w["announcements"], "sent" if ok else "spooled")

    if a.pcap:
        records = from_file(a.pcap)
    elif a.spool:
        records = from_spool(a.spool, once=a.once)
    else:
        records = live(a.iface, server_url=a.server, bpf=a.bpf)
    try:
        n = pump(records, agg, emit)
    except KeyboardInterrupt:
        n = 0
        if agg.window_start is not None:  # don't lose the partial window on Ctrl-C / SIGINT
            emit(agg.flush())
            n = 1
    log.info("done: %d batch(es)", n)
    return 0


def _can_capture() -> bool:
    if os.geteuid() == 0:
        return True
    getcap, tcpdump = shutil.which("getcap"), shutil.which("tcpdump")
    if not (getcap and tcpdump):
        return False
    import subprocess

    out = subprocess.run([getcap, tcpdump], capture_output=True, text=True, check=False).stdout  # noqa: S603
    return "cap_net_raw" in out


def _cmd_doctor(a: argparse.Namespace) -> int:
    ok = True

    def check(name: str, passed: bool, hint: str = "") -> None:
        nonlocal ok
        ok &= passed
        print(f"  [{'ok' if passed else 'FAIL'}] {name}" + ("" if passed else f"  -> {hint}"))

    print(f"paddock-sentry {__version__} doctor")
    check("tcpdump installed", bool(shutil.which("tcpdump")), "apt install tcpdump")
    if a.iface:
        check(f"interface {a.iface} exists", os.path.exists(f"/sys/class/net/{a.iface}"),
              "ip link  # pick the interface wired to the mirror/SPAN port")
        check("capture permission (root or CAP_NET_RAW on tcpdump)", _can_capture(),
              "run as root or: setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)")
    if a.server:
        try:
            with urllib.request.urlopen(a.server.rstrip("/") + "/healthz", timeout=5) as r:  # noqa: S310
                check("server reachable", r.status == 200)
        except (OSError, ValueError) as exc:
            check("server reachable", False, f"{exc}")
    check("token configured", bool(a.token or os.environ.get("PADDOCK_SENTRY_TOKEN")),
          "--token or PADDOCK_SENTRY_TOKEN (create one in Paddock: Settings > Sensors)")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="paddock-sentry", description="Passive network sensor for Paddock.")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="capture and ship observations")
    src = r.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="interface wired to a mirror/SPAN port")
    src.add_argument("--pcap", help="replay a classic-pcap file")
    src.add_argument("--spool", help="consume *.pcap files dropped into a directory")
    r.add_argument("--server", default=os.environ.get("PADDOCK_SERVER"), help="Paddock ingest base URL")
    r.add_argument("--token", default=None, help="sensor token (or PADDOCK_SENTRY_TOKEN)")
    r.add_argument("--sensor-id", default=os.environ.get("PADDOCK_SENTRY_ID", socket.gethostname()))
    r.add_argument("--site", default=os.environ.get("PADDOCK_SITE"))
    r.add_argument("--window", type=float, default=30.0, help="seconds per batch")
    r.add_argument("--outbox", default=os.environ.get("PADDOCK_SENTRY_OUTBOX", "/var/lib/paddock-sentry/outbox"))
    r.add_argument("--bpf", help="extra BPF filter, e.g. 'not port 22'")
    r.add_argument("--once", action="store_true", help="with --spool: process what's there and exit")
    r.add_argument("--dry-run", action="store_true", help="print batches instead of shipping")
    r.set_defaults(fn=_cmd_run)

    d = sub.add_parser("doctor", help="pre-flight checks")
    d.add_argument("--iface")
    d.add_argument("--server", default=os.environ.get("PADDOCK_SERVER"))
    d.add_argument("--token")
    d.set_defaults(fn=_cmd_doctor)

    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
