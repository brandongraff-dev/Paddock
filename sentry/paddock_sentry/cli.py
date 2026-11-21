"""``paddock-sentry`` command line.

    paddock-sentry enroll https://paddock.example:8101 pet_xxxxxxxx_...   # once, per sensor
    paddock-sentry run --iface eth1                                      # uses the enrolled credential
    paddock-sentry run --iface eth1 --server https://paddock.example:8101 --token $TOKEN   # legacy shared token
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
import signal
import socket
import sys
import urllib.request
from typing import Any, Iterable

from . import __version__, install_egress_guard, netif, store
from .aggregate import Aggregator
from .enroll import EnrollError, enroll as do_enroll
from .health import Heartbeat, RunStats
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


def _creds(a: argparse.Namespace) -> store.Credentials | None:
    try:
        return store.load(a.cred or store.default_path())
    except store.CredentialError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


def _cmd_run(a: argparse.Namespace) -> int:
    creds = _creds(a)
    server = a.server or (creds.server if creds else None)
    token = a.token or os.environ.get("PADDOCK_SENTRY_TOKEN") or (creds.credential if creds else None)
    site = a.site or (creds.site if creds else None)
    sensor_id = a.sensor_id or (creds.name if creds and creds.name else socket.gethostname())
    if not a.dry_run:
        if not server:
            print("error: this sensor is not enrolled. Run `paddock-sentry enroll <server> <token>` "
                  "(or pass --server and --token, or use --dry-run)", file=sys.stderr)
            return 2
        install_egress_guard(server)
    agg = Aggregator(window_s=a.window)
    stats = RunStats()
    stop_hb = None
    if a.dry_run:
        def emit(batch: dict[str, Any]) -> None:
            print(json.dumps({"window": batch["window"], "observations": batch["observations"]}))
    else:
        shipper = Shipper(server, token, sensor_id=sensor_id, site=site, outbox=a.outbox,
                          outbox_max_bytes=int(a.outbox_max_mb * 1024 * 1024))
        if token and token.startswith("pst_"):
            hb = Heartbeat(server, token, shipper, stats, iface=a.iface, interval=a.heartbeat)
            _, stop_hb = hb.start()

        def emit(batch: dict[str, Any]) -> None:
            ok = shipper.send(batch)
            w = batch["window"]
            stats.add_window(w)
            log.info("window: %d pkts %d flows %d announcements -> %s",
                     w["packets"], w["flows"], w["announcements"], "sent" if ok else "buffered")

    if a.pcap:
        records = from_file(a.pcap)
    elif a.spool:
        records = from_spool(a.spool, once=a.once)
    else:
        records = live(a.iface, server_url=server, bpf=a.bpf)

    def _term(*_: Any) -> None:  # systemd stop: flush the partial window like Ctrl-C does
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, _term)
    except (ValueError, OSError):  # not the main thread (tests)
        pass
    try:
        n = pump(records, agg, emit)
    except KeyboardInterrupt:
        n = 0
        if agg.window_start is not None:  # don't lose the partial window on Ctrl-C / SIGINT
            emit(agg.flush())
            n = 1
    finally:
        if stop_hb is not None:
            stop_hb.set()
    log.info("done: %d batch(es)", n)
    return 0


def _cmd_enroll(a: argparse.Namespace) -> int:
    server = a.server or os.environ.get("PADDOCK_SERVER")
    token = a.token or os.environ.get("PADDOCK_ENROLL_TOKEN")
    if not server or not token:
        print("usage: paddock-sentry enroll <server> <token>   (or PADDOCK_SERVER / PADDOCK_ENROLL_TOKEN)",
              file=sys.stderr)
        return 2
    allow_http = a.allow_http or os.environ.get("PADDOCK_ALLOW_HTTP", "").lower() in ("1", "true", "yes")
    try:
        creds = do_enroll(server, token, name=a.name or os.environ.get("PADDOCK_SENTRY_NAME"),
                          cred_path=a.cred, force=a.force, allow_http=allow_http)
    except EnrollError as exc:
        print(f"enroll failed: {exc}", file=sys.stderr)
        return 1
    path = a.cred or store.default_path()
    print(f"enrolled as {creds.name} (site {creds.site}); credential saved to {path} (mode 600)")
    print("next: paddock-sentry doctor   then   paddock-sentry run --iface <mirror-port>")
    return 0


def _cmd_status(a: argparse.Namespace) -> int:
    creds = _creds(a)
    if creds is None:
        print("not enrolled")
        return 1
    from .buffer import Outbox
    box = Outbox(a.outbox) if os.path.isdir(a.outbox) else None
    print(json.dumps({
        "enrolled": True, "sensor_id": creds.sensor_id, "name": creds.name, "site": creds.site,
        "server": creds.server, "enrolled_at": creds.enrolled_at, "version": __version__,
        "buffer": {"batches": len(box) if box else 0, "bytes": box.size() if box else 0},
    }, indent=2))
    return 0


def _cmd_pick_iface(a: argparse.Namespace) -> int:
    iface, why = netif.pick_capture_interface()
    if iface is None:
        print(why, file=sys.stderr)
        return 1
    if a.explain:
        print(why, file=sys.stderr)
    print(iface)
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
    creds = _creds(a)
    check("sensor enrolled (or a token configured)",
          bool(creds or a.token or os.environ.get("PADDOCK_SENTRY_TOKEN")),
          "paddock-sentry enroll <server> <token>   (create the token in Paddock: Sensors > Add sensor)")
    if creds and not a.server:
        try:
            with urllib.request.urlopen(creds.server.rstrip("/") + "/healthz", timeout=5) as r:  # noqa: S310
                check(f"enrolled server {creds.server} reachable", r.status == 200)
        except (OSError, ValueError) as exc:
            check(f"enrolled server {creds.server} reachable", False, f"{exc}")
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
    r.add_argument("--sensor-id", default=os.environ.get("PADDOCK_SENTRY_ID"))
    r.add_argument("--cred", default=None, help="credential file (default: PADDOCK_SENTRY_CRED or "
                                                "/var/lib/paddock-sentry/credentials.json)")
    r.add_argument("--heartbeat", type=float, default=60.0, help="seconds between health heartbeats")
    r.add_argument("--outbox-max-mb", type=float,
                   default=float(os.environ.get("PADDOCK_SENTRY_OUTBOX_MB", "256")),
                   help="upload buffer cap; oldest batches are dropped first")
    r.add_argument("--site", default=os.environ.get("PADDOCK_SITE"))
    r.add_argument("--window", type=float, default=30.0, help="seconds per batch")
    r.add_argument("--outbox", default=os.environ.get("PADDOCK_SENTRY_OUTBOX", "/var/lib/paddock-sentry/outbox"))
    r.add_argument("--bpf", help="extra BPF filter, e.g. 'not port 22'")
    r.add_argument("--once", action="store_true", help="with --spool: process what's there and exit")
    r.add_argument("--dry-run", action="store_true", help="print batches instead of shipping")
    r.set_defaults(fn=_cmd_run)

    e = sub.add_parser("enroll", help="exchange a one-time enrollment token for this sensor's credential")
    e.add_argument("server", nargs="?", help="Paddock sensor-ingest URL, e.g. https://paddock.example:8101")
    e.add_argument("token", nargs="?", help="enrollment token (pet_...), or PADDOCK_ENROLL_TOKEN")
    e.add_argument("--name", help="sensor name shown in the dashboard (default: hostname)")
    e.add_argument("--cred", default=None, help="where to store the credential (mode 600)")
    e.add_argument("--force", action="store_true", help="enroll again over an existing credential")
    e.add_argument("--allow-http", action="store_true", help="allow plain http to a non-local server")
    e.set_defaults(fn=_cmd_enroll)

    st = sub.add_parser("status", help="show this sensor's enrollment and upload buffer")
    st.add_argument("--cred", default=None)
    st.add_argument("--outbox", default=os.environ.get("PADDOCK_SENTRY_OUTBOX", "/var/lib/paddock-sentry/outbox"))
    st.set_defaults(fn=_cmd_status)

    pi = sub.add_parser("pick-iface", help="print the NIC that looks like the mirror/SPAN port")
    pi.add_argument("--explain", action="store_true")
    pi.set_defaults(fn=_cmd_pick_iface)

    d = sub.add_parser("doctor", help="pre-flight checks")
    d.add_argument("--cred", default=None)
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
