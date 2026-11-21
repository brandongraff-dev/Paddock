"""Syslog connector: RFC 5424 messages carrying CEF or OCSF JSON.

Transports:

* ``tls`` (default, port 6514) -- RFC 5425 syslog over TLS >= 1.2 with
  certificate + hostname verification against the system trust store or a
  configured ``ca_cert`` PEM. ``tls_verify: false`` is honoured only for
  ``allow_private`` integrations.
* ``tcp`` (port 514, RFC 6587 octet-counted framing) and ``udp`` (RFC 5426,
  one datagram per message) are **plaintext**, so they are refused unless the
  integration has ``allow_private`` AND every address the host resolves to is
  private/loopback. Plaintext findings never cross the internet.

Destination safety: the host is checked with ``netsafety`` (metadata/reserved
ranges always refused; private only with ``allow_private``), then resolved
ONCE here and every resolved address re-checked; the socket connects to that
vetted address (TLS still verifies the configured hostname via SNI), so a DNS
rebind between check and connect cannot redirect the stream.

Payload (``format``):

* ``ocsf_json`` (default) -- the compact OCSF 1.3 JSON object as MSG.
* ``cef`` -- ArcSight CEF:0 built from the same OCSF mapping (see
  docs/INTEGRATIONS-SIEM.md for the extension-key table).

The RFC 5424 header carries PRI (facility * 8 + severity), an RFC 3339
timestamp, APP-NAME ``paddock``, MSGID = the event type, and one
structured-data element ``[paddock@32473 eventId=... eventType=...
classUid=... severity=...]`` (32473 is the RFC 5612 documentation PEN;
override ``sd_id`` with your own).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, ClassVar, Mapping, Optional

from ... import scope
from ... import __version__
from .. import netsafety
from ..base import DeliveryResult, Event, HealthResult, register
from ._siem import SiemConnector, test_event

CONNECT_TIMEOUT = 5.0
WRITE_TIMEOUT = 10.0
MAX_UDP_BYTES = 8192

# Paddock severity -> syslog severity (RFC 5424 table 2).
_SYSLOG_SEV = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
# OCSF severity_id -> CEF severity (0-10).
_CEF_SEV = {0: 0, 1: 1, 2: 3, 3: 5, 4: 8, 5: 10}
_PADDOCK_SEV = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}


# --------------------------------------------------------------------------- #
# formatting (pure)
# --------------------------------------------------------------------------- #

def _printusascii(s: str, limit: int) -> str:
    out = "".join(c for c in s if 33 <= ord(c) <= 126)
    return (out or "-")[:limit]


def _sd_escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def cef_header_escape(v: Any) -> str:
    s = str(v if v is not None else "")
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def cef_ext_escape(v: Any) -> str:
    s = str(v if v is not None else "")
    return (s.replace("\\", "\\\\").replace("=", "\\=")
             .replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\r"))


def _paddock(record: Mapping[str, Any]) -> Mapping[str, Any]:
    um = record.get("unmapped")
    p = um.get("paddock") if isinstance(um, Mapping) else None
    return p if isinstance(p, Mapping) else {}


def to_cef(record: Mapping[str, Any], event: Event) -> str:
    """ArcSight CEF:0 line for one OCSF record."""
    fi = record.get("finding_info") or {}
    sid = int(record.get("severity_id") or 0)
    pd = _paddock(record)
    sig = pd.get("rule_id") or (fi.get("analytic") or {}).get("uid") or event.type
    name = fi.get("title") or event.title
    header = "|".join([
        "CEF:0", "Paddock", "Paddock", cef_header_escape(__version__),
        cef_header_escape(sig)[:1023], cef_header_escape(name)[:512], str(_CEF_SEV.get(sid, 0)),
    ])
    ext: list[tuple[str, Any]] = [
        ("rt", record.get("time")),
        ("externalId", fi.get("uid")),
        ("cat", event.type),
        ("msg", (fi.get("desc") or event.summary or "")[:1023]),
        ("cs1Label", "ocsfClassUid"), ("cs1", record.get("class_uid")),
        ("cs2Label", "status"), ("cs2", pd.get("status") or record.get("status")),
    ]
    vulns = record.get("vulnerabilities") or []
    cves = [v["cve"]["uid"] for v in vulns if isinstance(v.get("cve"), Mapping)]
    cwes = list(dict.fromkeys(v["cwe"]["uid"] for v in vulns if isinstance(v.get("cwe"), Mapping)))
    if cves:
        ext += [("cs3Label", "cve"), ("cs3", ",".join(cves))]
    if cwes:
        ext += [("cs4Label", "cwe"), ("cs4", ",".join(cwes))]
    if pd.get("rule_source"):
        ext += [("cs5Label", "ruleSource"), ("cs5", pd["rule_source"])]
    res = (record.get("resources") or [None])[0]
    if isinstance(res, Mapping):
        kind, value = res.get("type"), res.get("name")
        if kind:
            ext += [("cs6Label", "assetKind"), ("cs6", kind)]
        if value:
            if kind in ("ipv4", "ipv6"):
                ext.append(("dst", value))
            elif kind in ("domain", "subdomain"):
                ext.append(("dhost", value))
            else:
                ext.append(("duser" if kind == "repository" else "dvchost", value))
    if pd.get("cvss") is not None:
        ext += [("cn1Label", "cvss"), ("cn1", pd["cvss"])]
    if pd.get("epss") is not None:
        ext += [("cfp1Label", "epss"), ("cfp1", pd["epss"])]
    if fi.get("src_url"):
        ext.append(("request", fi["src_url"]))
    ext_s = " ".join(f"{k}={cef_ext_escape(v)}" for k, v in ext if v is not None and v != "")
    return f"{header}|{ext_s}"


def to_rfc5424(record: Mapping[str, Any], event: Event, *, fmt: str, facility: int,
               hostname: str, app_name: str, sd_id: str) -> bytes:
    sid = int(record.get("severity_id") or 0)
    sev_word = _PADDOCK_SEV.get(sid, "info")
    pri = facility * 8 + _SYSLOG_SEV.get(sev_word, 6)
    ts = record.get("time")
    when = (datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc) if isinstance(ts, (int, float))
            else event.occurred_at.astimezone(timezone.utc))
    stamp = when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"
    params = {
        "eventId": event.id,
        "eventType": event.type,
        "classUid": str(record.get("class_uid") or ""),
        "severity": sev_word,
        "findingUid": str((record.get("finding_info") or {}).get("uid") or ""),
    }
    sd = "[" + _printusascii(sd_id, 32).replace("=", "").replace("]", "").replace('"', "") + "".join(
        f' {k}="{_sd_escape(v)}"' for k, v in params.items() if v) + "]"
    if fmt == "cef":
        msg = to_cef(record, event)
    else:
        msg = json.dumps(record, separators=(",", ":"), default=str, ensure_ascii=False)
    head = " ".join([
        f"<{pri}>1", stamp, _printusascii(hostname, 255), _printusascii(app_name, 48), "-",
        _printusascii(event.type, 32), sd,
    ])
    return (head + " " + msg).encode("utf-8")


def frame_octet_counted(msg: bytes) -> bytes:
    """RFC 5425 / 6587 octet-counting: ``MSG-LEN SP SYSLOG-MSG``."""
    return str(len(msg)).encode("ascii") + b" " + msg


def shrink(record: dict[str, Any]) -> dict[str, Any]:
    """A smaller OCSF record for size-limited UDP datagrams."""
    small = {k: v for k, v in record.items()
             if k not in ("vulnerabilities", "remediation", "observables")}
    fi = dict(small.get("finding_info") or {})
    if fi.get("desc"):
        fi["desc"] = str(fi["desc"])[:512]
    small["finding_info"] = fi
    return small


# --------------------------------------------------------------------------- #
# connector
# --------------------------------------------------------------------------- #

class _Refused(Exception):
    pass


@register
class SyslogConnector(SiemConnector):
    kind = "syslog"
    display_name = "Syslog (RFC 5424, CEF / OCSF JSON)"
    docs_url = "https://www.rfc-editor.org/rfc/rfc5424"
    secret_fields: ClassVar[tuple[str, ...]] = ()
    max_batch: ClassVar[int] = 500
    config_schema = {
        "type": "object",
        "required": ["host"],
        "properties": {
            "host": {"type": "string", "description": "Collector host name or IP"},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535,
                     "description": "Default 6514 for tls, 514 for tcp/udp"},
            "transport": {"type": "string", "enum": ["tls", "tcp", "udp"], "default": "tls",
                          "description": "tcp/udp are plaintext: private targets only"},
            "format": {"type": "string", "enum": ["ocsf_json", "cef"], "default": "ocsf_json"},
            "facility": {"type": "integer", "minimum": 0, "maximum": 23, "default": 13},
            "app_name": {"type": "string", "default": "paddock"},
            "hostname": {"type": "string", "description": "HOSTNAME header field (default: paddock)"},
            "sd_id": {"type": "string", "default": "paddock@32473"},
            "ca_cert": {"type": "string", "description": "PEM CA bundle to trust (public data)"},
            "tls_verify": {"type": "boolean", "default": True,
                           "description": "Only allow_private integrations may turn this off"},
        },
    }

    # -- settings ------------------------------------------------------------ #
    @property
    def transport(self) -> str:
        t = str(self.config.get("transport") or "tls").lower()
        return t if t in ("tls", "tcp", "udp") else "invalid"

    @property
    def port(self) -> int:
        p = self.config.get("port")
        if isinstance(p, int) and 0 < p < 65536:
            return p
        return 6514 if self.transport == "tls" else 514

    @property
    def fmt(self) -> str:
        f = str(self.config.get("format") or "ocsf_json").lower()
        return "cef" if f == "cef" else "ocsf_json"

    def _facility(self) -> int:
        f = self.config.get("facility", 13)
        return f if isinstance(f, int) and 0 <= f <= 23 else 13

    def messages(self, records: list[dict[str, Any]], events: list[Event]) -> list[bytes]:
        out = []
        for r, e in zip(records, events):
            kw = dict(fmt=self.fmt, facility=self._facility(),
                      hostname=str(self.config.get("hostname") or "paddock"),
                      app_name=str(self.config.get("app_name") or "paddock"),
                      sd_id=str(self.config.get("sd_id") or "paddock@32473"))
            msg = to_rfc5424(r, e, **kw)
            if self.transport == "udp" and len(msg) > MAX_UDP_BYTES:
                msg = to_rfc5424(shrink(r), e, **kw)[:MAX_UDP_BYTES]
            out.append(msg)
        return out

    # -- destination safety --------------------------------------------------- #
    @staticmethod
    def _url_host(h: str) -> str:
        try:
            if ipaddress.ip_address(h).version == 6:
                return f"[{h}]"
        except ValueError:
            pass
        return h

    async def resolve(self) -> list[str]:
        host = str(self.config.get("host") or "").strip()
        if not host:
            raise _Refused("missing config 'host'")
        if self.transport == "invalid":
            raise _Refused("transport must be one of tls, tcp, udp")
        port = self.port
        # 1. policy check on the configured name (resolves every address).
        await netsafety.validate_outbound_url(f"https://{self._url_host(host)}:{port}/",
                                              allow_private=self.allow_private)
        # 2. resolve once, re-check each literal (no DNS), connect to these.
        loop = asyncio.get_running_loop()
        stype = socket.SOCK_DGRAM if self.transport == "udp" else socket.SOCK_STREAM
        try:
            infos = await loop.getaddrinfo(host, port, type=stype)
        except OSError as exc:
            raise netsafety.UnsafeURL(f"host does not resolve: {host}") from exc
        ips = list(dict.fromkeys(i[4][0] for i in infos))
        for ip in ips:
            await netsafety.validate_outbound_url(f"https://{self._url_host(ip)}:{port}/",
                                                  allow_private=self.allow_private)
            if self.transport != "tls":
                addr = scope._unmap(ipaddress.ip_address(ip))
                if not (self.allow_private and scope.is_internal(addr)):
                    raise _Refused(
                        f"plaintext syslog ({self.transport}) is only allowed to private targets "
                        "with allow_private; use transport=tls for public collectors")
        if not ips:
            raise netsafety.UnsafeURL(f"host does not resolve: {host}")
        return ips

    def ssl_context(self) -> ssl.SSLContext:
        verify = self.config.get("tls_verify", True) is not False
        if not verify and not self.allow_private:
            raise _Refused("tls_verify=false is only allowed for allow_private integrations")
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ca = self.config.get("ca_cert")
        if ca:
            ctx.load_verify_locations(cadata=str(ca))
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    # -- send ---------------------------------------------------------------- #
    async def _send_stream(self, ips: list[str], frames: list[bytes]) -> None:
        host = str(self.config["host"]).strip()
        ctx = self.ssl_context() if self.transport == "tls" else None
        last: Optional[BaseException] = None
        for ip in ips:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, self.port, ssl=ctx,
                                            server_hostname=host if ctx else None),
                    timeout=CONNECT_TIMEOUT)
            except (OSError, asyncio.TimeoutError) as exc:
                if isinstance(exc, ssl.SSLError):
                    raise
                last = exc
                continue
            try:
                writer.write(b"".join(frames))
                await asyncio.wait_for(writer.drain(), timeout=WRITE_TIMEOUT)
            finally:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                except (OSError, asyncio.TimeoutError, ssl.SSLError):
                    pass
            return
        raise last or OSError("no address to connect to")

    async def _send_udp(self, ips: list[str], msgs: list[bytes]) -> None:
        loop = asyncio.get_running_loop()
        family = socket.AF_INET6 if ":" in ips[0] else socket.AF_INET
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=(ips[0], self.port), family=family)
        try:
            for m in msgs:
                transport.sendto(m)
        finally:
            transport.close()

    async def send_records(self, records: list[dict[str, Any]], events: list[Event]) -> DeliveryResult:
        try:
            ips = await self.resolve()
            msgs = self.messages(records, events)
            if self.transport == "udp":
                await self._send_udp(ips, msgs)
                return DeliveryResult(ok=True, detail=f"sent {len(msgs)} datagram(s) (UDP is unacknowledged)")
            await self._send_stream(ips, [frame_octet_counted(m) for m in msgs])
            return DeliveryResult(ok=True, detail=f"sent {len(msgs)} message(s) over {self.transport}")
        except _Refused as exc:
            return self.fail(str(exc), retryable=False)
        except netsafety.UnsafeURL as exc:
            return self.fail(f"refused unsafe destination: {exc}", retryable=False)
        except ssl.SSLCertVerificationError as exc:
            return self.fail(f"TLS certificate verification failed: {exc.verify_message}", retryable=False)
        except ssl.SSLError as exc:
            return self.fail(f"TLS error: {exc.reason or type(exc).__name__}", retryable=False)
        except asyncio.TimeoutError:
            return self.fail("timed out contacting the syslog collector", retryable=True)
        except OSError as exc:
            return self.fail(f"connection failed: {exc.strerror or type(exc).__name__}", retryable=True)

    async def test(self) -> HealthResult:
        res = await self.deliver_batch([test_event()])
        return HealthResult(ok=res.ok, detail=res.detail)
