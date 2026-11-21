"""Fakes for the passive growth features: NO network, ever.

``FakeResolver`` answers from an in-memory zone; ``FakeCT`` returns canned
crt.sh-shaped rows. Both record every call so tests can assert exactly what
the engine asked for (and that nothing else happened).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.growth.engine import CTError, DnsResult

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)


class FakeResolver:
    def __init__(self, zone: dict[tuple[str, str], list[str]] | None = None, nx: set[str] | None = None):
        # (name, rtype) -> records. A name in `nx` is NXDOMAIN for every type.
        self.zone = {(n.lower(), t): v for (n, t), v in (zone or {}).items()}
        self.nx = {n.lower() for n in (nx or set())}
        self.calls: list[tuple[str, str]] = []

    def add(self, name: str, rtype: str, *records: str) -> "FakeResolver":
        self.zone[(name.lower(), rtype)] = list(records)
        return self

    async def resolve(self, name: str, rtype: str) -> DnsResult:
        name = name.lower().rstrip(".")
        self.calls.append((name, rtype))
        if name in self.nx:
            return DnsResult("nxdomain")
        recs = self.zone.get((name, rtype))
        if recs:
            return DnsResult("ok", list(recs))
        # a name that exists for some other type is NODATA, else NXDOMAIN
        if any(n == name for (n, _t) in self.zone):
            return DnsResult("nodata")
        return DnsResult("nxdomain")


class FakeCT:
    def __init__(self, rows: list[dict] | None = None, fail: bool = False):
        self.rows = rows or []
        self.fail = fail
        self.calls: list[str] = []

    async def fetch(self, domain: str) -> list[dict]:
        self.calls.append(domain)
        if self.fail:
            raise CTError("down")
        return list(self.rows)


def cert(names, *, serial="01", issuer="C=US, O=Let's Encrypt, CN=R3", days_left=60, age_days=30, **extra) -> dict:
    return {
        "name_value": "\n".join(names),
        "serial_number": serial,
        "issuer_name": issuer,
        "common_name": names[0],
        "not_before": (NOW - timedelta(days=age_days)).strftime("%Y-%m-%dT%H:%M:%S"),
        "not_after": (NOW + timedelta(days=days_left)).strftime("%Y-%m-%dT%H:%M:%S"),
        **extra,
    }


def healthy_zone(domain: str = "acme.test.org") -> FakeResolver:
    """A tidy domain: 2 NS, MX, strict SPF, DMARC reject, MTA-STS, CAA."""
    r = FakeResolver()
    r.add(domain, "NS", "ns1.dnsprovider.net", "ns2.dnsprovider.net")
    r.add(domain, "A", "93.184.216.34")
    r.add(domain, "MX", "10 aspmx.l.google.com")
    r.add(domain, "TXT", "v=spf1 include:_spf.google.com -all")
    r.add("_spf.google.com", "TXT", "v=spf1 ip4:35.190.247.0/24 -all")
    r.add(f"_dmarc.{domain}", "TXT", "v=DMARC1; p=reject; rua=mailto:d@" + domain)
    r.add(f"_mta-sts.{domain}", "TXT", "v=STSv1; id=1")
    r.add(f"_smtp._tls.{domain}", "TXT", "v=TLSRPTv1; rua=mailto:t@" + domain)
    r.add(domain, "CAA", '0 issue "letsencrypt.org"')
    r.add(domain, "DS", "12345 13 2 abcdef")
    r.add("ns1.dnsprovider.net", "A", "198.51.100.1")
    r.add("ns2.dnsprovider.net", "A", "198.51.100.2")
    r.add("aspmx.l.google.com", "A", "142.250.0.1")
    r.add(f"www.{domain}", "A", "93.184.216.34")
    return r
