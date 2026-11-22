"""The passive engine, driven entirely by a fake resolver and a fake CT log."""
from __future__ import annotations

import base64
import json
import re

import pytest
from app.growth import engine
from app.growth.config import GrowthSettings

from tests.growth_fakes import NOW, FakeCT, FakeResolver, cert, healthy_zone

D = "acme-corp.org"
S = GrowthSettings()


async def run(resolver, ct=None, domain=D):
    return await engine.assess(domain, resolver=resolver, ct=ct or FakeCT(), now=NOW, settings=S)


def rules(a):
    return {f["rule"] for f in a.findings}


def by_rule(a, rule):
    return [f for f in a.findings if f["rule"] == rule]


@pytest.mark.asyncio
async def test_healthy_domain_grades_a():
    a = await run(healthy_zone(D), FakeCT([cert([D, f"www.{D}"])]))
    assert a.grade == "A", a.reasons
    assert a.score >= 90
    assert a.reasons == ["No issues found in public DNS and certificate-transparency data."]
    assert a.stats["email"]["dmarc"] == "reject"
    assert a.stats["email"]["spf"] == "fail"
    assert a.stats["email"]["mta_sts"] is True


@pytest.mark.asyncio
async def test_domain_that_does_not_exist():
    with pytest.raises(engine.DomainNotFound):
        await run(FakeResolver(nx={D}))


@pytest.mark.asyncio
async def test_only_dns_and_ct_calls_are_made():
    r, ct = healthy_zone(D), FakeCT([cert([D, f"www.{D}"])])
    await run(r, ct)
    assert ct.calls == [D]
    assert {t for _, t in r.calls} <= {"NS", "A", "AAAA", "MX", "TXT", "CAA", "DS", "CNAME"}


@pytest.mark.asyncio
async def test_email_auth_gaps_are_graded():
    r = FakeResolver()
    r.add(D, "NS", "ns1.p.net")
    r.add(D, "A", "93.184.216.34")
    r.add(D, "MX", "10 mx.mailhost.net")
    r.add("mx.mailhost.net", "A", "203.0.113.5")
    r.add("ns1.p.net", "A", "198.51.100.1")
    a = await run(r)
    assert {"spf_missing", "dmarc_missing", "mta_sts_missing", "single_nameserver", "no_caa"} <= rules(a)
    assert by_rule(a, "dmarc_missing")[0]["severity"] == "high"
    assert a.grade in ("B", "C")  # one high + mediums, not catastrophic
    assert a.stats["email"]["dmarc"] == "missing"


@pytest.mark.asyncio
async def test_spf_variants():
    base = healthy_zone(D)
    base.add(D, "TXT", "v=spf1 +all")
    a = await run(base)
    assert "spf_allow_all" in rules(a)

    r = healthy_zone(D).add(D, "TXT", "v=spf1 ip4:1.2.3.4 ?all")
    assert "spf_neutral" in rules(await run(r))

    r = healthy_zone(D).add(D, "TXT", "v=spf1 ip4:1.2.3.4")
    assert "spf_no_all" in rules(await run(r))

    r = healthy_zone(D).add(D, "TXT", "v=spf1 -all", "v=spf1 ip4:1.1.1.1 -all")
    assert "spf_multiple" in rules(await run(r))


@pytest.mark.asyncio
async def test_spf_lookup_limit_counts_nested_includes():
    r = healthy_zone(D)
    r.add(D, "TXT", "v=spf1 " + " ".join(f"include:s{i}.vendor.net" for i in range(6)) + " -all")
    for i in range(6):
        r.add(f"s{i}.vendor.net", "TXT", "v=spf1 a mx -all")
    a = await run(r)
    f = by_rule(a, "spf_too_many_lookups")
    assert f and f[0]["data"]["lookups"] == 18


@pytest.mark.asyncio
async def test_dmarc_policies():
    r = healthy_zone(D).add(f"_dmarc.{D}", "TXT", "v=DMARC1; p=none")
    a = await run(r)
    assert {"dmarc_none", "dmarc_no_reports"} <= rules(a)
    r = healthy_zone(D).add(f"_dmarc.{D}", "TXT", "v=DMARC1; p=quarantine; pct=25; rua=mailto:a@b.c")
    a = await run(r)
    assert "dmarc_partial" in rules(a) and "dmarc_none" not in rules(a)


@pytest.mark.asyncio
async def test_dkim_key_strength():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    def pub(bits):
        k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        der = k.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(der).decode()

    r = healthy_zone(D).add(f"google._domainkey.{D}", "TXT", f"v=DKIM1; k=rsa; p={pub(1024)}")
    a = await run(r)
    assert "dkim_weak_key" in rules(a)
    r = healthy_zone(D).add(f"google._domainkey.{D}", "TXT", f"v=DKIM1; k=rsa; p={pub(2048)}")
    a = await run(r)
    assert "dkim_weak_key" not in rules(a) and a.stats["email"]["dkim"] is True


@pytest.mark.asyncio
async def test_dangling_cname_to_takeover_prone_service_is_possible_not_confirmed():
    r = healthy_zone(D)
    r.add(f"old.{D}", "CNAME", "acme-old.herokuapp.com")
    # herokuapp target is absent from the fake zone -> NXDOMAIN
    ct = FakeCT([cert([D, f"www.{D}", f"old.{D}"])])
    a = await run(r, ct)
    f = by_rule(a, "dangling_cname_takeover")
    assert len(f) == 1
    assert f[0]["confidence"] == "possible"
    assert f[0]["host"] == f"old.{D}"
    assert f[0]["data"]["service"] == "Heroku"
    assert f[0]["severity"] == "high"
    # the engine only ever asked DNS questions: no A/HTTP towards the heroku host beyond a lookup
    assert all(t in {"NS", "A", "AAAA", "MX", "TXT", "CAA", "DS", "CNAME"} for _, t in r.calls)


@pytest.mark.asyncio
async def test_dangling_cname_generic_and_expired_domain():
    r = healthy_zone(D)
    r.add(f"a.{D}", "CNAME", "gone.some-vendor-site.com")
    r.add(f"b.{D}", "CNAME", "x.alive-vendor.com")
    r.add("x.alive-vendor.com", "A", "203.0.113.9")
    r.add("alive-vendor.com", "NS", "ns.alive.net")
    r.add(f"c.{D}", "CNAME", "x.nxtld-vendor.com")  # registrable domain has no NS: expired
    r.add("some-vendor-site.com", "NS", "ns.vendor.net")
    ct = FakeCT([cert([D, f"a.{D}", f"b.{D}", f"c.{D}"])])
    a = await run(r, ct)
    got = {f["host"]: f["rule"] for f in a.findings if f["category"] == "dangling_dns"}
    assert got[f"a.{D}"] == "dangling_cname"
    assert got[f"c.{D}"] == "dangling_cname_expired_domain"
    assert f"b.{D}" not in got


@pytest.mark.asyncio
async def test_dangling_nameserver_and_dead_mx():
    r = healthy_zone(D)
    r.add(D, "NS", "ns1.dnsprovider.net", "ns.gone-provider.com")
    r.add(D, "MX", "10 mail.gone-mail.com")
    a = await run(r)
    assert by_rule(a, "dangling_ns")[0]["host"] == "ns.gone-provider.com"
    assert "mx_unresolvable" in rules(a)


@pytest.mark.asyncio
async def test_certificate_expiry_wildcards_and_weak_keys():
    certs = [
        # expiring in 2 days for a live host, no replacement logged
        cert([f"www.{D}"], serial="aa", days_left=2, age_days=88),
        # a healthy apex cert
        cert([D], serial="bb", days_left=60),
        # an old cert that was renewed: must NOT alert
        cert([f"app.{D}"], serial="old", days_left=1, age_days=89),
        cert([f"app.{D}"], serial="new", days_left=80, age_days=10),
        # weak key / sha1 (only when CT supplies it)
        cert([f"legacy.{D}"], serial="weak", key_type="RSA", key_bits=1024, sig_alg="sha1WithRSAEncryption"),
    ] + [cert([f"*.int.{D}"], serial=f"w{i}", issuer=f"CA{i}") for i in range(4)]
    r = healthy_zone(D)
    for h in ("app", "legacy"):
        r.add(f"{h}.{D}", "A", "93.184.216.34")
    a = await run(r, FakeCT(certs))
    exp = by_rule(a, "cert_expiring")
    assert len(exp) == 1 and exp[0]["severity"] == "high" and exp[0]["data"]["days_left"] == 2
    assert "cert_expired" not in rules(a)
    assert by_rule(a, "cert_weak_crypto")[0]["severity"] == "high"
    assert by_rule(a, "wildcard_sprawl") and by_rule(a, "issuer_sprawl")


@pytest.mark.asyncio
async def test_expired_cert_on_live_host():
    r = healthy_zone(D)
    a = await run(r, FakeCT([cert([D, f"www.{D}"], days_left=-3, age_days=93)]))
    assert by_rule(a, "cert_expired")


@pytest.mark.asyncio
async def test_ct_outage_degrades_without_penalty():
    a = await run(healthy_zone(D), FakeCT(fail=True))
    assert a.stats["ct_available"] is False
    assert a.grade == "A"
    assert [c for c in a.checks if c["key"] == "certificates"][0]["status"] == "unknown"


@pytest.mark.asyncio
async def test_host_budget_is_enforced():
    s = GrowthSettings(max_hosts=5)
    names = [f"h{i}.{D}" for i in range(40)]
    r = healthy_zone(D)
    a = await engine.assess(D, resolver=r, ct=FakeCT([cert([D] + names)]), now=NOW, settings=s)
    assert a.stats["subdomains_ct"] == 40 and a.stats["subdomains_checked"] == 5


@pytest.mark.asyncio
async def test_sensitive_and_private_names():
    r = healthy_zone(D)
    r.add(f"vpn.{D}", "A", "93.184.216.40")
    r.add(f"intra.{D}", "A", "10.1.2.3")
    a = await run(r, FakeCT([cert([D, f"vpn.{D}", f"intra.{D}"])]))
    assert by_rule(a, "sensitive_hostnames")[0]["data"]["count"] == 1
    assert by_rule(a, "private_ip_in_public_dns")


def test_grade_boundaries_and_caps():
    def f(sev, rule="r"):
        return {"severity": sev, "rule": rule, "title": f"t-{rule}"}

    assert engine.grade_findings([])[1] == "A"
    s, g, _ = engine.grade_findings([f("high", "a")])
    assert (s, g) == (88, "B")  # a high can never leave an A
    _, g, _ = engine.grade_findings([f("high", "a"), f("high", "b")])
    assert g == "C"
    _, g, _ = engine.grade_findings([f("high", "a"), f("high", "b"), f("high", "c")])
    assert g == "D"
    _, g, _ = engine.grade_findings([f("critical")])
    assert g == "D"
    s, g, _ = engine.grade_findings([f("critical", str(i)) for i in range(5)] + [f("high", "x")] * 3)
    assert g == "F" and s == 0
    # a repeating rule is capped, not multiplied
    s, _, _ = engine.grade_findings([f("low", "same")] * 50)
    assert s == 94


@pytest.mark.asyncio
async def test_public_projection_has_no_hosts_or_ips():
    r = healthy_zone(D)
    r.add(f"old.{D}", "CNAME", "acme-old.herokuapp.com")
    r.add(f"vpn.{D}", "A", "93.184.216.40")
    r.add(f"intra.{D}", "A", "10.9.9.9")
    a = await run(r, FakeCT([cert([D, f"old.{D}", f"vpn.{D}", f"intra.{D}"])]))
    pub = json.dumps(engine.public_summary(a))
    tz = json.dumps(engine.teaser(a, limit=10))
    for blob in (pub, tz):
        assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", blob)
        assert f"old.{D}" not in blob and f"vpn.{D}" not in blob and "herokuapp" not in blob
    t = engine.teaser(a, limit=1)
    assert len(t["shown"]) == 1 and t["hidden"] >= 1
    assert t["shown"][0]["host"].endswith(f"***.{D}") or "***" in t["shown"][0]["host"]
