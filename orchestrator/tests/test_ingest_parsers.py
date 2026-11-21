"""Pure tests for the universal-ingest parsers (no DB)."""
from __future__ import annotations

import copy
import gzip
import json

import pytest

from app.ingest import Hints, IngestError, decode_body, detect_format, parse_payload
from app.ingest.common import host_asset, norm_severity, safe_path, strip_url_credentials
from app.ingest.tokens import build_token, new_secret, parse_token, verify

from . import ingest_samples as S


def parse(doc_or_text, hint=None, **hk):
    text = doc_or_text if isinstance(doc_or_text, str) else json.dumps(doc_or_text)
    return parse_payload(text, hint, Hints(**hk))


# --------------------------------------------------------------------------- #
# detection + good input
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("doc,fmt", [
    (S.SARIF, "sarif"), (S.TRIVY, "trivy"), (S.GRYPE, "grype"), (S.SEMGREP, "semgrep"), (S.ZAP, "zap"),
    (S.CYCLONEDX, "cyclonedx"), (S.SPDX, "spdx"), (S.OCSF[0], "ocsf"), (S.NUCLEI_LINES[0], "nuclei"),
])
def test_detect_format(doc, fmt):
    assert detect_format(doc) == fmt
    assert parse(doc).format == fmt


def test_sarif():
    r = parse(S.SARIF)
    assert [f.rule_id for f in r.findings] == ["sarif:py/sql-injection@app/db.py:42", "sarif:py/unused-import@app/util.py:1"]
    sql = r.findings[0]
    assert sql.severity == "high" and sql.cvss == 8.8 and sql.rule_source == "sast"
    assert sql.evidence["cwe"] == "CWE-89" and sql.evidence["start_line"] == 42
    assert sql.title == "SQL query built from user input"
    # repo derived from versionControlProvenance, credentials never kept
    assert (sql.asset_kind, sql.asset_value) == ("repository", "acme/web")
    assert r.findings[1].severity == "low"
    assert r.skipped == 2 and len(r.errors) == 1          # 1 suppressed, 1 without ruleId (error)


def test_sarif_project_hint_overrides():
    r = parse(S.SARIF, project="my-proj")
    assert {f.asset_value for f in r.findings} == {"my-proj"}


def test_trivy():
    r = parse(S.TRIVY)
    kinds = {f.rule_source for f in r.findings}
    assert kinds == {"sca", "policy", "secret_scan"}
    v = next(f for f in r.findings if f.rule_id.startswith("CVE-2024-0001"))
    assert v.rule_id == "CVE-2024-0001:openssl@3.0.11" and v.cvss == 7.5 and v.severity == "high"
    assert v.remediation == "Upgrade openssl to 3.0.13"
    assert (v.asset_kind, v.asset_value) == ("cloud_resource", "registry.example.com/acme/api:1.4.2")
    assert not any(f.rule_id.startswith("trivy:DS999") for f in r.findings)       # PASS skipped
    sec = next(f for f in r.findings if f.rule_source == "secret_scan")
    assert "AKIA" not in json.dumps(sec.__dict__) and "Match" not in json.dumps(sec.__dict__)
    assert len(r.components) == 2 and len(r.component_vulns) == 2
    assert len(r.errors) == 1


def test_grype():
    r = parse(S.GRYPE, project="svc")
    assert len(r.findings) == 2 and len(r.errors) == 1
    f = r.findings[0]
    assert f.rule_id == "CVE-2021-44228:log4j-core@2.14.1" and f.severity == "critical" and f.cvss == 10.0
    assert "GHSA-jfh8-c2jp-5v3q" not in f.evidence["cve_ids"] and f.evidence["cve_ids"] == ["CVE-2021-44228"]
    assert (f.asset_kind, f.asset_value) == ("repository", "svc")
    assert any(c["purl"] == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" for c in r.components)


def test_semgrep_and_path_traversal():
    r = parse(S.SEMGREP)
    assert len(r.findings) == 2 and len(r.errors) == 1
    f = r.findings[0]
    assert f.evidence["file"] == "etc/shadow"                      # '..' stripped, never absolute
    assert ".." not in f.rule_id and f.rule_id.endswith("@etc/shadow:10")
    assert f.evidence["cwe"] == "CWE-89" and f.severity == "high" and f.title == "Detected SQL string formatting."
    assert r.findings[1].severity == "low"
    assert "lines" not in json.dumps(f.evidence)                    # source snippets are not stored


def test_nuclei_jsonl_and_array():
    r = parse(S.NUCLEI)
    assert r.format == "nuclei" and len(r.findings) == 2 and len(r.errors) == 1
    a, b = r.findings
    assert a.severity == "critical" and a.cvss == 9.8 and a.evidence["cve_ids"] == ["CVE-2023-1234"]
    assert (a.asset_kind, a.asset_value) == ("endpoint", "https://app.example.com")
    assert "curl" not in json.dumps(a.evidence) and "SECRET" not in json.dumps(a.__dict__)
    assert (b.asset_kind, b.asset_value) == ("subdomain", "app.example.com")
    assert parse(S.NUCLEI_LINES, "nuclei").findings.__len__() == 2


def test_zap():
    r = parse(S.ZAP)
    assert len(r.findings) == 2 and len(r.errors) == 1
    f = r.findings[0]
    assert f.severity == "medium" and f.rule_id == "zap:10038" and f.evidence["cwe"] == "CWE-693"
    assert "<p>" not in f.description and f.description == "CSP is missing."
    assert f.evidence["instance_count"] == 2
    assert all("u:p@" not in i["uri"] for i in f.evidence["instances"])
    assert (f.asset_kind, f.asset_value) == ("endpoint", "https://shop.example.com")
    assert f.references == ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"]


def test_ocsf_array_and_lines():
    r = parse(S.OCSF)
    assert r.format == "ocsf" and len(r.findings) == 2
    assert r.skipped == 2 and len(r.errors) == 1                    # 3002 not a finding class; {"nope"} error
    a, b = r.findings
    assert a.rule_id == "CVE-2022-0778:openssl@1.1.1" and a.rule_source == "cve_match" and a.cvss == 7.5
    assert (a.asset_kind, a.asset_value) == ("subdomain", "db1.example.com")
    assert b.severity == "low" and b.asset_kind == "cloud_resource"
    lines = "\n".join(json.dumps(e) for e in S.OCSF)
    assert len(parse(lines).findings) == 2


def test_csv():
    r = parse(S.CSV)
    assert r.format == "csv" and len(r.findings) == 3 and len(r.errors) == 2
    a, b, c = r.findings
    assert a.rule_id == "CVE-2021-23017:nginx@1.18.0" and a.rule_source == "cve_match" and a.cvss == 8.1
    assert (b.asset_kind, b.asset_value) == ("ipv4", "10.1.2.3")
    assert (c.asset_kind, c.asset_value) == ("repository", "acme/web") and c.evidence["file"] == "config/app.py"
    assert c.rule_id.endswith("@config/app.py:12")


def test_csv_missing_required_column():
    with pytest.raises(IngestError, match="missing required column"):
        parse("asset,title\nh,t\n", "csv")


def test_sbom_formats():
    r = parse(S.CYCLONEDX)
    assert r.sbom and {c["name"] for c in r.sbom["components"]} == {"express", "qs"} and r.project_hint == "acme-web"
    assert len(r.sbom["vulns"]) == 1
    r2 = parse(S.SPDX)
    assert r2.format == "spdx" and [c["name"] for c in r2.sbom["components"]] == ["flask"]


def test_force_format_mismatch_and_unknown():
    with pytest.raises(IngestError, match="looks like sarif"):
        parse(S.SARIF, "trivy")
    with pytest.raises(IngestError, match="unknown format"):
        parse(S.SARIF, "nessus")
    with pytest.raises(IngestError, match="unrecognised JSON"):
        parse({"hello": "world"})


# --------------------------------------------------------------------------- #
# malformed / hostile
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("text", ["", "   \n", "{", "[1,2", "not json at all", "\x00\x01"])
def test_malformed_rejected(text):
    with pytest.raises(IngestError):
        parse(text)


def test_malformed_required_structure():
    with pytest.raises(IngestError):
        parse({"runs": "nope", "version": "2.1.0"}, "sarif")
    with pytest.raises(IngestError):
        parse({"SchemaVersion": 2})                               # trivy without Results
    with pytest.raises(IngestError):
        parse({"matches": "x", "source": {}})


def test_xml_rejected_without_parsing():
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
            '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol2;</lolz>')
    with pytest.raises(IngestError) as e:
        parse(bomb)
    assert e.value.status == 415 and "XML" in str(e.value)
    with pytest.raises(IngestError):
        parse("<OWASPZAPReport/>", "zap")


def test_json_bomb_deep_nesting():
    with pytest.raises(IngestError) as e:
        parse("[" * 200_000)
    assert e.value.status == 422
    with pytest.raises(IngestError):
        parse('{"a":' * 5000 + "1" + "}" * 5000)


def test_oversized_and_gzip_bomb():
    with pytest.raises(IngestError) as e:
        decode_body(b"x" * 2048, gzipped=False, max_bytes=1024)
    assert e.value.status == 413
    bomb = gzip.compress(b"0" * (50 * 1024 * 1024))                # ~50 KiB compressed, 50 MiB inflated
    assert len(bomb) < 100_000
    with pytest.raises(IngestError) as e:
        decode_body(bomb, gzipped=True, max_bytes=1024 * 1024)
    assert e.value.status == 413
    with pytest.raises(IngestError):
        decode_body(b"\x1f\x8bgarbage", gzipped=True, max_bytes=1024)
    ok = decode_body(gzip.compress(b'{"a": 1}'), gzipped=False, max_bytes=1024)       # magic-detected
    assert ok == '{"a": 1}'
    with pytest.raises(IngestError):
        decode_body(b"\xff\xfe\xfa", gzipped=False, max_bytes=1024)


def test_too_many_findings():
    doc = copy.deepcopy(S.SEMGREP)
    doc["results"] = [{"check_id": f"r{i}", "path": "a.py", "start": {"line": i}, "extra": {"severity": "ERROR"}}
                      for i in range(50)]
    with pytest.raises(IngestError) as e:
        parse(doc, max_findings=10)
    assert e.value.status == 413


def test_csv_hostile():
    with pytest.raises(IngestError, match="too many columns"):
        parse(",".join(f"c{i}" for i in range(500)) + "\n", "csv")
    big = 'asset,title,severity\nh.example.com,"' + "A" * 200_000 + '",low\n'
    r = parse(big)
    assert r.findings == [] and r.errors                           # field-size limit -> row error, no crash
    r = parse('asset,title,severity\nh.example.com,"=cmd|\' /C calc\'!A0",low\n')
    assert r.findings[0].title.startswith("=cmd")                    # stored as inert text


def test_hostile_strings_are_sanitised():
    doc = copy.deepcopy(S.SEMGREP)
    doc["results"][0]["extra"]["message"] = "bad\x00\x07\x1b[31m" + "A" * 50_000
    r = parse(doc)
    f = r.findings[0]
    assert "\x00" not in f.description and "\x07" not in f.title and len(f.description) <= 4000 and len(f.title) <= 300


def test_safe_path_and_hosts():
    assert safe_path("../../etc/passwd") == "etc/passwd"
    assert safe_path("file:///etc/passwd") == "etc/passwd"
    assert safe_path("C:\\Windows\\..\\system32\\x.dll") == "Windows/system32/x.dll"
    assert safe_path("a/./b//c\x00/../d") == "a/b/c/d"
    assert strip_url_credentials("https://u:p@Example.com:8443/x?y=1") == "https://example.com:8443/x"
    assert host_asset("https://u:p@h.example.com/a")[1] == "https://h.example.com/a"
    assert host_asset("[2001:db8::1]") == ("ipv6", "2001:db8::1")
    assert host_asset("nope nope") is None and host_asset("..") is None and host_asset("") is None
    assert norm_severity("Moderate") == "medium" and norm_severity(9.1) == "critical" and norm_severity("zzz") == "medium"


# --------------------------------------------------------------------------- #
# tokens
# --------------------------------------------------------------------------- #

def test_token_roundtrip_and_malformed():
    secret, prefix, digest = new_secret()
    tok = build_token("00000000-0000-0000-0000-000000000001", "11111111-1111-1111-1111-111111111111", secret)
    t, s, sec = parse_token(tok)
    assert t == "00000000-0000-0000-0000-000000000001" and s == "11111111-1111-1111-1111-111111111111" and sec == secret
    assert verify(sec, digest) and not verify(sec + "x", digest) and not verify(sec, "revoked")
    for bad in (None, "", "pdi_", "pdi_x_y_z", "pak_abc", tok[:-30], tok + "!", "pdi_" + "g" * 32 + "_" + "1" * 32 + "_" + secret):
        assert parse_token(bad) is None
