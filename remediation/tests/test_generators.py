"""Deterministic diff generator tests (THREAT-MODEL LAYER 2)."""
from __future__ import annotations

import json

import pytest

from app import gate
from app import generators as gen


def test_dependency_bump_requirements():
    gd = gen.generate_dependency_bump({
        "ecosystem": "PyPI", "package": "flask",
        "current_version": "1.0.0", "fixed_version": "1.1.4",
        "osv_id": "GHSA-1",
    })
    assert gd.change_class == "dependency_bump"
    assert gd.path == "requirements.txt"
    assert "-flask==1.0.0" in gd.unified
    assert "+flask==1.1.4" in gd.unified
    assert gate.check(gd.unified, "dependency_bump", gd.spec).ok


def test_dependency_bump_requirements_with_base():
    base = "django==3.2.0\nflask==1.0.0\nrequests==2.25.0\n"
    gd = gen.generate_dependency_bump({
        "ecosystem": "PyPI", "package": "flask",
        "current_version": "1.0.0", "fixed_version": "1.1.4",
        "base_content": base,
    })
    # only the flask line changes; django/requests appear as unchanged context
    assert "-flask==1.0.0" in gd.unified
    assert "+flask==1.1.4" in gd.unified
    assert "+django" not in gd.unified and "-django" not in gd.unified
    assert "+requests" not in gd.unified and "-requests" not in gd.unified
    res = gate.check(gd.unified, "dependency_bump", gd.spec)
    assert res.ok, res.reasons


def test_dependency_bump_npm_lock():
    gd = gen.generate_dependency_bump({
        "ecosystem": "npm", "package": "minimist",
        "current_version": "1.2.0", "fixed_version": "1.2.6",
        "osv_id": "GHSA-2",
    })
    assert gd.path == "package-lock.json"
    # the added line sets the fixed version; the removed line had the old one.
    assert '"version": "1.2.6"' in gd.unified
    assert "-" in gd.unified and '"version": "1.2.0"' in gd.unified
    assert gate.check(gd.unified, "dependency_bump", gd.spec).ok


def test_dependency_bump_refuses_missing_fixed_version():
    with pytest.raises(gen.GeneratorError):
        gen.generate_dependency_bump({
            "ecosystem": "PyPI", "package": "flask",
            "current_version": "1.0.0", "fixed_version": "",
        })


def test_dependency_bump_refuses_unsafe_package_name():
    with pytest.raises(gen.GeneratorError):
        gen.generate_dependency_bump({
            "ecosystem": "PyPI", "package": "flask; rm -rf /",
            "current_version": "1.0.0", "fixed_version": "1.1.4",
        })


def test_security_header_generator():
    for header in gen.SECURITY_HEADER_TEMPLATES:
        gd = gen.generate_security_header({"header": header})
        assert gd.change_class == "security_header"
        res = gate.check(gd.unified, "security_header", gd.spec)
        assert res.ok, (header, res.reasons)


def test_security_header_unknown_refused():
    with pytest.raises(gen.GeneratorError):
        gen.generate_security_header({"header": "x-make-me-admin"})


def test_tls_fix_generator():
    gd = gen.generate_tls_fix({})
    assert gd.change_class == "config_fix"
    assert "TLSv1.2 TLSv1.3" in gd.unified
    assert "-    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;" in gd.unified
    assert gate.check(gd.unified, "config_fix", gd.spec).ok


def test_tls_fix_with_base():
    base = "server {\n    ssl_protocols TLSv1 TLSv1.1;\n}\n"
    gd = gen.generate_tls_fix({"base_content": base})
    assert "TLSv1.2 TLSv1.3" in gd.unified
    assert gate.check(gd.unified, "config_fix", gd.spec).ok


def test_dotfile_block_generator():
    gd = gen.generate_dotfile_block({})
    assert gd.change_class == "dotfile_block"
    assert "deny all" in gd.unified
    assert gate.check(gd.unified, "dotfile_block", gd.spec).ok


def test_generators_are_deterministic():
    spec = {"ecosystem": "PyPI", "package": "flask",
            "current_version": "1.0.0", "fixed_version": "1.1.4"}
    a = gen.generate_dependency_bump(dict(spec)).unified
    b = gen.generate_dependency_bump(dict(spec)).unified
    assert a == b
