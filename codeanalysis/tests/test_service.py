from __future__ import annotations

import pytest

from app import config as config_module
from app.main import CodeAnalysisService, sanitize_files


def _svc():
    svc = CodeAnalysisService(config_module.load())
    svc._db_ok = False  # offline: no DB, no orchestrator
    return svc


def test_sanitize_files_prunes_binaries_and_oversize():
    files = {
        "a.py": "x = 1\n",
        "bin.dat": "ok\x00binary",
        "big.py": "#" * (3 * 1024 * 1024),
    }
    clean = sanitize_files(files)
    assert "a.py" in clean
    assert "bin.dat" not in clean
    assert "big.py" not in clean


@pytest.mark.asyncio
async def test_run_sast_offline_counts_hits():
    svc = _svc()
    files = {"v.py": "import os\ndef h(request):\n    os.system(request.args.get('c'))\n"}
    res = await svc.run_sast("demo", files, None)
    assert res["engine"] == "taint_fallback"
    assert res["hits"] >= 1
    assert res["by_class"].get("command_injection", 0) >= 1
    # no DB and no orchestrator -> nothing persisted/posted, but no crash
    assert res["code_findings_written"] == 0
    assert res["findings_posted"] == 0


@pytest.mark.asyncio
async def test_run_reachability_offline_notes_no_db():
    svc = _svc()
    res = await svc.run_reachability("demo", {"a.py": "import requests\n"})
    assert "note" in res
    assert res["breakdown"]["reachable"] == 0


@pytest.mark.asyncio
async def test_run_analyze_combines_both():
    svc = _svc()
    files = {
        "app.py": (
            "import requests\n"
            "def h(request):\n"
            "    return requests.get(request.args.get('u'))\n"
        )
    }
    out = await svc.run_analyze("demo", files, None)
    assert "reachability" in out and "sast" in out
    assert out["sast"]["hits"] >= 1  # ssrf
    assert out["files"] == 1
