"""P3.2: router/loop discovery hook (docs/ASSURANCE_P3.md 7.1), the two licensing features (7.3) and the isolation-sweep
registrations (5.8).

``attest.wiring`` includes whichever of ``routers/attestations.py`` and ``routers/public_attest.py`` exists and starts
``attest.loop`` when present, so ``main.py`` is edited once. A module that exists but is broken is an error, never
skipped: swallowing it would ship an application with silently missing routes.
"""
from __future__ import annotations

import asyncio
import importlib
import inspect
import sys
import textwrap
from pathlib import Path

import pytest
from fastapi import FastAPI

from app import licensing
from app.attest import wiring


@pytest.fixture
def fakeapp(tmp_path, monkeypatch):
    """A throw-away package standing in for ``app``: ``wiring`` is pointed at it so tests control which modules exist."""
    root = tmp_path / "fakeroot"
    pkg = root / "fakeapp"
    (pkg / "routers").mkdir(parents=True)
    (pkg / "attest").mkdir()
    for p in (pkg, pkg / "routers", pkg / "attest"):
        (p / "__init__.py").write_text("")
    monkeypatch.syspath_prepend(str(root))
    monkeypatch.setattr(wiring, "BASE_PACKAGE", "fakeapp")
    importlib.invalidate_caches()
    yield pkg
    for name in [n for n in sys.modules if n == "fakeapp" or n.startswith("fakeapp.")]:
        del sys.modules[name]


def _router_module(pkg: Path, name: str, route: str) -> None:
    (pkg / "routers" / f"{name}.py").write_text(textwrap.dedent(f"""
        from fastapi import APIRouter
        router = APIRouter()

        @router.get("{route}")
        async def handler():
            return {{"ok": True}}
    """))


def _paths(app: FastAPI) -> set[str]:
    # include_router is lazy in this FastAPI: the OpenAPI document is what lists every included route
    return set(app.openapi()["paths"])


# --------------------------------------------------------------------------- #
# include
# --------------------------------------------------------------------------- #

def test_include_is_a_noop_when_neither_router_exists(fakeapp):
    app = FastAPI()
    before = _paths(app)
    assert wiring.include(app) == []
    assert _paths(app) == before


def test_include_adds_only_the_router_modules_that_exist(fakeapp):
    _router_module(fakeapp, "attestations", "/v1/attestations/ping")
    app = FastAPI()
    assert wiring.include(app) == ["fakeapp.routers.attestations"]
    assert "/v1/attestations/ping" in _paths(app)
    _router_module(fakeapp, "public_attest", "/v1/public/attest/ping")
    importlib.invalidate_caches()
    app2 = FastAPI()
    assert wiring.include(app2) == ["fakeapp.routers.attestations", "fakeapp.routers.public_attest"]
    assert {"/v1/attestations/ping", "/v1/public/attest/ping"} <= _paths(app2)


def test_a_found_module_with_an_import_error_is_not_swallowed(fakeapp):
    (fakeapp / "routers" / "attestations.py").write_text("import a_module_that_does_not_exist_p32\n")
    with pytest.raises(ImportError, match="a_module_that_does_not_exist_p32"):
        wiring.include(FastAPI())


def test_a_found_module_with_a_syntax_error_is_not_swallowed(fakeapp):
    (fakeapp / "routers" / "public_attest.py").write_text("def broken(:\n")
    with pytest.raises(SyntaxError):
        wiring.include(FastAPI())


def test_a_found_module_without_a_router_is_an_error(fakeapp):
    (fakeapp / "routers" / "attestations.py").write_text("x = 1\n")
    with pytest.raises(wiring.WiringError, match="router"):
        wiring.include(FastAPI())


def test_a_module_that_fails_at_import_with_a_missing_dependency_of_its_own_is_not_mistaken_for_absent(fakeapp):
    """ModuleNotFoundError raised INSIDE a found module names another module: it is a bug, not absence."""
    (fakeapp / "routers" / "attestations.py").write_text("from fakeapp.attest import not_there_yet\n")
    with pytest.raises(ImportError):
        wiring.include(FastAPI())


def test_the_real_app_includes_through_the_hook_exactly_once(monkeypatch):
    from app import main as main_mod

    seen = []
    monkeypatch.setattr(main_mod.attest_wiring, "include", lambda app: seen.append(app) or [])
    app = main_mod.create_app()
    assert seen == [app]


def test_the_real_hook_targets_the_real_package_and_modules():
    assert wiring.BASE_PACKAGE == "app"
    assert wiring.ROUTER_MODULES == ("routers.attestations", "routers.public_attest")
    assert wiring.LOOP_MODULE == "attest.loop" and wiring.LOOP_ENTRY == "attest_loop"


def test_creating_the_real_app_still_works_and_adds_no_stray_attest_routes_before_the_routers_exist():
    from app.main import create_app

    app = create_app()
    attest_routes = [p for p in _paths(app) if "attest" in p]
    if not (Path(wiring.__file__).parents[1] / "routers" / "attestations.py").exists():
        assert attest_routes == [] or all(p.startswith("/v1/public/attest") for p in attest_routes)


# --------------------------------------------------------------------------- #
# start / stop
# --------------------------------------------------------------------------- #

class _State:
    pass


class _App:
    def __init__(self) -> None:
        self.state = _State()


def _loop_module(pkg: Path, body: str) -> None:
    (pkg / "attest" / "loop.py").write_text(textwrap.dedent(body))
    importlib.invalidate_caches()


async def test_start_is_a_noop_without_a_loop_module(fakeapp):
    app = _App()
    assert wiring.start(app) is None
    assert getattr(app.state, "attest_task", None) is None
    await wiring.stop(app)                                    # stop without start is fine


async def test_start_runs_the_loop_and_stop_cancels_it(fakeapp):
    _loop_module(fakeapp, """
        import asyncio
        STATE = {"started": 0, "cancelled": 0}

        async def attest_loop(app):
            STATE["started"] += 1
            try:
                while True:
                    await asyncio.sleep(3600)
            except asyncio.CancelledError:
                STATE["cancelled"] += 1
                raise
    """)
    app = _App()
    task = wiring.start(app)
    assert isinstance(task, asyncio.Task) and app.state.attest_task is task
    await asyncio.sleep(0.01)
    mod = sys.modules["fakeapp.attest.loop"]
    assert mod.STATE == {"started": 1, "cancelled": 0}
    assert wiring.start(app) is task                           # idempotent while running
    await wiring.stop(app)
    assert task.done() and mod.STATE["cancelled"] == 1 and mod.STATE["started"] == 1
    assert app.state.attest_task is None
    await wiring.stop(app)                                     # and stop twice is fine


async def test_stop_survives_a_loop_that_crashed(fakeapp):
    _loop_module(fakeapp, """
        async def attest_loop(app):
            raise RuntimeError("boom")
    """)
    app = _App()
    wiring.start(app)
    await asyncio.sleep(0.01)
    await wiring.stop(app)                                     # must not raise
    assert app.state.attest_task is None


async def test_start_does_not_swallow_a_broken_loop_module(fakeapp):
    _loop_module(fakeapp, "import a_module_that_does_not_exist_p32\n")
    with pytest.raises(ImportError):
        wiring.start(_App())


async def test_start_requires_the_entry_point_in_a_found_module(fakeapp):
    _loop_module(fakeapp, "x = 1\n")
    with pytest.raises(wiring.WiringError, match="attest_loop"):
        wiring.start(_App())


async def test_a_stopped_loop_can_be_started_again(fakeapp):
    _loop_module(fakeapp, """
        import asyncio
        async def attest_loop(app):
            await asyncio.sleep(3600)
    """)
    app = _App()
    first = wiring.start(app)
    await wiring.stop(app)
    second = wiring.start(app)
    assert second is not first and not second.done()
    await wiring.stop(app)


# --------------------------------------------------------------------------- #
# main.py calls the hook (include in create_app, start/stop in the lifespan)
# --------------------------------------------------------------------------- #

def test_the_lifespan_starts_the_hook_and_stops_it_in_finally():
    from app import main

    src = inspect.getsource(main.lifespan)
    assert "attest_wiring.start(app)" in src
    assert "attest_wiring.stop(app)" in src.split("finally:")[1]
    assert "attest_wiring.include(app)" in inspect.getsource(main.create_app)


async def test_the_lifespan_runs_start_then_stop_around_the_app(monkeypatch):
    from app import auth as auth_svc
    from app import fleet_monitor, main
    from app import sensors as sensors_svc
    from app.config import settings

    calls: list[str] = []

    class _Pool:
        async def close(self):
            calls.append("pool.close")

    class _Redis:
        async def aclose(self):
            calls.append("redis.close")

    async def _create_pool():
        return _Pool()

    async def _create_redis():
        return _Redis()

    async def _noop(*a, **k):
        return None

    async def _forever(*a, **k):
        await asyncio.sleep(3600)

    monkeypatch.setattr(main.ops_settings, "migrate_on_startup", False)
    monkeypatch.setattr(main, "create_pool", _create_pool)
    monkeypatch.setattr(main, "create_redis", _create_redis)
    monkeypatch.setattr(main, "warn_if_privileged", _noop)
    monkeypatch.setattr(main, "sink_from_settings", lambda: None)
    monkeypatch.setattr(auth_svc, "bootstrap_admin", _noop)
    monkeypatch.setattr(auth_svc, "harden_audit_table", _noop)
    monkeypatch.setattr(sensors_svc, "monitor_loop", _forever)
    monkeypatch.setattr(fleet_monitor, "fleet_agent_monitor_loop", _forever)
    monkeypatch.setattr(settings, "scheduler_enabled", False)
    monkeypatch.setattr(settings, "assurance_enabled", False)
    monkeypatch.setattr(main.growth_settings, "runner_enabled", False)
    monkeypatch.setattr(main.attest_wiring, "start", lambda app: calls.append("attest.start"))

    async def _stop(app):
        calls.append("attest.stop")

    monkeypatch.setattr(main.attest_wiring, "stop", _stop)
    app = FastAPI()
    async with main.lifespan(app):
        assert calls == ["attest.start"]
    assert calls.index("attest.stop") > calls.index("attest.start")
    assert calls.index("attest.stop") < calls.index("pool.close")      # stopped before the pool goes away


# --------------------------------------------------------------------------- #
# licensing (7.3)
# --------------------------------------------------------------------------- #

def test_two_enterprise_features_are_catalogued_with_the_contract_text():
    pub = licensing.FEATURES["attestations_public"]
    byok = licensing.FEATURES["attestation_byok"]
    assert (pub.min_edition, pub.description) == (
        "enterprise", "Public attestations: hosted bundle, DNS key binding, push targets")
    assert (byok.min_edition, byok.description) == (
        "enterprise", "Bring-your-own-key / KMS signing for attestations")


def test_team_keeps_private_attestation_through_assurance_and_not_the_public_features():
    team = licensing.edition_features("team")
    assert "assurance" in team
    assert not ({"attestations_public", "attestation_byok"} & team)
    assert {"attestations_public", "attestation_byok"} <= licensing.edition_features("enterprise")
    assert {"attestations_public", "attestation_byok"} <= licensing.edition_features("edge")
    assert not ({"attestations_public", "attestation_byok"} & licensing.edition_features("community"))


def test_the_existing_catalogue_is_unchanged_apart_from_the_two_new_lines():
    assert licensing.FEATURES["assurance"].min_edition == "team"
    assert {"sso_saml", "scim", "multi_tenant", "audit_anchoring", "air_gapped"} <= set(licensing.FEATURES)


def test_unknown_feature_names_still_raise_so_a_typo_cannot_silently_open_a_gate():
    with pytest.raises(ValueError):
        licensing.require_feature("attestation_public")      # singular typo


def test_the_new_features_can_be_required_by_name():
    licensing.require_feature("attestations_public")
    licensing.require_feature("attestation_byok")


# --------------------------------------------------------------------------- #
# isolation sweep registrations (5.8)
# --------------------------------------------------------------------------- #

def test_the_lookup_policy_and_the_global_unique_index_are_registered_for_the_sweeps():
    from tests.test_isolation_keys import GLOBAL_UNIQUE_OK
    from tests.test_isolation_sweep import EXTRA_POLICIES

    assert EXTRA_POLICIES[("attest_bundle_objects", "attest_public_lookup")] == "app.attest_lookup"
    assert "attest_bundle_objects" in GLOBAL_UNIQUE_OK
    assert "domain" in GLOBAL_UNIQUE_OK["attest_bundle_objects"].lower()
