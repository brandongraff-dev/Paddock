# SPDX-License-Identifier: AGPL-3.0-or-later
"""Configuration: precedence, tighten-only, trusted user file (contract 3.6, D32; test_config_trust)."""
from __future__ import annotations

import os
import stat

import pytest

from paddock_cli.guard import config, errors, registry
from paddock_cli.guard.registry import Check, register
from support import gitenv


@pytest.fixture
def proj(tmp_path):
    root = tmp_path / "proj"
    (root / ".paddock").mkdir(parents=True)
    return root


def _project(proj, text):
    (proj / ".paddock" / "guard.toml").write_text(text)


def _user(tmp_path, monkeypatch, text, *, mode=0o600, env="PADDOCK_CONFIG_DIR", where=None):
    d = where or (tmp_path / "userconf")
    d.mkdir(parents=True, exist_ok=True)
    f = d / "guard.toml"
    f.write_text(text)
    f.chmod(mode)
    if env == "XDG_CONFIG_HOME":
        monkeypatch.delenv("PADDOCK_CONFIG_DIR", raising=False)
        base = d.parent / "xdg"
        (base / "paddock").mkdir(parents=True, exist_ok=True)
        (base / "paddock" / "guard.toml").write_text(text)
        (base / "paddock" / "guard.toml").chmod(mode)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(base))
    else:
        monkeypatch.setenv(env, str(d))
    return f


def _load(proj, **kw):
    return config.load_config(str(proj), **kw)


def _check(cid="PG-WEB-005", severity="medium"):
    return Check(id=cid, title="t", severity=severity, proposed_tier="high", scope="file", agent_prompt="p",
                 run=lambda c, f: [])


def test_defaults(proj):
    cfg = _load(proj)
    assert (cfg.tier, cfg.fail_on, cfg.offline, cfg.exclude) == ("high", "high", False, ())
    assert cfg.packages.enabled and cfg.packages.min_age_days == 7 and cfg.packages.request_budget == 400
    assert cfg.packages.first_run_ack is False and cfg.url.allow_loopback is False and cfg.url.allow_hosts == ()
    assert cfg.prompt.no_prompt is False and cfg.prompt.trusted_packs == ()
    assert cfg.ci.fail_on_new_suppression is True and cfg.ci.approved_suppressions == ()
    assert cfg.notices == [] and cfg.ignored_loosening == []


def test_precedence_defaults_user_project_cli(proj, tmp_path, monkeypatch):
    _user(tmp_path, monkeypatch, '[guard]\ntier = "medium"\nfail_on = "critical"\n')
    assert _load(proj).tier == "medium" and _load(proj).fail_on == "critical"
    _project(proj, '[guard]\ntier = "low"\nfail_on = "medium"\n')
    cfg = _load(proj)
    assert cfg.tier == "low" and cfg.fail_on == "medium"
    cfg = _load(proj, cli={"tier": "high", "fail_on": "low"})
    assert cfg.tier == "high" and cfg.fail_on == "low"


def test_unknown_keys_are_errors_naming_the_key(proj):
    for text, name in (('[guard]\ntiier = "high"\n', "tiier"), ('[nope]\nx = 1\n', "nope"),
                       ('[packages]\nenabeld = true\n', "enabeld"), ('[checks."PG-X-001"]\nenabeld = true\n', "enabeld"),
                       ('[url]\nallow_loopbak = true\n', "allow_loopbak")):
        _project(proj, text)
        with pytest.raises(errors.ConfigError) as ei:
            _load(proj)
        assert name in str(ei.value)


@pytest.mark.parametrize("text", [
    '[guard]\ntier = "ultra"\n', '[guard]\nfail_on = "urgent"\n', '[guard]\noffline = "yes"\n',
    '[guard]\nexclude = "x"\n', '[packages]\nmin_age_days = -1\n', '[packages]\nrequest_budget = "a"\n',
    '[checks."PG-X-001"]\nseverity = "urgent"\n', '[ci]\napproved_suppressions = "x"\n', "garbage [[[",
])
def test_invalid_values_are_config_errors(proj, text):
    _project(proj, text)
    with pytest.raises(errors.ConfigError):
        _load(proj)


def test_project_can_tighten(proj, registry_sandbox):
    register(_check())
    _project(proj, '[guard]\ntier = "low"\nfail_on = "medium"\nexclude = ["**/fixtures/**", "docs/**", "**/examples/**"]\n'
                   '[checks."PG-WEB-005"]\nenabled = true\nseverity = "critical"\n'
                   '[packages]\nenabled = true\nmin_age_days = 14\nrequest_budget = 500\n')
    cfg = _load(proj)
    assert cfg.tier == "low" and cfg.fail_on == "medium"
    assert cfg.exclude == ("**/fixtures/**", "docs/**", "**/examples/**")
    assert cfg.checks["PG-WEB-005"].severity == "critical" and cfg.checks["PG-WEB-005"].enabled is True
    assert cfg.packages.min_age_days == 14 and cfg.packages.request_budget == 500
    assert cfg.ignored_loosening == [] and cfg.notices == []


@pytest.mark.parametrize("text, key", [
    ('[checks."PG-WEB-005"]\nenabled = false\n', "checks.PG-WEB-005.enabled"),
    ('[checks."PG-WEB-005"]\nseverity = "low"\n', "checks.PG-WEB-005.severity"),
    ('[guard]\nexclude = ["**"]\n', "guard.exclude"),
    ('[guard]\nexclude = ["src/**"]\n', "guard.exclude"),
    ('[guard]\nexclude = ["**/*"]\n', "guard.exclude"),
    ('[guard]\noffline = true\n', "guard.offline"),
    ('[packages]\nenabled = false\n', "packages.enabled"),
    ('[packages]\nprivate = ["*"]\n', "packages.private"),
    ('[packages]\nallow = ["**"]\n', "packages.allow"),
    ('[packages]\nallow = ["npm:*"]\n', "packages.allow"),
    ('[packages]\nprivate = ["@*/*"]\n', "packages.private"),
    ('[packages]\nmin_age_days = 1\n', "packages.min_age_days"),
    ('[packages]\nrequest_budget = 5\n', "packages.request_budget"),
    ('[packages]\nfirst_run_ack = true\n', "packages.first_run_ack"),
    ('[url]\nallow_loopback = true\n', "url.allow_loopback"),
    ('[url]\nallow_hosts = ["example.com"]\n', "url.allow_hosts"),
    ('[url]\nallow_query = true\n', "url.allow_query"),
    ('[prompt]\ntrusted_packs = ["' + "a" * 64 + '"]\n', "prompt.trusted_packs"),
    ('[ci]\nfail_on_new_suppression = false\n', "ci.fail_on_new_suppression"),
    ('[ci]\napproved_suppressions = ["0123456789abcdef"]\n', "ci.approved_suppressions"),
])
def test_project_loosening_is_ignored_with_a_first_line_notice(proj, registry_sandbox, text, key):
    register(_check())
    _project(proj, text)
    cfg = _load(proj)
    assert any(key in item for item in cfg.ignored_loosening), cfg.ignored_loosening
    assert cfg.notices and "ignored" in cfg.notices[0].lower() and key.split(".")[0] in cfg.notices[0] + " ".join(cfg.ignored_loosening)
    # the defaults still stand
    assert cfg.offline is False and cfg.packages.enabled and cfg.url.allow_loopback is False
    assert cfg.exclude == () and "PG-WEB-005" not in {k for k, v in cfg.checks.items() if v.enabled is False}
    assert cfg.ci.fail_on_new_suppression is True and cfg.ci.approved_suppressions == ()
    assert cfg.packages.min_age_days == 7 and cfg.packages.first_run_ack is False
    ch = cfg.config_changes()
    assert any(key in item for item in ch["ignored_loosening"])


def test_project_allow_entries_are_not_trusted_but_kept_for_unknown_verdicts(proj):
    _project(proj, '[packages]\nallow = ["npm:@acme/*", "*"]\nprivate = ["@acme/*"]\n')
    cfg = _load(proj)
    assert cfg.packages.allow == () and cfg.packages.allow_project == ("npm:@acme/*",)
    assert cfg.packages.private == ("@acme/*",)
    assert any("packages.allow" in i for i in cfg.ignored_loosening)


def test_loosening_in_the_user_file_is_honoured(proj, tmp_path, monkeypatch, registry_sandbox):
    register(_check())
    _user(tmp_path, monkeypatch,
          '[guard]\noffline = true\nexclude = ["vendor-code/**"]\n[checks."PG-WEB-005"]\nenabled = false\nseverity = "low"\n'
          '[packages]\nenabled = false\nallow = ["npm:@acme/*"]\nmin_age_days = 1\nfirst_run_ack = true\n'
          '[url]\nallow_loopback = true\nallow_hosts = ["staging.example.com"]\nallow_query = true\n'
          '[prompt]\ntrusted_packs = ["' + "b" * 64 + '"]\n[ci]\nfail_on_new_suppression = false\napproved_suppressions = ["0123456789abcdef"]\n')
    cfg = _load(proj)
    assert cfg.user_config_trusted is True
    assert cfg.offline and cfg.exclude == ("vendor-code/**",) and not cfg.packages.enabled
    assert cfg.checks["PG-WEB-005"].enabled is False and cfg.checks["PG-WEB-005"].severity == "low"
    assert cfg.packages.allow == ("npm:@acme/*",) and cfg.packages.min_age_days == 1 and cfg.packages.first_run_ack
    assert cfg.url.allow_loopback and cfg.url.allow_hosts == ("staging.example.com",) and cfg.url.allow_query
    assert cfg.prompt.trusted_packs == ("b" * 64,)
    assert cfg.ci.fail_on_new_suppression is False and cfg.ci.approved_suppressions == ("0123456789abcdef",)
    assert cfg.ignored_loosening == [] and cfg.notices == []
    ch = cfg.config_changes()
    assert ch["disabled_checks"] == ["PG-WEB-005"] and ch["excluded"] == ["vendor-code/**"]
    assert ch["severity_overrides"] == ["PG-WEB-005=low"] and any("enabled=false" in p for p in ch["packages"])


def test_project_allow_loopback_is_ignored_with_a_warning(proj):
    _project(proj, "[url]\nallow_loopback = true\n")
    cfg = _load(proj)
    assert cfg.url.allow_loopback is False
    assert cfg.notices and "url.allow_loopback" in " ".join(cfg.notices + cfg.ignored_loosening)


@pytest.mark.parametrize("how", ["inside_project_env", "symlink", "world_writable", "group_writable", "xdg_inside_project"])
def test_user_config_is_not_trusted_when(how, proj, tmp_path, monkeypatch):
    text = "[url]\nallow_loopback = true\n[guard]\nfail_on = \"critical\"\n[checks.\"PG-X-001\"]\nenabled = false\n"
    if how == "inside_project_env":
        d = proj / "conf"
        _user(tmp_path, monkeypatch, text, where=d)
    elif how == "xdg_inside_project":
        d = proj / "xdgroot"
        d.mkdir()
        (d / "paddock").mkdir()
        (d / "paddock" / "guard.toml").write_text(text)
        (d / "paddock" / "guard.toml").chmod(0o600)
        monkeypatch.delenv("PADDOCK_CONFIG_DIR", raising=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(d))
    elif how == "symlink":
        real = tmp_path / "real.toml"
        real.write_text(text)
        real.chmod(0o600)
        d = tmp_path / "userconf"
        d.mkdir()
        os.symlink(real, d / "guard.toml")
        monkeypatch.setenv("PADDOCK_CONFIG_DIR", str(d))
    elif how == "world_writable":
        _user(tmp_path, monkeypatch, text, mode=0o666)
    else:
        _user(tmp_path, monkeypatch, text, mode=0o660)
    cfg = _load(proj)
    assert cfg.user_config_trusted is False
    assert cfg.url.allow_loopback is False
    assert cfg.notices, "a visible warning is required"
    # untrusted user config is treated as project-level: tightening survives, loosening does not
    assert cfg.fail_on in ("high", "critical") and not cfg.checks.get("PG-X-001", config.CheckOverride()).enabled is False


def test_user_config_owned_by_another_user_is_not_trusted(proj, tmp_path, monkeypatch):
    _user(tmp_path, monkeypatch, "[url]\nallow_loopback = true\n")
    monkeypatch.setattr(config.os, "geteuid", lambda: os.stat(tmp_path / "userconf" / "guard.toml").st_uid + 1)
    cfg = _load(proj)
    assert cfg.user_config_trusted is False and cfg.url.allow_loopback is False


def test_trusted_user_config_resolves_outside_project_with_xdg(proj, tmp_path, monkeypatch):
    _user(tmp_path, monkeypatch, "[url]\nallow_loopback = true\n", env="XDG_CONFIG_HOME")
    cfg = _load(proj)
    assert cfg.user_config_trusted and cfg.url.allow_loopback


def test_absent_user_config_is_fine(proj):
    cfg = _load(proj)
    assert cfg.user_config_path is None and cfg.user_config_trusted is False and cfg.notices == []


def test_project_config_is_never_loaded_from_an_ancestor(tmp_path):
    parent = tmp_path / "parent"
    (parent / ".paddock").mkdir(parents=True)
    (parent / ".paddock" / "guard.toml").write_text('[guard]\ntier = "low"\n')
    child = parent / "child"
    child.mkdir()
    assert _load(child).tier == "high"


def test_symlinked_project_config_is_not_read(tmp_path):
    root = tmp_path / "p"
    (root / ".paddock").mkdir(parents=True)
    outside = tmp_path / "o.toml"
    outside.write_text('[guard]\ntier = "low"\n')
    os.symlink(outside, root / ".paddock" / "guard.toml")
    cfg = _load(root)
    assert cfg.tier == "high" and cfg.notices


def test_config_ref_reads_the_project_file_from_git_and_honours_ci_keys(repo):
    (repo / ".paddock").mkdir()
    (repo / ".paddock" / "guard.toml").write_text(
        '[guard]\ntier = "medium"\n[ci]\nfail_on_new_suppression = false\napproved_suppressions = ["0123456789abcdef"]\n')
    sha = gitenv.commit_all(repo)
    # a pull request edits the working tree copy; the base ref stays in force
    (repo / ".paddock" / "guard.toml").write_text('[guard]\ntier = "low"\n')
    cfg = config.load_config(str(repo), config_ref=sha)
    assert cfg.tier == "medium" and cfg.project_config_ref == sha
    assert cfg.ci.fail_on_new_suppression is False and cfg.ci.approved_suppressions == ("0123456789abcdef",)
    # the same keys read from the working tree are ignored
    (repo / ".paddock" / "guard.toml").write_text('[ci]\nfail_on_new_suppression = false\n')
    cfg = config.load_config(str(repo))
    assert cfg.ci.fail_on_new_suppression is True and cfg.ignored_loosening


def test_config_ref_rejects_option_like_refs(repo):
    (repo / "a").write_text("1")
    gitenv.commit_all(repo)
    with pytest.raises(errors.ConfigError):
        config.load_config(str(repo), config_ref="--output=/tmp/x")


def test_config_ref_without_a_file_in_that_ref_is_just_defaults(repo):
    (repo / "a").write_text("1")
    sha = gitenv.commit_all(repo)
    (repo / ".paddock").mkdir()
    (repo / ".paddock" / "guard.toml").write_text('[guard]\ntier = "low"\n')
    assert config.load_config(str(repo), config_ref=sha).tier == "high"


def test_hook_mode_falls_back_to_defaults_and_reports_the_error_first(proj, tmp_path, monkeypatch):
    _user(tmp_path, monkeypatch, '[guard]\nfail_on = "critical"\n')
    _project(proj, "this is [[[ not toml")
    with pytest.raises(errors.ConfigError):
        _load(proj)
    cfg = _load(proj, hook_mode=True)
    assert cfg.tier == "high" and cfg.fail_on == "high"
    assert cfg.notices and "config" in cfg.notices[0].lower() and "defaults" in cfg.notices[0].lower()


def test_hostile_toml_is_bounded(proj):
    _project(proj, "x = " + "[" * 100000 + "]" * 100000 + "\n")
    with pytest.raises(errors.ConfigError):
        _load(proj)
    _project(proj, "# " + "x" * 200000 + "\n")
    with pytest.raises(errors.ConfigError):
        _load(proj)


def test_environment_switches(proj, monkeypatch):
    monkeypatch.setenv("PADDOCK_GUARD_OFFLINE", "1")
    monkeypatch.setenv("PADDOCK_NO_PROMPT", "1")
    cfg = _load(proj)
    assert cfg.offline is True and cfg.prompt.no_prompt is True


def test_prompt_no_prompt_is_honoured_from_the_project(proj):
    _project(proj, "[prompt]\nno_prompt = true\n")
    assert _load(proj).prompt.no_prompt is True


def test_severity_override_of_an_unregistered_check_is_not_honoured_from_project(proj, registry_sandbox):
    _project(proj, '[checks."PG-ZZZ-999"]\nseverity = "critical"\n')
    cfg = _load(proj)
    assert "PG-ZZZ-999" not in cfg.checks or cfg.checks["PG-ZZZ-999"].severity is None


def test_hook_fail_on_is_a_tighten_only_key(proj):
    assert _load(proj).hook_fail_on == "high"
    _project(proj, '[guard]\nhook_fail_on = "medium"\n')
    assert _load(proj).hook_fail_on == "medium"
    _project(proj, '[guard]\nhook_fail_on = "critical"\n')
    cfg = _load(proj)
    assert cfg.hook_fail_on == "high" and any("hook_fail_on" in i for i in cfg.ignored_loosening)


def test_notices_are_clean_ascii(proj):
    _project(proj, '[guard]\nexclude = ["**\\u202e"]\n')
    cfg = _load(proj)
    assert all(n.isascii() for n in cfg.notices + cfg.ignored_loosening)


def test_user_config_mode_bits_helper_matches_spec():
    assert config.mode_is_private(0o600) and config.mode_is_private(0o644)
    assert not config.mode_is_private(0o666) and not config.mode_is_private(0o620) and not config.mode_is_private(0o664)
    assert stat.S_IMODE(0o100600) == 0o600
