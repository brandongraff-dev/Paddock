# SPDX-License-Identifier: AGPL-3.0-or-later
"""Configuration (contract 3.6, D32).

Precedence, lowest first: built-in defaults, the user-level file, the project file
``.paddock/guard.toml`` (or that file read from a git ref), command-line flags. Precedence is not
trust: a cloned repository's file can only tighten. Anything that loosens is honoured only from
the user-level file (when it passes the trust test) or, for two ``[ci]`` keys, from a project file
read from the base ref; elsewhere it is ignored and reported (first line of output and
``config_changes.ignored_loosening``).
"""
from __future__ import annotations

import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from paddock_cli.guard import files, gitutil, model, textsafe
from paddock_cli.guard.errors import ConfigError, GuardError

MAX_CONFIG_BYTES = 100 * 1024
CONFIG_REL = ".paddock/guard.toml"
DEFAULT_MIN_AGE_DAYS = 7
DEFAULT_REQUEST_BUDGET = 400
_SAFE_EXCLUDE_SEGMENTS = ("fixtures", "examples", "docs")
_CHECK_KEY = re.compile(r"^[A-Za-z0-9_-]{1,60}$")


@dataclass
class CheckOverride:
    enabled: bool | None = None
    severity: str | None = None


@dataclass
class PackagesCfg:
    enabled: bool = True
    allow: tuple[str, ...] = ()           # trusted: user-level file only; may yield verdict "ok"
    allow_project: tuple[str, ...] = ()   # from the project file: verdict "unknown", never "ok"
    private: tuple[str, ...] = ()
    min_age_days: int = DEFAULT_MIN_AGE_DAYS
    request_budget: int = DEFAULT_REQUEST_BUDGET
    first_run_ack: bool = False


@dataclass
class UrlCfg:
    allow_loopback: bool = False
    allow_hosts: tuple[str, ...] = ()
    allow_query: bool = False


@dataclass
class PromptCfg:
    no_prompt: bool = False
    trusted_packs: tuple[str, ...] = ()


@dataclass
class CiCfg:
    fail_on_new_suppression: bool = True
    approved_suppressions: tuple[str, ...] = ()


@dataclass
class Config:
    tier: str = "high"
    fail_on: str = "high"
    hook_fail_on: str = "high"
    exclude: tuple[str, ...] = ()
    offline: bool = False
    checks: dict[str, CheckOverride] = field(default_factory=dict)
    packages: PackagesCfg = field(default_factory=PackagesCfg)
    url: UrlCfg = field(default_factory=UrlCfg)
    prompt: PromptCfg = field(default_factory=PromptCfg)
    ci: CiCfg = field(default_factory=CiCfg)
    notices: list[str] = field(default_factory=list)
    ignored_loosening: list[str] = field(default_factory=list)
    user_config_path: str | None = None
    user_config_trusted: bool = False
    project_config_present: bool = False
    project_config_ref: str | None = None
    sources: list[str] = field(default_factory=list)

    def check_enabled(self, check_id: str) -> bool:
        ov = self.checks.get(check_id)
        return not (ov is not None and ov.enabled is False)

    def severity_for(self, check_id: str, default: str) -> str:
        ov = self.checks.get(check_id)
        return ov.severity if ov is not None and ov.severity else default

    def config_changes(self) -> dict[str, list[str]]:
        """What this configuration changes against the defaults (3.4, 3.6)."""
        pk: list[str] = []
        if not self.packages.enabled:
            pk.append("enabled=false")
        if self.packages.allow:
            pk.append("allow=%d entries" % len(self.packages.allow))
        if self.packages.allow_project:
            pk.append("allow (project, unknown verdict)=%d entries" % len(self.packages.allow_project))
        if self.packages.private:
            pk.append("private=%d entries" % len(self.packages.private))
        if self.packages.min_age_days != DEFAULT_MIN_AGE_DAYS:
            pk.append("min_age_days=%d" % self.packages.min_age_days)
        if self.packages.request_budget != DEFAULT_REQUEST_BUDGET:
            pk.append("request_budget=%d" % self.packages.request_budget)
        return {
            "disabled_checks": sorted(k for k, v in self.checks.items() if v.enabled is False),
            "excluded": [textsafe.safe_text(g, cap=200) for g in self.exclude],
            "severity_overrides": sorted("%s=%s" % (k, v.severity) for k, v in self.checks.items() if v.severity),
            "packages": pk,
            "ignored_loosening": list(self.ignored_loosening),
        }


# ---- schema ----------------------------------------------------------------------------------
def _enum(values: tuple[str, ...]) -> Callable[[Any, str], str]:
    def check(v: Any, where: str) -> str:
        if not isinstance(v, str) or v not in values:
            raise ConfigError("%s must be one of: %s" % (where, ", ".join(values)))
        return v

    return check


def _bool(v: Any, where: str) -> bool:
    if not isinstance(v, bool):
        raise ConfigError("%s must be true or false" % where)
    return v


def _int(v: Any, where: str) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > 10_000_000:
        raise ConfigError("%s must be a non-negative integer" % where)
    return v


def _strlist(v: Any, where: str) -> tuple[str, ...]:
    if not isinstance(v, list) or len(v) > 500:
        raise ConfigError("%s must be a list of at most 500 strings" % where)
    out = []
    for item in v:
        if not isinstance(item, str) or not item or len(item) > 200 or "\x00" in item:
            raise ConfigError("%s has an invalid entry" % where)
        out.append(item)
    return tuple(out)


_SCHEMA: dict[str, dict[str, Callable[[Any, str], Any]]] = {
    "guard": {
        "tier": _enum(model.TIERS), "fail_on": _enum(model.SEVERITIES), "hook_fail_on": _enum(model.SEVERITIES),
        "exclude": _strlist, "offline": _bool,
    },
    "packages": {
        "enabled": _bool, "allow": _strlist, "private": _strlist, "min_age_days": _int,
        "request_budget": _int, "first_run_ack": _bool,
    },
    "url": {"allow_loopback": _bool, "allow_hosts": _strlist, "allow_query": _bool},
    "prompt": {"no_prompt": _bool, "trusted_packs": _strlist},
    "ci": {"fail_on_new_suppression": _bool, "approved_suppressions": _strlist},
}
_CHECK_SCHEMA = {"enabled": _bool, "severity": _enum(model.SEVERITIES)}


def _key_name(s: str) -> str:
    return textsafe.safe_text(s, cap=60)


def _validate(doc: dict[str, Any], label: str) -> dict[str, Any]:
    """Validate against the schema; an unknown key is an error naming it (typos must not silently
    disable a check)."""
    out: dict[str, Any] = {}
    for table, body in doc.items():
        if table == "checks":
            if not isinstance(body, dict):
                raise ConfigError("%s: [checks] must be a table" % label)
            checks: dict[str, dict[str, Any]] = {}
            for cid, ov in body.items():
                if not _CHECK_KEY.match(cid):
                    raise ConfigError("%s: invalid check id %s" % (label, _key_name(cid)))
                if not isinstance(ov, dict):
                    raise ConfigError("%s: [checks.%s] must be a table" % (label, _key_name(cid)))
                parsed: dict[str, Any] = {}
                for k, v in ov.items():
                    if k not in _CHECK_SCHEMA:
                        raise ConfigError("%s: unknown key %s in [checks.%s]" % (label, _key_name(k), _key_name(cid)))
                    parsed[k] = _CHECK_SCHEMA[k](v, "%s: checks.%s.%s" % (label, _key_name(cid), k))
                checks[cid] = parsed
            out["checks"] = checks
            continue
        spec = _SCHEMA.get(table)
        if spec is None:
            raise ConfigError("%s: unknown table [%s]" % (label, _key_name(table)))
        if not isinstance(body, dict):
            raise ConfigError("%s: [%s] must be a table" % (label, table))
        parsed = {}
        for k, v in body.items():
            if k not in spec:
                raise ConfigError("%s: unknown key %s in [%s]" % (label, _key_name(k), table))
            parsed[k] = spec[k](v, "%s: %s.%s" % (label, table, k))
        out[table] = parsed
    return out


def _parse_toml(text: str, label: str) -> dict[str, Any]:
    if len(text.encode("utf-8", "replace")) > MAX_CONFIG_BYTES:
        raise ConfigError("%s: larger than %d KB" % (label, MAX_CONFIG_BYTES // 1024))
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError("%s: invalid TOML (%s)" % (label, textsafe.safe_text(str(exc), cap=100))) from None
    except (RecursionError, MemoryError, OverflowError, ValueError):
        raise ConfigError("%s: invalid or too deeply nested TOML" % label) from None
    return _validate(doc, label)


# ---- trust ------------------------------------------------------------------------------------
def mode_is_private(mode: int) -> bool:
    """True when neither the group nor others can write (``mode & 0o022 == 0``)."""
    return (mode & 0o022) == 0


def _inside(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip(os.sep) + os.sep)


def user_config_location(env: Mapping[str, str]) -> tuple[str | None, str | None]:
    """(file path, the directory chosen through an environment variable or None)."""
    d = env.get("PADDOCK_CONFIG_DIR")
    if d:
        return os.path.join(d, "guard.toml"), d
    xdg = env.get("XDG_CONFIG_HOME")
    if xdg:
        return os.path.join(xdg, "paddock", "guard.toml"), os.path.join(xdg, "paddock")
    home = os.path.expanduser("~")
    return os.path.join(home, ".config", "paddock", "guard.toml"), None


def user_config_trust(path: str, env_dir: str | None, root_real: str) -> list[str]:
    """Reasons the user-level file is NOT trusted (empty list means trusted), per 3.6."""
    reasons: list[str] = []
    try:
        st = os.lstat(path)
    except OSError:
        return ["not readable"]
    if stat.S_ISLNK(st.st_mode):
        reasons.append("it is a symlink")
        return reasons
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        reasons.append("it is not owned by the current user")
    if not mode_is_private(st.st_mode):
        reasons.append("it is group- or world-writable")
    real = os.path.realpath(path)
    if _inside(real, root_real):
        reasons.append("it is inside the project")
    if env_dir is not None and _inside(os.path.realpath(env_dir), root_real):
        reasons.append("the environment variable that selects it points into the project")
    return reasons


# ---- applying layers ---------------------------------------------------------------------------
def _glob_is_safe_exclude(glob: str) -> bool:
    """A project ``exclude`` glob may cover only fixtures, examples or docs trees (D32)."""
    if not glob or glob.startswith("/") or "\\" in glob or ".." in glob.split("/"):
        return False
    segs = glob.split("/")
    for i, seg in enumerate(segs):
        if seg in _SAFE_EXCLUDE_SEGMENTS:
            if any(("*" in s and s != "**") or "?" in s or "[" in s for s in segs[:i]):
                return False
            tail = segs[i + 1:]
            return all(t == "**" or t == "*" or "*" not in t or t.startswith("*.") for t in tail) and (
                not tail or tail[-1] in ("**", "*") or "*" not in tail[-1] or tail[-1].startswith("*."))
    return False


_EVERYTHING = {"*", "**", "@*", "@*/*", "*/*", "@**"}


def _matches_everything(entry: str) -> bool:
    e = entry
    for prefix in ("npm:", "pypi:"):
        if e.startswith(prefix):
            e = e[len(prefix):]
            break
    return e in _EVERYTHING


class _Loader:
    def __init__(self, severity_of: Callable[[str], str | None]):
        self.cfg = Config()
        self.severity_of = severity_of

    def loosen(self, key: str, origin: str) -> None:
        self.cfg.ignored_loosening.append("%s (%s)" % (key, origin))

    # -- fully trusted layer ------------------------------------------------------------------
    def apply_trusted(self, doc: dict[str, Any]) -> None:
        c = self.cfg
        g = doc.get("guard", {})
        for k in ("tier", "fail_on", "hook_fail_on", "offline"):
            if k in g:
                setattr(c, k, g[k])
        if "exclude" in g:
            c.exclude = tuple(dict.fromkeys(c.exclude + g["exclude"]))
        for cid, ov in doc.get("checks", {}).items():
            cur = c.checks.setdefault(cid, CheckOverride())
            cur.enabled = ov.get("enabled", cur.enabled)
            cur.severity = ov.get("severity", cur.severity)
        p = doc.get("packages", {})
        for k in ("enabled", "min_age_days", "request_budget", "first_run_ack"):
            if k in p:
                setattr(c.packages, k, p[k])
        if "allow" in p:
            c.packages.allow = p["allow"]
        if "private" in p:
            c.packages.private = p["private"]
        u = doc.get("url", {})
        for k in ("allow_loopback", "allow_query"):
            if k in u:
                setattr(c.url, k, u[k])
        if "allow_hosts" in u:
            c.url.allow_hosts = u["allow_hosts"]
        pr = doc.get("prompt", {})
        if "no_prompt" in pr:
            c.prompt.no_prompt = pr["no_prompt"]
        if "trusted_packs" in pr:
            c.prompt.trusted_packs = tuple(h.lower() for h in pr["trusted_packs"])
        ci = doc.get("ci", {})
        if "fail_on_new_suppression" in ci:
            c.ci.fail_on_new_suppression = ci["fail_on_new_suppression"]
        if "approved_suppressions" in ci:
            c.ci.approved_suppressions = ci["approved_suppressions"]

    # -- tighten-only layer -----------------------------------------------------------------------
    def apply_restricted(self, doc: dict[str, Any], origin: str, *, from_base_ref: bool = False) -> None:
        c = self.cfg
        g = doc.get("guard", {})
        if "tier" in g:
            if model.tier_rank(g["tier"]) <= model.tier_rank(c.tier):
                c.tier = g["tier"]
            else:
                self.loosen("guard.tier", origin)
        for k in ("fail_on", "hook_fail_on"):
            if k in g:
                if model.severity_rank(g[k]) <= model.severity_rank(getattr(c, k)):
                    setattr(c, k, g[k])
                else:
                    self.loosen("guard.%s" % k, origin)
        if "offline" in g and g["offline"]:
            self.loosen("guard.offline", origin)
        if "exclude" in g:
            bad = [x for x in g["exclude"] if not _glob_is_safe_exclude(x)]
            good = [x for x in g["exclude"] if _glob_is_safe_exclude(x)]
            if bad:
                self.loosen("guard.exclude", origin)
            c.exclude = tuple(dict.fromkeys(c.exclude + tuple(good)))
        for cid, ov in doc.get("checks", {}).items():
            if "enabled" in ov:
                if ov["enabled"]:
                    c.checks.setdefault(cid, CheckOverride()).enabled = True
                else:
                    self.loosen("checks.%s.enabled" % _key_name(cid), origin)
            if "severity" in ov:
                base = self.severity_of(cid)
                cur = c.checks.get(cid)
                current = (cur.severity if cur and cur.severity else None) or base
                if current is not None and model.severity_rank(ov["severity"]) >= model.severity_rank(current):
                    c.checks.setdefault(cid, CheckOverride()).severity = ov["severity"]
                else:
                    self.loosen("checks.%s.severity" % _key_name(cid), origin)
        p = doc.get("packages", {})
        if p.get("enabled") is False:
            self.loosen("packages.enabled", origin)
        if "allow" in p:
            keep = tuple(e for e in p["allow"] if not _matches_everything(e))
            if len(keep) != len(p["allow"]):
                self.loosen("packages.allow", origin)
            c.packages.allow_project = tuple(dict.fromkeys(c.packages.allow_project + keep))
        if "private" in p:
            keep = tuple(e for e in p["private"] if not _matches_everything(e))
            if len(keep) != len(p["private"]):
                self.loosen("packages.private", origin)
            c.packages.private = tuple(dict.fromkeys(c.packages.private + keep))
        if "min_age_days" in p:
            if p["min_age_days"] >= c.packages.min_age_days:
                c.packages.min_age_days = p["min_age_days"]
            else:
                self.loosen("packages.min_age_days", origin)
        if "request_budget" in p:
            if p["request_budget"] >= c.packages.request_budget:
                c.packages.request_budget = p["request_budget"]
            else:
                self.loosen("packages.request_budget", origin)
        if p.get("first_run_ack"):
            self.loosen("packages.first_run_ack", origin)
        u = doc.get("url", {})
        for k, v in u.items():
            if v:
                self.loosen("url.%s" % k, origin)
        pr = doc.get("prompt", {})
        if "no_prompt" in pr:
            c.prompt.no_prompt = c.prompt.no_prompt or pr["no_prompt"]
        if pr.get("trusted_packs"):
            self.loosen("prompt.trusted_packs", origin)
        ci = doc.get("ci", {})
        if "fail_on_new_suppression" in ci:
            if ci["fail_on_new_suppression"] is False:
                if from_base_ref:
                    c.ci.fail_on_new_suppression = False
                else:
                    self.loosen("ci.fail_on_new_suppression", origin)
        if ci.get("approved_suppressions"):
            if from_base_ref:
                c.ci.approved_suppressions = tuple(dict.fromkeys(c.ci.approved_suppressions + ci["approved_suppressions"]))
            else:
                self.loosen("ci.approved_suppressions", origin)


def _default_severity_of(check_id: str) -> str | None:
    from paddock_cli.guard import registry

    return registry.get(check_id).severity if registry.has(check_id) else None


def _read_project_text(root_real: str, config_ref: str | None, cfg: Config) -> str | None:
    if config_ref is not None:
        sha = gitutil.resolve_ref(root_real, config_ref)
        cfg.project_config_ref = sha
        try:
            r = gitutil.run_git(root_real, ["show", "--end-of-options", "%s:%s" % (sha, CONFIG_REL)])
        except GuardError as exc:
            raise ConfigError("cannot read the config from the ref: %s" % exc) from None
        if r.returncode != 0:
            return None  # no file in that ref: defaults
        return r.stdout
    view, why = files.read_file(root_real, CONFIG_REL, limit=MAX_CONFIG_BYTES)
    if view is not None:
        return view.text
    if why == "missing":
        return None
    if why == "oversize":
        raise ConfigError("%s is larger than %d KB" % (CONFIG_REL, MAX_CONFIG_BYTES // 1024))
    cfg.notices.append("config: %s was not read (%s)" % (CONFIG_REL, why))
    return None


def load_config(root: str, *, cli: Mapping[str, Any] | None = None, config_ref: str | None = None,
                hook_mode: bool = False, env: Mapping[str, str] | None = None,
                severity_of: Callable[[str], str | None] | None = None) -> Config:
    """Load the effective configuration for ``root``.

    ``config_ref`` reads the project file from that git ref (validated and resolved to a 40-hex
    id); the working-tree file is then not read. In ``hook_mode`` a configuration error falls
    back to the built-in defaults and becomes the first notice, so a malformed file cannot
    disable the tool.
    """
    root_real = files.real_root(root)
    e = os.environ if env is None else env
    loader = _Loader(severity_of or _default_severity_of)
    try:
        cfg = _load(loader, root_real, cli, config_ref, e)
    except ConfigError as exc:
        if not hook_mode:
            raise
        cfg = Config()
        cfg.notices.append("config: %s; using built-in defaults" % textsafe.safe_text(str(exc), cap=160))
        _apply_cli(cfg, cli, e)
        return cfg
    return cfg


def _apply_cli(cfg: Config, cli: Mapping[str, Any] | None, env: Mapping[str, str]) -> None:
    if env.get("PADDOCK_GUARD_OFFLINE") == "1":
        cfg.offline = True
    if env.get("PADDOCK_NO_PROMPT") == "1":
        cfg.prompt.no_prompt = True
    if not cli:
        return
    for k in ("tier", "fail_on", "hook_fail_on"):
        if cli.get(k):
            setattr(cfg, k, cli[k])
    if cli.get("offline"):
        cfg.offline = True
    if cli.get("no_prompt"):
        cfg.prompt.no_prompt = True
    if cli.get("exclude"):
        cfg.exclude = tuple(dict.fromkeys(cfg.exclude + tuple(cli["exclude"])))


def _load(loader: _Loader, root_real: str, cli: Mapping[str, Any] | None, config_ref: str | None,
          env: Mapping[str, str]) -> Config:
    cfg = loader.cfg
    # user-level file
    path, env_dir = user_config_location(env)
    if path is not None and os.path.lexists(path):
        reasons = user_config_trust(path, env_dir, root_real)
        if "it is a symlink" in reasons:
            cfg.notices.append("config: user-level config ignored (it is a symlink)")
        else:
            text, why = files.read_abs_text(path, limit=MAX_CONFIG_BYTES)
            if text is None:
                if why == "oversize":
                    raise ConfigError("user-level config is larger than %d KB" % (MAX_CONFIG_BYTES // 1024))
                cfg.notices.append("config: user-level config was not read (%s)" % why)
            else:
                doc = _parse_toml(text, "user-level config")
                cfg.user_config_path = path
                cfg.sources.append("user")
                if reasons:
                    cfg.user_config_trusted = False
                    cfg.notices.append("config: user-level config is not trusted (%s); it is treated as project-level"
                                       % "; ".join(reasons))
                    loader.apply_restricted(doc, "user file, untrusted")
                else:
                    cfg.user_config_trusted = True
                    loader.apply_trusted(doc)
    # project file
    text = _read_project_text(root_real, config_ref, cfg)
    if text is not None:
        cfg.project_config_present = True
        cfg.sources.append("project-ref" if config_ref is not None else "project")
        doc = _parse_toml(text, "project config")
        loader.apply_restricted(doc, "project file" if config_ref is None else "project file at base ref",
                                from_base_ref=config_ref is not None)
    _apply_cli(cfg, cli, env)
    if cfg.ignored_loosening:
        keys = ", ".join(textsafe.safe_text(k, cap=70) for k in cfg.ignored_loosening[:4])
        more = "" if len(cfg.ignored_loosening) <= 4 else " and %d more" % (len(cfg.ignored_loosening) - 4)
        cfg.notices.insert(0, "config: ignored %d setting(s) that would loosen checks: %s%s"
                           % (len(cfg.ignored_loosening), keys, more))
    cfg.notices = [textsafe.safe_text(n, cap=300) for n in cfg.notices]
    cfg.ignored_loosening = [textsafe.safe_text(n, cap=120) for n in cfg.ignored_loosening]
    return cfg
