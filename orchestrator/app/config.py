"""Settings loaded from environment via pydantic-settings."""
from __future__ import annotations

from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # DATABASE_URL is written in the sqlalchemy-style form in docker-compose
    # (`postgresql+asyncpg://...`). asyncpg needs a plain `postgresql://` DSN,
    # so db.py strips the `+asyncpg` segment at pool-creation time.
    database_url: str = "postgresql://asm:asm_dev@localhost:5432/asm"
    redis_url: str = "redis://localhost:6379/0"

    db_pool_min: int = 2
    db_pool_max: int = 10

    scope_cache_ttl_sec: int = 60
    dns_cache_ttl_sec: int = 60

    log_level: str = "INFO"
    # Legacy flag retained for back-compat. The real switch is `auth_mode`
    # below; `allow_no_auth` is no longer consulted by the auth layer.
    allow_no_auth: bool = True

    # --- Auth / governance (schema 011) ------------------------------------
    # AUTH_MODE governs how unauthenticated requests are treated:
    #   dev     -- inject a synthetic admin principal (loudly logged) so local
    #              dev, the existing tests, and the fleet of worker services
    #              keep working with no credentials. DEFAULT for now.
    #   enforce -- deny-closed; every request must present a valid API key or
    #              JWT. This is the DEFAULT: a deployment that forgets to set
    #              AUTH_MODE fails closed. Only docker-compose.override.yml
    #              (local dev, ports bound to 127.0.0.1) opts into `dev`.
    auth_mode: Literal["dev", "enforce"] = "enforce"

    # Browser origins allowed to call the API (comma-separated). Never "*".
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    # Only these peers may set X-Forwarded-For (comma-separated CIDRs). The
    # audit log records the socket peer otherwise, so a client can't forge
    # the IP an action is attributed to.
    trusted_proxy_cidrs: str = "127.0.0.1/32,::1/128"

    # Login throttling: max failed attempts per (username) and per (client
    # ip) inside the window before 429s.
    login_max_failures: int = 10
    login_window_sec: int = 300

    # A shared, per-service API key the worker fleet (passive/active/intel/...)
    # can send via `Authorization: Bearer <key>` or `X-API-Key`. When set it
    # resolves to a synthetic `service` principal with the `write` scope so
    # services can ingest without a per-service DB user. Unset by default.
    service_api_key: str | None = None

    # JWT signing. In enforce mode with >1 worker process set a stable secret
    # via env; otherwise a random per-process secret is generated (fine for
    # single-process dev + tests, where tokens simply don't survive a restart).
    jwt_secret: str | None = None
    jwt_algorithm: str = "HS256"
    jwt_ttl_sec: int = 3600  # short-lived access tokens (1h)

    # Bootstrap admin password. On startup, if the seeded `admin` user has no
    # pw_hash, it is set from this env var (or a random one is generated and
    # logged ONCE). Never ship a known credential.
    admin_bootstrap_password: str | None = None

    # --- Enterprise identity: SSO (OIDC/SAML) + SCIM (schema 020) ---------
    # Public base URL of THIS orchestrator as the browser / IdP reaches it.
    # Redirect URIs, the SAML ACS + entity id are derived from it -- never
    # from the request's Host header (host-header injection).
    sso_base_url: str = "http://localhost:8080"
    # Where the SPA lives; the callback redirects to <this>/sso/callback.
    sso_dashboard_url: str = "http://localhost:3000"
    sso_state_ttl_sec: int = 600       # start -> callback window
    sso_code_ttl_sec: int = 60         # one-time SPA exchange code lifetime
    sso_clock_skew_sec: int = 60       # leeway for exp/nbf/iat checks

    # Stream and queue names (kept in config so other services can share)
    events_stream: str = "stream:events"
    queue_passive: str = "queue:passive"
    queue_active: str = "queue:active"
    queue_correlate: str = "queue:correlate"

    # BFS graph caps (safety limits)
    graph_max_depth: int = 3
    graph_max_nodes: int = 500

    # Correlation service: attack-path (re)compute endpoint. The recompute
    # route prefers a synchronous call here and falls back to a Redis job.
    correlation_url: str = "http://correlation:8091"

    # Continuous-monitoring scheduler (Tier 2). The loop wakes every
    # `scheduler_interval_sec`; schedules without a cron (or when croniter is
    # not installed) fall back to `scheduler_default_minutes`.
    scheduler_enabled: bool = True
    # Provable containment (schema 039, app/assurance/). The loop builds the reach graph from
    # stored data and evaluates each tenant's enabled invariants. It only reads stored rows
    # and writes the graph, run ledger and findings: it never sends a packet.
    assurance_enabled: bool = True
    assurance_tick_s: int = 30             # how often the loop wakes
    assurance_rebuild_min: int = 10        # full rebuild of all builders, per tenant
    assurance_backstop_min: int = 15       # re-evaluate even if nothing changed
    assurance_edge_window_h: int = 24      # observed flow edges older than this are dropped
    assurance_external_max_age_h: int = 168  # external-scan observations older than this are ignored
    scheduler_interval_sec: int = 60
    scheduler_default_minutes: int = 60

    # Tier 3 proxy targets. The orchestrator only *reads/proxies* these; both
    # must degrade gracefully (never hard-fail) when the upstream is down.
    #   brain      -- LLM triage + NL-query ("Ask") service.
    #   graphsync  -- Neo4j-backed graph path/neighborhood service.
    brain_url: str = "http://brain:8095"
    graphsync_url: str = "http://graphsync:8096"

    # Tier 4 proxy targets. As with the Tier 3 targets, the orchestrator only
    # reads/proxies these and must degrade gracefully when the upstream is down.
    #   codeanalysis -- reachability + SAST (static) service.
    #   mlrisk       -- adaptive risk ranker + anomaly detector service.
    codeanalysis_url: str = "http://codeanalysis:8097"
    mlrisk_url: str = "http://mlrisk:8098"
    ontology_url: str = "http://ontology:8099"
    threatintel_url: str = "http://threatintel:8100"
    otdiscovery_url: str = "http://otdiscovery:8101"
    remediation_url: str = "http://remediation:8102"

    # --- Proof-of-control for scope (schema 021) ----------------------------
    # When true, a scope entry authorises nothing until its ownership is
    # proven (DNS TXT / HTTPS file for domains, a recorded attestation for IP
    # ranges). Default false so dev + existing tests keep working; the hardened
    # docker-compose.yml and the lite stack set it to true.
    require_scope_proof: bool = False
    # Re-check verified proofs this often; a proof that keeps failing for
    # longer than the grace period is expired (and stops authorising scans).
    scope_proof_reverify_hours: float = 24
    scope_proof_grace_hours: float = 72
    # Floor between two checks of the same entry (the check is an outbound
    # request to the target, so it must not be spammable).
    scope_proof_min_interval_sec: float = 5
    scope_proof_timeout_sec: float = 5
    scope_proof_user_agent: str = (
        "Paddock-Verifier/1.0 (+https://github.com/brandongraff-dev/paddock; scope ownership check)"
    )

    # Deployment shape: "full" (every service) or "lite" (single node: no
    # neo4j/graphsync/ML/LLM/compute services). Optional services that are not
    # part of the deployment are reported as "not enabled" rather than "down".
    deployment_mode: Literal["full", "lite"] = "full"
    # --- Enterprise trust: tenancy + keyed/anchored audit (schema 098/099) --
    # TENANCY_STRICT: code running with no tenant in context (no principal,
    # background job that forgot to pick a tenant) sees NO rows and can write
    # none, instead of falling back to the default tenant. Turn on for a
    # multi-tenant deployment; single-tenant installs leave it off.
    tenancy_strict: bool = False

    # HMAC key for the audit chain. Keep it OUTSIDE the database (env, a docker
    # secret file, or a KMS-decrypted file). Unset = legacy unkeyed sha256.
    audit_hmac_key: str | None = None
    audit_hmac_key_file: str | None = None
    # Retired keys still needed to verify older rows (comma/space separated).
    audit_hmac_previous_keys: str = ""

    # Fail-closed audit: a mutating request whose write-ahead audit record
    # cannot be persisted is refused with 503 before the handler runs.
    audit_fail_closed: bool = True

    # Anchoring of the chain head to an append-only sink. Comma-separated list
    # of: file, s3, webhook. Empty = no anchoring.
    audit_anchor_sinks: str = ""
    audit_anchor_interval_sec: int = 3600
    audit_anchor_file: str = "/var/lib/paddock/audit-anchors.jsonl"
    audit_anchor_s3_bucket: str | None = None
    audit_anchor_s3_prefix: str = "paddock/audit-anchors/"
    audit_anchor_s3_region: str | None = None
    audit_anchor_s3_endpoint_url: str | None = None
    audit_anchor_s3_retention_days: int = 400
    audit_anchor_s3_lock_mode: Literal["COMPLIANCE", "GOVERNANCE"] = "COMPLIANCE"
    audit_anchor_webhook_url: str | None = None
    audit_anchor_webhook_secret: str | None = None
    # Optional read-back endpoint (GET ?tenant_id=) returning the latest anchor
    # JSON, so verify() can compare against a webhook-only sink.
    audit_anchor_webhook_latest_url: str | None = None
    audit_verify_batch: int = 1000


settings = Settings()
