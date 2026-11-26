# Provable Containment, P2.1: the P2 follow-up

> Status: **design contract for P2.1, not yet built** (written 2026-11-26). Companion to
> [ASSURANCE_P2.md](ASSURANCE_P2.md) (agent v2, the `host_fw` builder, the field registry and its sections 11 and 13: the
> known gaps and the open owner decisions this phase closes), [ASSURANCE_P1.md](ASSURANCE_P1.md) (the reach graph; its
> section 12 holds `builders-7` and `runner-4`) and [PROVABLE_CONTAINMENT_MVP.md](PROVABLE_CONTAINMENT_MVP.md) sections
> 4 to 6 and 10. Where documents disagree, **this file wins for P2.1**. The four scouting designs this contract merges
> (and the probes, fixtures and prototypes behind them) are in the session scratchpad `.../scratchpad/p21/`; they may
> contradict the decisions below, which are final.
>
> **Product rules (unchanged, binding on every line below).** `HOLDS` means *no counterexample under this evidence*,
> never "the host is secure". `UNKNOWN` never becomes `HOLDS`. Violations win (a provable counterexample is reported
> even when other parts are unknown). A signed fact is not a true fact. Fail safe: when a decision is the code's to make
> and the safe direction is clear, the code takes it; unknown widens, never narrows.
>
> **Authority.** The owner delegated every design decision for P2.1 through P6 to the contract writers, so this file
> asks no questions: every open choice has a default and a reason in section 0. The owner's standing sign-off for UI
> work is already recorded (`CLAUDE.md`, commit `a50c444`; MVP section 12 item 6), so no step here waits for UI
> approval; P2.1 builds **no dashboard screens** (those are P6) and therefore touches no file under `dashboard/`.

## 0. Decisions

Each row is final. "Resolves" names the scout conflict or P2 open item it settles.

| # | Decision | Why | Resolves |
|---|---|---|---|
| D1 | **Scope and order.** P2.1 is six sections: (A) KEV invariant, (B) collectors, (C) packaging, (D) identity trust root, (E) cloud ENI coverage, (F) lifecycle residuals. Built in the nine two-package waves of section 7; no dashboard work; the library and every std invariant change ship behind the existing mechanisms (no new feature flag except `assurance_kev_enabled`). | The owner asked for one section at a time and for no UI gate. A wave never has more than two concurrent packages. | MVP 10, P2 O4 |
| D2 | **Migration numbers: `044_advisories.sql`, `045_agent_identity.sql`, `046_assurance_lifecycle.sql`.** `043` stays unused (a gap is tolerated: `035` is missing and `migrate.py` only warns on a gap). **One package (WP0) owns all three files and every shared-table test edit**, so no two packages ever claim a number or edit `test_isolation_sweep.py` together. | Scout A took 043 and scout C 044/045; the lead said 044+. Applied files are immutable, so numbers are fixed now. | scout clash |
| D3 | **Matching runs in the orchestrator builder `host_kev`, over a pure library module `paddock_assurance.vulnmatch`; feeds are ingested only by the `intel` service into global tables.** Intel never reads tenant data; the orchestrator never fetches vendor feeds. | The package list is tenant data under RLS; the verdict machinery (digests, signed/tier/conflict, tombstones) lives in builders; the library has the property-test culture and a CLI `kev explain`. Only intel has egress. | A |
| D4 | **The KEV invariant reads its own table `kev_entries`, never `cves.known_exploited`.** Sources: CISA JSON and the `cisagov/kev-data` mirror, **union** (an extra CVE can only add violations); an entry with no parseable `dateAdded` is rejected, never defaulted to now. | `mark_kev` is UPDATE-only on `cves` (pinned by `intel/tests/test_kev.py`), skips CVEs NVD has not ingested, never stores `dueDate`, and writes `COALESCE(dateAdded, ..., NOW())`, which would delay an exposure clock. | A, trap T1 |
| D5 | **The clock.** `clock_start = max(earliest unmet-fix date, KEV date_added)`; overdue iff `now - clock_start > N days` (strictly greater, second precision, no floor). Day-only dates are read as `00:00:00Z` of that day (the earliest instant). A date later than our own first sighting of the row is clamped to the first sighting (a feed cannot delay a clock). CISA `dueDate` is stored and shown, never the clock. | A CVE fixed two years ago and listed yesterday is not an instant violation; one fixed and listed long ago is. Early rounding can only make a violation appear up to 24 h early, never hide one. | A |
| D6 | **A fix with no dated advisory** (Debian point-release kernels, tracker-only fixes) is dated by our first sighting, which is an *upper bound*: it can prove a violation, never a pass. Inside the window the item is `undecided` (the leaf is UNKNOWN). | Dating it later than the truth would hide a violation. Measured: 3 bookworm and 2 trixie post-release KEV rows are undated, so UNKNOWN is rare. | A |
| D7 | **Store only advisory rows whose CVE is in `kev_entries`, guarded by `kev_ids_sha`.** A snapshot records the sha of the KEV id set it was filtered with; the matcher reads UNKNOWN `advisory_behind_kev` unless it equals the current set. Intel keeps the last raw artefact of each feed in a cache and re-filters on a KEV change; KEV and the advisory rows swap in **one transaction**. | Store-all is about 1.5 M rows (Ubuntu kernel flavours alone are 250 k per release) re-upserted every 3 h for rows no invariant reads; KEV-only is under 50 k. The guard removes the only soundness risk of filtering (a freshly listed CVE reading "patched"). | A |
| D8 | **The package list is persisted at ingest in a content-addressed per-tenant table** (`agent_manifests` plus `agent_manifest_refs`), after the server recomputes `sha256(canon(sorted rows))` and requires it to equal the signed `manifest.sha256`. The builder requires the newest verified posture's sha to equal the stored ref. The server echoes `known_manifest_sha` so an agent re-sends within one heartbeat instead of 24 h. | The compact `patch` fact drops the list; postings coalesce within 300 s, evict by byte cap and expire at 90 d; the list is sent only when it changes. The signed digest binds the list to the signature. | A, trap T2 |
| D9 | **Distros in P2.1:** Debian 12 and 13 (tracker + DSA/DLA), Ubuntu 22.04 and 24.04 (public CVE and USN OVAL), RHEL 8 and 9 (Red Hat OVAL v2), AlmaLinux 8 and 9 (errata). **Rocky is deferred** (its public errata path could not be verified; the bare API answered 405). Everything else (derivatives such as Mint/Pop/Raspbian, Amazon, Oracle, SUSE, Alpine, CentOS Stream, EOL releases, Ubuntu Pro/ESM, Debian ELTS, Rocky) reads UNKNOWN `distro_unsupported`, `release_eol` or `esm_only_fix`. | These have free, machine-readable, dated data. A derivative's package set differs from its parent's, so `ID_LIKE` never maps. | A |
| D10 | **Kernel CVEs use the running kernel only**, compared by its BINARY version against the alias-mapped source; kernel unmanaged or `livepatch: true` makes every kernel item UNKNOWN. | Old installed kernels are not exposed code; a fixed kernel installed but not booted is still exposure; Debian signed kernels carry a source version (`6.1.76+1`) that is not comparable with the tracker's `linux` fixed version; a livepatch can fix without a version change. | A, trap T3 |
| D11 | **Undecidable packages** (ESM-tagged version, modular rpm name, foreign-signature rpm, unparsable version, `undetermined` or `esm_only` advisory) make that `(cve, package)` UNKNOWN **only when the name is KEV-relevant for the scope**. A definite violation still wins. Per-package origin is proven only for rpm (`signature_keyid`); deb origin cannot be proven per package, so a HOLDS carries a note and the field `host.kev.third_party_sources` lets a stricter custom invariant require false. | Restricting to the 79 (Debian 12) or 588 (Alma 9) relevant names keeps exotic irrelevant packages from making every host UNKNOWN, while nothing that could hide a KEV exposure becomes a pass. | A, trap T4 |
| D12 | **Field shape.** `host.kev.exploited_unpatched(N)` is a **bool with an int parameter** (0 to 3650) whose accessor does interval logic: `Known(True)` when a lower bound proves a violation, `Known(False)` only when the upper bound excludes one, else `Unknown`. `Known` gains an optional `until` and the verdict's `valid_until` is clamped to it. | Kleene correctness through `not`/`any`/`all` without a new type; a count field would force "violation hidden by an unknown" or "unknown never lets a violation win". The clamp keeps a HOLDS with a fix pending inside its window from claiming 24 h it cannot have. | A |
| D13 | **Std invariants.** Three KEV ids (`std:kev-patched-within-7d`, `-14d` the default recommendation, `-30d`); six host-config ids (section 2.6). All: selector `tag: [agent, server]`, `min_tier: configured`, `coverage.require: 1.0` (E5). `max_age`: KEV 24 h with the feed bound in D14; the six others 6 h. N is in the id so the digest binds it; a different N is a custom invariant. | The consumer must be able to require an exact id (no vacuous invariant); 14 days matches the classic CISA windows. Feeds refresh every 3 h, so a 24 h host window never rests on a day-old advisory by accident. | A, B |
| D14 | **Feed trust.** Debian, Canonical, Alma and the Red Hat OVAL publish no signature (probed). Transport trust only: TLS to a closed host allow-list, no cross-host redirects, per-snapshot sha256 recorded in the fact's `evidence_ref`, anomaly guards and an atomic swap. A feed older than `assurance_advisory_max_age_h` (48) gives `advisory_stale`, and `Known.until` is clamped to `min(fetched_at) + that age`. **The feed vendor is the trust root of the KEV invariant and the std text says so.** | A malicious vendor path (delete a row, lower a fixed version, delay a date) gives a false HOLDS no guard can catch; recording the sha lets P3 attest to the exact bytes. | A |
| D15 | **Vulnerabilities with no published fix are outside the N-day question**: counted and listed (`no_fix`, `host.kev.unfixed_count`) and every HOLDS carries `basis:no_fix_not_counted` when any exists. A sibling invariant for them is deferred. | The invariant is "N days after a fix existed"; hiding them silently over-claims and calling them violations makes an unfixable case a permanent finding. | A |
| D16 | **Skew negotiation: one additive reply field `accepts`.** The enroll, heartbeat and posture replies carry `accepts: [<token>, ...]` (at most 32 tokens of at most 32 characters). The agent sends a new section or optional block only if its token is listed; no field means the legacy set. Tokens: `accounts sudo authkeys containers platform persistence listeners.v2 patch.meta`. After a 422 `payload_schema` the agent drops back to the legacy set until the next heartbeat says otherwise. Roll out **server first**. | Every P2 model is `extra=forbid`, so an agent that sends an unknown key is refused and the host reads UNKNOWN for sshd and firewall too (the round-1 integration defect). One mechanism covers scout A's `meta` and scout B's sections. | A, B |
| D17 | **Collectors shipped:** `accounts`, `sudo`, `authkeys`, `containers`, `platform`, `persistence` (as `/etc/ld.so.preload` and `rc.local` only), plus a listeners v2 delta. **Deferred with reasons (section 2.7):** FIM, SUID/SGID, enabled units and cron drift, disk encryption, auditd/journald, the IMDSv2 std invariant, containerd/CRI-O/Kubernetes, egress baseline. | Shipped ones are file-only or one bounded socket read and give baseline-free claims; deferred ones need baseline governance, a package-ownership oracle, a capability the unit deliberately lacks, or are not evidence from inside a VM. | B, MVP 6.2 |
| D18 | **One unit change: `ProtectHome=read-only`** (installer heredoc, repo unit, `AGENT_V2.md` section 3 and the parity test move together). **No capability is added**; `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE` are already in the bounding set. `adjtimex` is never called (`@system-service` excludes `@clock`; a denied syscall is SIGSYS and kills the agent): time sync comes from `timedatectl` and `chronyc`. | Home directories stay unwritable; this is the smallest widening that makes `authkeys` meaningful. | B |
| D19 | **The `unavailable(not_applicable)` discrepancy is closed by documentation, not code.** The library maps every `unavailable` to `Unknown`; applicability is written in the predicate (the `host.sshd.installed == false` pattern). The P2 text that says `not_applicable` maps to N/A is corrected (WP17). | Implementing N/A in the evaluator would change digests and the P3 spec for no gain. | B |
| D20 | **New collectors run after the four P2 collectors, with a combined 45 s cap inside the existing 240 s total** and per-collector caps (2 to 15 s); exhaustion is `error(timeout)` for that section only. Moving the heartbeat to its own thread is a later item. | `silent_after_s` is 300 s and collection is synchronous with the heartbeat; a slow new collector must never starve sshd/firewall evidence nor make the agent look silent. | B |
| D21 | **Privacy is by construction.** Never uploaded: password hashes and aging fields, GECOS and home paths, key blobs/comments/option text, sudoers command text, container env/cmd/labels/mount paths, IMDS bodies. `PADDOCK_COLLECTORS_OFF` removes a section entirely (absent = Unknown on the server); `PADDOCK_HASH_USERNAMES=1` (default off) hashes non-root names. | Operators need names to remediate, so hashing is opt-in; a kill switch is cheaper than a redaction layer. | B |
| D22 | **Packages:** `paddock-agent_X-1_all.deb` and `paddock-agent-X-1.noarch.rpm`; the only command is `/usr/bin/paddock-agent` (never `/usr/bin/paddock`, which the Paddock CLI owns); the wrapper pins an absolute interpreter (`/usr/bin/python3`); the pyz is shipped `0644` and byte-identical to the release asset; never enable or start on install; stop before unpack and restart after on upgrade only if it was active; `remove` keeps state, `purge` deletes state only if a marker file exists; the package refuses to install over a script-installed agent and the installer refuses over a package. | pkg-8 (no clobbering `paddock`); a replaced zipapp under a live agent breaks its lazy imports (`bad local file header`, reproduced); the signing key is the host identity. | C |
| D23 | **The `.deb` is written by a pure-Python builder (hand-written ustar, stored-block gzip, fixed epoch 315532800) and is byte-identical on Python 3.8 to 3.13; the `.rpm` is a generated spec built by `rpmbuild`** (no pure-Python rpm writer). | stdlib `tarfile` differs between 3.8 and 3.13 (probed); stored gzip removes zlib-version dependence; a hand-written rpm could only be checked against our own reading of the format. | C |
| D24 | **Signing:** repository-level GPG (RSA 4096 offline primary, 2-year signing subkey; only the subkey in the `release` environment's secrets, fingerprint pinned in a variable, public key committed under `docs/trust/`), `rpmsign` for rpm, `InRelease` + `Release.gpg` for apt, detached `.asc` per file, and cosign keyless over a new `PACKAGE_SHA256SUMS` inside the **existing** `release` job (so the cosign-installer count stays 3). **No key, no repository**: the release then carries unsigned packages covered only by the cosign-signed sums. The existing `SHA256SUMS` is not touched. | apt and dnf cannot verify sigstore; the installer's trust path was hardened over three rounds. | C |
| D25 | **Repository layout:** apt `stable main` (pool, `Architectures: all amd64 arm64 armhf i386 ppc64el riscv64 s390x`, no `Valid-Until` by default), yum flat noarch via `createrepo_c`, always a repo tarball on the release, an opt-in `publish-repo` job (`vars.PACKAGES_PUBLISH == 'true'`) that pushes an orphan `packages` branch. Maintainer defaults to `Paddock Maintainers <paddock-maintainers@paddock.invalid>` (overridable with `--maintainer` / `vars.PADDOCK_PKG_MAINTAINER`). | A tarball lets customers self-host; the branch needs no extra secret; a non-deliverable `.invalid` address cannot be mistaken for a real mailbox. | C |
| D26 | **Pairing is a ledger table `fleet_agent_pairings`** (partial unique indexes: one active pairing per agent and per asset; rows never deleted or re-pointed), **admin only**, justification (3+ characters) mandatory, billing-gated on create (`require_paid("assurance")`), never gated on unpair, **no four-eyes**. | Reversible, audited, and an admin can already change verdicts through zone labels and revocation; the database, not the app, forbids two agents on one asset. | D, P2 11.2 |
| D27 | **A pairing changes identity, never trust level.** The host becomes `asset:<uuid>`, basis `paired`; addresses, zone and CIDR membership come from the cloud asset, never from the host's claim; facts stay `configured`; every P2 gate (signature, key, freshness, silence, exactness, listener completeness, conflicts) still applies. `_ipmap.PRIVATE_PEER_IS_PROOF` stays `False` and `corroborate()` stays dormant; pairing is the only path from agent to asset. | E2: signed is not true. | D |
| D28 | **The peer address survives only as a negative detector:** a direct, unshared, private observed peer that is not one of the asset's addresses raises conflict `paired_peer_mismatch` (no coverage, UNKNOWN, not acknowledgeable). A claimed-address or peer disagreement at pairing time is a 409 unless `acknowledge_mismatch` is set. | A signal that can only withdraw trust is monotone: a false conflict costs availability, never a false HOLDS. | D |
| D29 | **Pairing lifecycle.** Revoking the agent and a token re-key end the pairing in the same transaction; a signed key rotation keeps it. A missing, stale (> 72 h, `assurance_pairing_asset_max_age_h`) or non-VM asset makes the pairing **inert** (the agent falls back to `agent:<uuid>` with a visible note; nothing is auto-ended; findings follow the node through `finding_follow.migrate_targets`). | A re-key token can rebind a row to a different host; an inert pairing fails safe and never silently deletes an operator decision. | D |
| D30 | **A scan conflict is acknowledged per `(agent, proto, port)` and per observation.** Admin; justification 10+ characters; default expiry 168 h, maximum 720 h; supersede on re-ack; cleared by revoke and re-key; a LATER observation is not covered and re-raises the conflict. Only `agent_closed_scan_open` is acknowledgeable. Every ack is disclosed in the facts, the coverage detail and the audit chain. | It lets an honest remediated host leave conflict without waiting 168 h, but cannot pre-clear a future observation or outlive the evidence window. P3 must count acknowledged conflicts like exceptions. | D, P2 11.9 |
| D31 | **builders-7 is fixed by a residual node, not a new coverage origin.** A new pseudo kind `estate` (`estate:<12-digit account>:<region>:<vpc|none>`, never covered, `zone_unknown`, not CIDR-expanded, in the library's `PSEUDO_KINDS`) with a configured edge `estate -> dst` for every SG-reference rule whose membership is not **proven** complete. Completeness comes from a new `ec2:DescribeNetworkInterfaces` read. **The estate edge and the ENI read ship in one package (WP2); the estate edge never ships alone** (it would turn every AWS tenant UNKNOWN). No operator "members enumerated" label. | A coverage-origin qualifier changes library semantics, the digest and the P3 spec, and draws n x m unknown edges; a `cidr:` node would be expanded to every modelled node in the VPC; an operator label is the same unverifiable trust as the boundary labels P1 warned about. | E, P1 builders-7 |
| D32 | **RDS, Lambda, ECS/Fargate, VPC endpoint, NAT, detached and unclassifiable ENIs all count as unmodelled**; any failed or partial `DescribeNetworkInterfaces`, `DescribeInstances` or `DescribeSecurityGroups` page marks the region's inventory incomplete (the builder withdraws coverage for those nodes). Per-ENI nodes are P2.2. | Unknown widens. The cost (an SG shared with such resources keeps its estate edge and the invariant stays UNKNOWN) is stated in 9. | E |
| D33 | **Disabled, deleted, invalid or unentitled invariants: annotate, never close.** Open and triaged findings gain `metadata.invariant_state` in `{disabled, archived, invalid_definition, not_entitled}`, cleared on re-enable; a human-only `POST /v1/invariants/{id}/findings/release` sets `wontfix` with a reason and never reopens by itself. | Closing by absence is a false verification (the P1 rule); `wontfix` is an existing human state the machine never undoes. | F, runner-4 |
| D34 | **`invariant_runs`:** compact the heavy result JSON after 30 days (`assurance_runs_compact_days`), delete rows after 365 days (`RETENTION_INVARIANT_RUNS_DAYS`; 0 keeps all) **except the newest row of each (tenant, invariant)**, and add a `pinned` column now (never compacted or deleted) so P3 attestations can hold rows without another migration. | One heartbeat row per invariant per day carries up to 10 k target refs; the ledger anchor ("since when") must survive. | F |
| D35 | **`auth.client_ip()` becomes the strict address** (`client_ip_strict`: Nth entry from the right, `TRUSTED_PROXY_HOPS`, fail closed to the socket peer), cached per request. No per-site edits; a static test forbids reading the leftmost `X-Forwarded-For` entry anywhere outside `auth.py`. | Two functions with different trust is how the next call site gets the wrong one. A wrong hop count degrades to a shared bucket (availability), never to a forged address. | F, P2 11.15 |
| D36 | **An invalid `assert:` no longer hides other schema errors:** `parse_invariant` passes a validation context that collects the assert problem (placeholder `covered`, assert-dependent shape checks skipped) and then reports every problem; without a context the validator raises exactly as before, so library users and the digest of every valid document are unchanged. `_compile_host` collects every offending leaf. | Smallest change that gives the operator or CLI the full list in one 422. | F |
| D37 | **Sensor scopes stay an accountability record, not an equality check.** GET gains evidence-based advisories (observed /24 prefixes per sensor, declared-but-unobserved, observed-outside-scope, suggestions); PUT refuses prefixes shorter than /16 (v4) or /48 (v6) unless `allow_wide=true` with a 20-character justification; `GET /v1/sensors` gains `scope_declared`; the CLI gains `paddock assurance scopes`. | A sensor cannot prove what it does not see, so an enforced equality check would be false precision. | F, P1 |
| D38 | **Library 0.4.0, pinned.** The orchestrator's dependency pin on `paddock-assurance` moves to `>=0.4.0` in WP2; no runner feature detection (an older library would only count `estate` in the coverage ratio: UNKNOWN, safe). | One less moving part than `_lib_knows_zone_unknown`. | E |
| D39 | **File ownership is per wave** (section 7): a file may be owned by several packages, but never by two packages of the same wave, and a later owner lists the earlier one in `depends_on`. `auth.py`, `config.py`, `retention.py`, all three migrations and the isolation-sweep tests belong to WP0 alone; routes are added by the package that owns the router, with their RBAC rules already present from WP0. | Removes the shared-seam conflicts the four scouts all had (`fleet_posture.py`, `host_fw.py`, `hostfields.py`, `auth.py`, `agent.py`). | all |

## 1. Section A: vulnerability matching and the KEV invariant

### 1.1 What the verdict claims

`std:kev-patched-within-Nd` answers: *is any CISA KEV vulnerability, for which the host's own distribution published a
fix more than N days ago (and which CISA listed more than N days ago), still unfixed in the host's installed packages
(the running kernel for kernel CVEs)?*

**HOLDS** = no counterexample in: the agent-signed package list (tier `configured`, never lifted), the current advisory
snapshots of the host's distribution release, and the current KEV catalogue. It is **not** a claim about snaps,
flatpaks, containers, language packages, third-party repositories, a process that has not restarted since a library
update (only the kernel is judged by what runs), or a CVE without a published fix. Those limits ride on every HOLDS as
`basis:` notes. Anything undecidable is UNKNOWN. A violation needs only one provable counterexample.

Five traps found in the real feeds and the code. **Each is a named test** (section 8):

| Trap | What it is | Rule |
|---|---|---|
| T1 | intel's KEV sync only updates `cves` rows NVD already has; a missing `dateAdded` becomes `NOW()` | D4: own table, no defaults |
| T2 | manifests are not retained (sent on change plus a 24 h refresh; postures coalesce, evict, expire) | D8: persist at ingest, bind to the signed digest |
| T3 | Debian signed kernels: `linux-image-6.1.0-18-amd64` is `6.1.76-1` with source `linux-signed-amd64` `6.1.76+1`; not comparable with the tracker's `linux` | D10: binary version of the running image against the alias-mapped source |
| T4 | tracker `fixed_version: "0"` means never affected; `open`+`nodsa` means no fix is coming; `undetermined` exists; Ubuntu `~esmN` sorts BEFORE the public fix and ESM fixes live in scope `esm-apps/<release>`; rpm modular builds are not comparable across streams; Alma/RHEL advisories are per minor stream (several fixed EVRs per CVE) | section 1.6 rules |
| T5 | only 78 (bookworm) and 28 (trixie) Debian KEV fixes are post-release (`+deb12u`/`+deb13u`) and 96 % / 93 % of those are dated by DSA/DLA; the rest have ancient fixed versions and can never flag a host; a few are undated | D6 |

### 1.2 Evidence chain and where code runs

```
vendor feeds (TLS) --intel--> advisory_fixes + kev_entries   (global, KEV-filtered, atomic snapshot swap)
agent signed posture (list verified against signed manifest.sha256) --orchestrator ingest--> agent_manifests (tenant RLS)
host_fw (verifies posture, writes fact `patch`: os, kernel, manifest sha, reboot, conflict flags)
   --> host_kev builder (load: patch fact + manifest + current snapshots; build: pure)
   --> reach_node_facts rows: source `host_kev`, collector `kev`
library fields host.kev.* --> std:kev-patched-within-Nd --> verdict / finding (existing runner and findings_sync)
```

| Where | What | Never |
|---|---|---|
| `intel/` | fetches, parses, guards, filters and swaps the global tables; keeps raw artefacts in a cache dir | reads tenant data |
| `assurance/paddock_assurance/vulnmatch/` | `vercmp.py` (dpkg and rpm comparators), `model.py`, `match.py`, `scopes.py` (alias maps, key sets), `leaf.py` (the N-day decision over a fact); pure, no I/O, no clock except the `now` argument | imports the orchestrator |
| `orchestrator/app/assurance/builders/host_kev.py` | loads, calls `match_host`, emits the `kev` fact | fetches feeds |
| `orchestrator/app/fleet_posture.py` | persists and verifies the manifest at ingest | trusts an unverified list |

### 1.3 Schema: `schema/044_advisories.sql` (WP0; runs before 099)

Six global tables carry `COMMENT ON TABLE ... IS '@paddock:global ...'` so 099 gives them `global_read` and
`global_platform_write` (no `tenant_id`). Add all four advisory tables and `kev_entries` to `GLOBAL_ALLOWLIST` in
`orchestrator/tests/test_isolation_sweep.py` and re-create `paddock_apply_service_grants()` in 044 with the new names in
the `intel` append list (029 defines it with `['cves','intel_cursors']`). The orchestrator only SELECTs them.

```sql
CREATE TABLE IF NOT EXISTS kev_entries (               -- canonical for assurance; independent of the NVD-gated `cves`
  cve_id TEXT PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,10}$'),
  vendor TEXT NOT NULL DEFAULT '' CHECK (length(vendor) <= 200), product TEXT NOT NULL DEFAULT '' CHECK (length(product) <= 200),
  name TEXT NOT NULL DEFAULT '' CHECK (length(name) <= 400),
  date_added DATE NOT NULL,                            -- no parseable dateAdded => rejected, never NOW()
  due_date DATE, ransomware BOOLEAN NOT NULL DEFAULT FALSE,
  required_action TEXT NOT NULL DEFAULT '' CHECK (length(required_action) <= 1000),
  sources TEXT[] NOT NULL DEFAULT '{}',                -- 'cisa','cisagov-kev-data'
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  absent_fetches INTEGER NOT NULL DEFAULT 0, removed_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS advisory_scopes (           -- the closed list of scopes we claim to judge (upserted by intel from code)
  scope TEXT PRIMARY KEY CHECK (scope ~ '^[a-z0-9_.:-]{3,40}$'),
  family TEXT NOT NULL CHECK (family IN ('deb','rpm')), vendor TEXT NOT NULL, release TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('supported','extended','eol')), support_until DATE,   -- eol or past => UNKNOWN release_eol
  primary_source TEXT NOT NULL, dating_sources TEXT[] NOT NULL DEFAULT '{}',
  max_staleness_s INTEGER NOT NULL DEFAULT 172800, key_ids TEXT[] NOT NULL DEFAULT '{}');      -- rpm distro key ids
CREATE TABLE IF NOT EXISTS advisory_snapshots (        -- one row per accepted or rejected fetch; one 'current' per (source, scope)
  id BIGSERIAL PRIMARY KEY, source TEXT NOT NULL, scope TEXT NOT NULL DEFAULT '',
  fetched_at TIMESTAMPTZ NOT NULL, generated_at TIMESTAMPTZ,       -- the feed's own timestamp; shown, never used to shorten freshness
  etag TEXT NOT NULL DEFAULT '', sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'), bytes BIGINT NOT NULL,
  rows_total INTEGER NOT NULL DEFAULT 0, rows_kev INTEGER NOT NULL DEFAULT 0, rows_dropped INTEGER NOT NULL DEFAULT 0,
  kev_ids_sha TEXT NOT NULL DEFAULT '',                             -- sha256 of the sorted KEV id set this snapshot was filtered with
  status TEXT NOT NULL CHECK (status IN ('current','superseded','rejected')), reject_reason TEXT NOT NULL DEFAULT '',
  parser_version INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS uq_advisory_snapshot_current ON advisory_snapshots (source, scope) WHERE status = 'current';
CREATE TABLE IF NOT EXISTS advisory_fixes (            -- only rows whose CVE is in kev_entries at filter time
  id BIGSERIAL PRIMARY KEY, scope TEXT NOT NULL REFERENCES advisory_scopes(scope), cve_id TEXT NOT NULL,
  pkg TEXT NOT NULL, pkg_kind TEXT NOT NULL CHECK (pkg_kind IN ('source','binary')),
  state TEXT NOT NULL CHECK (state IN ('fixed','open','not_affected','undetermined','esm_only')),
  fixed_evr TEXT NOT NULL DEFAULT '', advisory_id TEXT NOT NULL DEFAULT '',
  fixed_at TIMESTAMPTZ,                                              -- advisory publication, start of its UTC day; NULL = undated
  urgency TEXT NOT NULL DEFAULT '', stream TEXT NOT NULL DEFAULT '', modular BOOLEAN NOT NULL DEFAULT FALSE,
  first_seen_at TIMESTAMPTZ NOT NULL, last_seen_snapshot BIGINT NOT NULL REFERENCES advisory_snapshots(id), removed_at TIMESTAMPTZ,
  UNIQUE (scope, cve_id, pkg, state, fixed_evr, advisory_id));
CREATE INDEX IF NOT EXISTS idx_advisory_fixes_lookup ON advisory_fixes (scope, pkg) WHERE removed_at IS NULL;

-- tenant tables (FORCE RLS comes from 099; follow the 041 sweep rules: tenant_id with a default, in every UNIQUE,
-- every NOT NULL column has a default, no global UNIQUE; application SQL never names tenant_id)
CREATE TABLE IF NOT EXISTS agent_manifests (           -- content addressed per tenant: clones share one row
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  sha256 TEXT NOT NULL DEFAULT '' CHECK (sha256 ~ '^[0-9a-f]{0,64}$'), mgr TEXT NOT NULL DEFAULT 'dpkg' CHECK (mgr IN ('dpkg','rpm')),
  pkg_count INTEGER NOT NULL DEFAULT 0, src_names TEXT[] NOT NULL DEFAULT '{}',   -- GIN index: which hosts a KEV delta can touch
  packages_gz BYTEA NOT NULL DEFAULT '', size_bytes INTEGER NOT NULL DEFAULT 0 CHECK (size_bytes <= 1048576),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_ref_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (tenant_id, sha256));
CREATE INDEX IF NOT EXISTS idx_agent_manifests_src ON agent_manifests USING GIN (src_names);
CREATE TABLE IF NOT EXISTS agent_manifest_refs (       -- the agent's CURRENT list and the envelope that carried it
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  agent_id UUID NOT NULL REFERENCES fleet_agents(id) ON DELETE CASCADE,
  manifest_sha TEXT NOT NULL DEFAULT '', key_id TEXT NOT NULL DEFAULT '', seq BIGINT NOT NULL DEFAULT 0,
  collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE (tenant_id, agent_id));
```

(`agent_manifest_refs` uses an `id` primary key plus `UNIQUE (tenant_id, agent_id)` instead of `agent_id` as the primary
key, so it passes the isolation-key sweep without a special case.)

### 1.4 Feed ingestion (intel service; WP11 then WP13)

**Scopes** (`<vendor>:<release>`, a closed list in `intel/app/sources/advisories/scopes.py`, upserted into
`advisory_scopes` at start so `support_until` moves with a code release): `debian:bookworm`, `debian:trixie`,
`ubuntu:jammy`, `ubuntu:noble`, `rhel:8`, `rhel:9`, `alma:8`, `alma:9`.

| Feed | Primary (status + fixed version) | Dating source | Size | Cadence |
|---|---|---|---|---|
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (about 1805 entries: `cveID, vendorProject, product, dateAdded, dueDate, knownRansomwareCampaignUse, requiredAction ...`, top-level `catalogVersion, dateReleased, count`) and the mirror `raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json` | n/a | 1.9 MB | 1 h, conditional GET |
| `debian:*` | `security-tracker.debian.org/tracker/data/json`: ONE line, 93 MB, `{source:{CVE:{releases:{rel:{status resolved\|open\|undetermined, fixed_version, urgency, nodsa?}}}}}`; **stream it key by key** with `JSONDecoder.raw_decode` on 1 MiB blocks (`json.load` peaks at 374 MB RSS) | DSA and DLA lists from salsa `data/DSA/list` and `data/DLA/list` (`[01 Jul 2024] DSA-5724-1 openssh - ...`, `{CVE-...}`, `[bookworm] - openssh 1:9.2p1-2+deb12u3`); bookworm is in LTS so **DLA is required** | 93 + 1.3 + 1.0 MB | 3 h |
| `ubuntu:*` | `com.ubuntu.<rel>.cve.oval.xml.bz2` (12 MB bz2, 292 MB xml): criterion comments `S source package in noble, is affected and has been fixed (note: 'EVR')` -> fixed, `... might be affected and may need fixing` -> open, `esm-apps/noble ... fixed` -> `esm_only`, `K kernel in noble was vulnerable but has been fixed (note:'EVR')`; the CVE element carries `usns="6859-1"` | `com.ubuntu.<rel>.usn.oval.xml.bz2` (`<advisory><issued date="..."/>`); **join** CVE definition -> USN id -> issued date and require the USN criterion's note to equal the fixed EVR for that source | 12 + 2 MB bz2 | 6 h |
| `rhel:8/9` | Red Hat OVAL v2 `.../data/oval/v2/RHEL9/rhel-9.oval.xml.bz2` (37 MB xml): per definition `<issued date=.../>`, CVE references, rpminfo tests `NAME is earlier than E:V-R`, AND `signature_keyid` tests; `affected_cpe_list` separates standard `enterprise_linux:9` from `rhel_eus` | same file | 1.6 MB bz2 | 6 h |
| `alma:8/9` | `errata.almalinux.org/<N>/errata.json` (34 MB): `updateinfo_id`, `issued_date.$date` ms, references type cve, `pkglist.packages[{name,epoch,version,release,arch}]`; the pkglist name carries the minor stream (`...__9_7_default`) | same file (the distro's own date: when the fix became available to THAT host) | 34 MB | 6 h |

The exact Canonical download host and every other URL are a **closed config allow-list** (`ADVISORY_HOSTS`), confirmed
from the real download URL while building; a redirect to another host is a rejected fetch.

**Guards on every fetch, before the swap.** A failing check stores the snapshot as `rejected` with a reason, writes a
system audit row (reason, sha) and leaves the previous `current` snapshot in place (it ages into `advisory_stale`):
row count within -30 % / +100 % of the previous current snapshot; parse drop rate under 0.5 % (a version string must parse
with the pure comparators of `paddock_assurance.vulnmatch.vercmp`; intel gains the pure `paddock-assurance` library as a dependency, WP11); every expected top-level key present; monotone `generated_at` and KEV
`catalogVersion`/`count` (never accept an older KEV catalogue or one with fewer entries than we hold); decompression
caps (bz2 expansion ratio 100x and 1 GiB); XML only through `lxml` `iterparse` with `resolve_entities=False,
no_network=True, huge_tree=False`; JSON duplicate keys and size caps; a TLS-only fetch to the allow-list.

**KEV rules.** The union of both sources is used. A CVE is marked `removed_at` only when both sources omit it for 3
consecutive fetches over at least 48 h (`absent_fetches`). An entry's `date_added` later than our first sighting is clamped
to that sighting's date. The existing `intel/app/sources/kev.py` keeps flipping `cves.known_exploited` for the UI and
risk scoring and shares the fetch (its tests stay green); the new `kev_catalogue.py` feeds `kev_entries`.

**Swap.** `Database.swap_advisories()` (platform context, one transaction) upserts `kev_entries`, supersedes the old
snapshot, inserts the new `current` one with its `kev_ids_sha`, and upserts `advisory_fixes` (`removed_at` set for rows no
longer present, `first_seen_at` kept for rows that were). A KEV change triggers `refilter()` from the raw cache
(`/var/cache/paddock-intel`, about 200 MB) and swaps KEV and rows together so readers never see a KEV set ahead of the
rows. Loops in `main.py`: `advisories` every 3 h and `kev` every 1 h, each under the existing per-source lock;
`POST /sync/advisories/{source}`; counters under `/stats`; config `ENABLE_ADVISORIES`, `ADVISORY_SOURCES`,
`ADVISORY_CACHE_DIR`, `ADVISORY_HOSTS`.

**Honest limit.** Whoever controls the vendor feed, or the TLS path to it, controls the verdict (delete a row, lower a
fixed version, delay a date: false HOLDS). The guards catch truncation, rollback and garbage, not a malicious vendor. Red
Hat's CSAF advisories carry PGP signatures; if RHEL moves to CSAF, verify them against a vendored Red Hat key. Until
then the standard text says "advisory data is taken from the distribution's public feeds over TLS".

**Freshness.** `advisory_snapshots.fetched_at` is the staleness clock. A stale primary snapshot (older than the scope's
`max_staleness_s`, default 48 h, floor of `assurance_advisory_max_age_h`) or a stale KEV makes the host UNKNOWN
`advisory_stale`; a stale DATING source only makes undated rows undated. No `current` snapshot is also `advisory_stale`
(an air-gapped install with `ENABLE_ADVISORIES=false` reads UNKNOWN on every host, which is correct).

### 1.5 Manifest persistence and the agent's `meta` (orchestrator ingest, agent patch collector v2)

**Ingest** (`fleet_posture._claim_and_persist`, same transaction as the sequence claim, before the coalesce step): when the
validated payload has `patch.manifest.state == 'ok'` and `full`, recompute `sha256(canon(sorted rows))` **with the same
canonical encoder the agent uses** (`collectors/base.payload_bytes` over the sorted rows; a cross-language vector test pins
the two) and require it to equal `manifest.sha256`. That digest is inside the signed payload, so the list is bound to the
signature by transitivity.

* match: `INSERT ... ON CONFLICT (tenant_id, sha256) DO UPDATE SET last_ref_at = NOW()` into `agent_manifests` (rows
  gzipped; `src_names` = the distinct non-empty source names, or names for rpm) and upsert the agent's
  `agent_manifest_refs` row (`manifest_sha, key_id, seq, collected_at`);
* mismatch: accept the posture, store nothing, change no ref, write audit `fleet.manifest.digest_mismatch` (sampled like
  the other rejections); the newest posture's sha then differs from the ref and the host reads UNKNOWN
  `manifest_not_current`;
* a posture with no list does not touch the refs (a digest-unchanged posture references the same sha);
* caps: at most 8000 rows (already), gz at most 1 MiB (over: store nothing, audit `fleet.manifest.too_large`, UNKNOWN
  `manifest_missing`), per tenant 512 MiB (`fleet_manifest_tenant_max_mb`, evict unreferenced oldest first; if every row
  is referenced and over the cap, refuse the new one and audit), GC of unreferenced rows after 7 days in `retention.py`.

**Currency** (the builder, not ingest): the NEWEST verified posture's `manifest.sha256` (it is in the `patch` fact) must
equal `agent_manifest_refs.manifest_sha`, else the `kev` entry is `error: manifest_not_current`. To keep that window to
one heartbeat, the enroll/heartbeat/posture replies carry `known_manifest_sha` (the ref's sha, or null); when it differs
from the agent's current sha the agent sets `force_full_manifest` for its next collection. The 24 h forced full stays as
the backstop. Both reply fields (`accepts`, `known_manifest_sha`) are additive.

**Agent patch collector v2.** The 5-column row `[name, evr, arch, src, srcevr]` stays. An OPTIONAL `manifest.meta` object
is added and sent only when `accepts` lists `patch.meta` (the server model `PatchManifest` gains `meta` in WP8, one wave
BEFORE the agent ships it in WP9: deploy the server first):

* rpm: `meta.foreign` (names whose `%{RSAHEADER:pgpsig}` key id is not in the distro key set shipped per os id), and
  `meta.modular` (names with a non-empty `%{MODULARITYLABEL}`). Red Hat's own OVAL tests `signature_keyid`, so this is
  the vendor's origin proof.
* deb: `meta.apt_origins`, the distinct `o=`/`a=`/`n=` of apt sources at priority 100 or more from `apt-cache policy`
  (summary only, at most 16 entries). No per-package origin exists without parsing per-package policy (a superseded
  installed version reads "local only" exactly when it is the vulnerable one). The server derives `third_party_sources`
  = any origin outside the scope's allow-list.
* Without `meta` (older agent) the server still matches and adds the note `package_origin_unverified`; with `meta` it
  excludes foreign and modular names from matching and marks the `(cve, pkg)` UNKNOWN when the name is KEV-relevant.

### 1.6 The matcher (`paddock_assurance.vulnmatch`)

**1.6.1 Version algorithms** (`vercmp.py`; prototype and vectors in the scratchpad `proto/`).

* **dpkg**: Debian Policy 5.6.12 / dpkg `parseversion` + `verrevcmp`. Epoch = digits before the first `:`; revision after
  the LAST hyphen; `order()`: `~` < end of string < letters < everything else (+256); digit runs compare numerically
  ignoring leading zeros. Strict: refuse anything outside `[A-Za-z0-9.+~:-]`, an empty revision after a hyphen (dpkg
  refuses it), an upstream part not starting with a digit, a non-numeric or over-long epoch, length over 256. A
  `VersionError` makes the item UNKNOWN `version_unparsable`, never "patched".
* **rpm**: `rpmvercmp` from `lib/rpmvercmp.c` including `~` (before everything) and `^` (after end of string, before
  anything else), non-alphanumerics as separators, numeric segments newer than alpha, numeric compare by stripped length
  then bytes; EVR = epoch (missing 0), version, release split on the LAST hyphen; the release must exist.
* **Vectors**: 89 `rpmvercmp` rows (each also reversed), 9 EVR rows (epoch dominance, `el9_4.10` > `el9_4.9`, modular vs
  plain), 26 dpkg rows (policy examples, `+deb12u10` > `+deb12u3`, `3.0.13-0ubuntu3.1~esm1` < `3.0.13-0ubuntu3.1`,
  `5.6.1+really5.4.5-1` > `5.6.1-1`), refusal cases, and a 3000-pair random oracle against the real `dpkg
  --compare-versions` (2838 comparable pairs, 0 mismatches in the probe; skipped when `dpkg` is absent), plus hypothesis
  properties (total order, antisymmetry, transitivity on triples, epoch dominance, `~` minimality).

**1.6.2 Scope resolution** from the signed, untrusted `os` block: deb: `id=debian` + codename in `advisory_scopes`, or
`id=ubuntu` + `version_codename`; rpm: `id` in `{rhel, almalinux}` and the major of `version_id`. The scope must exist with
status `supported` or `extended` and `support_until` in the future. Everything else (including every `ID_LIKE`
derivative, `amzn`, `ol`, `centos`, `rocky`, SUSE, Alpine, an unknown codename, an EOL release) gives status
`unavailable` with reason `distro_unsupported` or `release_eol`. Defence in depth against a host lying about its os: for
debian and ubuntu require that more than 50 % of the packages that carry a release tag (`+debNu`, `ubuntuN`, `.elN`) carry
the claimed release's tag, else UNKNOWN `os_identity_inconsistent`. (A fully lying signed host is out of scope: E2.)

**1.6.3 What is compared.** deb (Debian and Ubuntu): per installed row look up `fixes[(scope, src)]` and compare `srcevr`
(`${source:Version}`, binNMU suffix removed) with the fixed source version. rpm: look up by binary NAME and compare EVR
ignoring arch; `src`, `debuginfo` and `debugsource` rows are dropped at ingest. Several binaries of one source are
compared individually; a leftover binary from an older source version reads as unpatched (the false-positive direction,
stated in 9).

**1.6.4 Kernel rule** (all families). Only the RUNNING kernel image counts; other installed kernels, headers, `libc-dev`,
`perf` and tools are ignored for kernel sources. Source aliases: deb `linux`, `linux-signed-*`, `linux-latest*` ->
`linux`; Ubuntu `linux-signed-X`, `linux-meta-X`, `linux-restricted-modules-X` -> `linux-X` (X in aws, azure, gcp, oracle,
kvm, lowlatency, hwe-*, raspi ...); rpm `kernel`, `kernel-core`, `kernel-rt-core`. Compare the BINARY version of the
package that owns the running kernel (`kernel.package`/`package_version`, present only when `/proc/sys/kernel/osrelease`
maps to an installed package). `kernel` unavailable or unmanaged -> every kernel item UNKNOWN `kernel_unknown`;
`livepatch: true` -> `livepatch`. An installed-but-not-running fixed kernel with the old one running (reboot pending) is a
real exposure and falls out of the same rule.

**1.6.5 Per `(cve, pkg)` status.** Gather every statement for the CVE and package in the scope:

* `not_affected` (deb `fixed_version "0"`): ignored.
* `fixed`: unmet iff `cmp(installed, fixed_evr) < 0`.
* `open` (no fix published; Ubuntu "might be affected" included) with nothing unmet: bucket `no_fix` (counted and listed;
  NOT part of the N-day question).
* `undetermined`, a `resolved` row with no fixed version, `esm_only`, an ESM-tagged installed version (`[~+]esm\d*`), an
  rpm modular name, a foreign-signature rpm, an unparsable version: UNKNOWN with that reason, **only when the name is
  KEV-relevant for the scope** (names in no KEV row cannot matter).
* Result per `(cve, pkg)` (deduplicated; the prototype duplicated under livepatch): `open_fix` (at least one unmet fix),
  `no_fix`, `unknown(reason)`, or nothing (patched).

**1.6.6 Dating and the clock.** Only a DATED advisory sets a fix date: DSA/DLA, USN issued, RHSA issued, ALSA
`issued_date`. For a CVE/package the fix date is the EARLIEST date among the unmet fixes (the host has lacked a fix since
the earliest it does not have; this also covers several minor streams and re-fixes). An undated fix uses the row's
`first_seen_at` (D6). Any fix or KEV date later than the row's `first_seen_at` is replaced by it (D5). `clock_start =
max(fix date, KEV date_added)`. Optional enrichment for the handful of undated post-release rows (Debian changelog date,
`snapshot.debian.org` first seen, Launchpad publishing date) is **not** in P2.1.

**1.6.7 Aggregation (the leaf, `leaf.py`)**, computed from the fact at evaluation time because N is a parameter:

* an `open` item with basis `advisory` is *overdue* iff `now - clock_start > N`; inside the window it is *pending* (a
  decided non-violation that expires at `clock_start + N`);
* an item with basis `first_seen` is overdue by the same test (proof of violation), and inside the window is
  *undecided*;
* `definite` = overdue items; `undecided` = undecided items + every `unknown` item;
* **True** if `definite > 0`; **False** iff `definite == 0`, `undecided == 0` and the item list is not truncated; else
  **Unknown** (`kev_undecided`, or the single reason when every undecided item shares it). A violation beats unknown
  items; unknown never becomes False.

Worked results on real data (scratchpad `demo.py`, `demo_rpm.py`, to become `match_host` golden tests): bookworm `libc6
2.36-9+deb12u2` -> CVE-2023-4911 open fix `2.36-9+deb12u3` (DSA-5514-1 2023-10-03; KEV added 2023-11-21 so `clock_start`
2023-11-21), leaf(14) True; at KEV+5 d False (pending), at KEV+15 d True; `deb12u10` -> no items -> False; undated fix first
seen 3 d ago -> UNKNOWN, 60 d ago -> True; `...deb12u2~esm1` -> UNKNOWN `esm_package`; running kernel `6.1.0-17`
(`6.1.69-1`) with `6.1.76-1` installed -> True, running `6.1.0-18` -> False, livepatch -> UNKNOWN; Alma 9 running
`5.14.0-162.6.1.el9_1` -> 14 KEV items, True.

### 1.7 The `kev` fact (collector `kev`, source `host_kev`, row tier `configured`)

Entry keys as in `types.FactOut`: `status` ok|error|unavailable; `signed` copied from the verified `patch` fact; `key_id`,
`seq`, `evidence_ref` = `agent_posture:<agent>:<kid>:<seq>|kev:<manifest12>|adv:<snapshot ids>:<sha12>|kev:<id>:<sha12>`;
`conf: exact` only when scope, kernel (if any kernel row is relevant), manifest and freshness all passed; `partial: false`;
`conflict` copied from the host's `patch` fact; **`observed_at` = `min(patch fact observed_at, primary fetched_at, kev
fetched_at)`** (the manifest's freshness is that of the newest verified posture, whose sha the currency check proved
equal; not the carrier envelope's age); no floats. `data`:

```
{ v:1, scope:"debian:bookworm", manifest:{sha256, count},
  snap:{primary:{id,sha12,fetched_at}, dating:[{source,id,sha12,fetched_at}], kev:{id,sha12,catalog:"2026.11.25",fetched_at},
        valid_until:"<min(fetched_at)+assurance_advisory_max_age_h>"},
  counts:{relevant:int, open_fix:int, no_fix:int, undecided:int},
  open:[{cve,pkg,inst,fixed,adv,fix_at:"2023-10-03T00:00:00Z",basis:"advisory|first_seen",kev_at:"2023-11-21T00:00:00Z",due:"2023-12-12",ransom:false}],
  open_truncated:bool,            // sorted clock_start asc then cve; cap 100 (the most overdue are kept)
  unknown:[{cve,pkg,reason}], unknown_total:int, unknown_reasons:{reason:int},   // cap 50
  no_fix:[{cve,pkg}], no_fix_total:int,                                            // cap 50
  third_party_sources:bool|null, notes:["basis:distro_packages_only","basis:installed_versions", ...] }
```

Status mapping: unsupported distro, EOL or a containerised agent -> `unavailable` (reasons `distro_unsupported`,
`release_eol`, `containerised_agent`); a stale snapshot, a snapshot behind KEV, a missing or not-current manifest, or a
bad digest -> `error` with reason `advisory_stale`, `advisory_behind_kev`, `manifest_missing`, `manifest_not_current`. A
healthy host is about 1 KB; the caps keep a hostile one under 64 KiB (the store's 256 KiB hard cap turns anything larger
into the existing `facts_too_large` error entry, which stays UNKNOWN).

### 1.8 Library: fields, `Known.until`, reasons, witness (WP10)

* Registry (`hostfields.py`): new `ParamSpec("days", 0, 3650)`; collector `kev`; `max_tier` configured; the parameter sits
  after segment 2 (`host.kev.exploited_unpatched(14)`). Fields: `host.kev.exploited_unpatched(N)` bool (the leaf of
  1.6.7); `host.kev.open_count` int (Known only when `undecided == 0` and not truncated); `host.kev.unfixed_count` int
  (informational: lets authors write a stricter custom invariant); `host.kev.undecided_count` int;
  `host.kev.third_party_sources` bool.
* New blind-spot reasons appended to `REASON_ORDER` after `unavailable`: `distro_unsupported`, `release_eol`,
  `manifest_missing`, `manifest_not_current`, `advisory_stale`, `advisory_behind_kev`, `kev_undecided`. Reuse
  `evidence_conflict`, `tier_below_min`, `stale`. Notes shown on every HOLDS: `basis:distro_packages_only`,
  `basis:installed_versions`, `basis:advisory_feed_tls_only`, plus conditional `basis:no_fix_not_counted`,
  `basis:package_origin_unverified`, `basis:third_party_repositories_present`, `basis:rhel_standard_stream_assumed` (RHEL
  EUS cannot be told from os-release).
* `Known` gains `until: Optional[datetime] = None`. The accessor sets it to the earliest instant the leaf can flip by the
  clock alone: `min(clock_start + N over pending items, snap.valid_until)`. The evaluator takes the minimum over every
  `Known.until` consulted and the verdict's `valid_until` = `min(existing rule, until)`. `until` is not part of the
  invariant digest. (The runner's 15 minute backstop re-evaluates for findings anyway; the clamp matters for P3
  attestation validity.)
* Witness: the host-config witness keeps its fixed all-string `detail` keys; `observed` is the worst item in a restricted
  charset, at most 120 characters, e.g. `CVE-2023-4911 libc6 2.36-9+deb12u2<2.36-9+deb12u3 fix 2023-10-03 kev 2023-11-21 +2
  more`; `evidence_ref` names the snapshots. The full list is served by `GET /v1/fleet/agents/{id}/kev`.
* CLI: `paddock-invariants kev explain --manifest FILE --os-release FILE [--kernel V]` over offline files, and the plan
  text (`render.py`) lists the `kev` collector.

### 1.9 The std invariants and the finding text

Three files (`stdlib/kev-patched-within-7d.yaml`, `-14d`, `-30d`); only N, the id, the title and the text differ.

```yaml
apiVersion: paddock.dev/invariant/v1
id: std:kev-patched-within-14d
title: No actively exploited vulnerability stays unpatched more than 14 days after a fix is published
description: >
  For every managed server tagged agent or server: no CISA Known Exploited Vulnerability for which the host's own
  distribution published a fix at least 14 days ago (and which CISA listed at least 14 days ago) is still unfixed in the
  installed packages (the running kernel for kernel CVEs). Judged from the agent's signed package list and the
  distribution's own advisory data, which is taken from the distribution's public feeds over TLS and is the trust root
  of this invariant. Not judged: vulnerabilities without a published fix (reported separately), snaps, flatpaks,
  containers, language packages, third-party repositories, processes not yet restarted. A host whose package list,
  distribution release or advisory data is missing, stale, unsupported or ambiguous (ESM, modular, livepatched kernel)
  is UNKNOWN, never a pass.
severity: high
subjects: { to: { tag: [agent, server] } }
assert: host.kev.exploited_unpatched(14) == false
evidence: { min_tier: configured, max_age: 24h }
coverage: { require: 1.0 }
```

**Finding text** (`findings_sync.describe_witness`, host-config, kev clause). Title: `Actively exploited vulnerabilities
unpatched more than 14 days after a fix: <host>`. Body: `<host> (<scope>): <n> CISA KEV vulnerabilities have had a fix
available for more than 14 days and are not installed. Worst: CVE-2023-4911 in libc6: installed 2.36-9+deb12u2, fixed in
2.36-9+deb12u3 (DSA-5514-1, 2023-10-03); in CISA KEV since 2023-11-21 (CISA due 2023-12-12). Evidence: package list sha256
<12>, advisory snapshot <source> <sha12> fetched <time>, KEV catalogue <version>, signed by agent key <kid> seq <n>. Fix:
upgrade the listed packages (apt-get install --only-upgrade <pkgs> / dnf upgrade); reboot if the kernel is listed. Not
judged: snaps, containers, third-party repositories.` Closing follows the existing host-config rule: only a host in
`passing_targets` closes its finding.

### 1.10 The builder `host_kev` and its cost (WP12)

Registered AFTER `host_fw` in `BUILDER_NAMES` (it reads `host_fw`'s persisted `patch` facts, which already carry
signature, key, sequence, freshness, tombstone and scan-conflict handling, so nothing is re-verified). `load(conn, now)`:
(1) the `host_fw` `patch` fact rows; (2) for hosts whose input key changed, `agent_manifest_refs` and `agent_manifests` by
sha; (3) the current snapshots, scopes, KEV and the KEV-filtered `advisory_fixes` per scope. `build(rows, now)` is pure and
byte-stable. A revoked, legacy, tombstoned or conflicted host gets no `kev` fact or a conflict-copied one, never a pass.
The first implementation verifies that `graph_loader._assemble_facts` merges facts of two sources by collector name (it
reads `reach_node_facts` per `(node_ref, source)`); if a test shows it does not, WP12 owns the loader fix.

Cost (measured, scratchpad `bench.py`): 0.5 ms per host for 1860 packages and 79 relevant names; the real cost is
decompressing and parsing a manifest (about 8 ms for 800 KB). So: (a) a per-host input key = `sha(manifest_sha, scope
row-set hash, snapshot validity flags, kernel package+version, livepatch, patch-fact seq/digest)` stored in the fact; an
unchanged key re-emits the stored entry with a new `observed_at` and loads no manifest (the fact digest ignores
`observed_at`/`seq`, so `graph_version` does not move); (b) the row-set hash is over the scope's KEV rows, not the
snapshot id, so a refresh that changes nothing relevant changes no key; (c) after a real change only hosts whose
`src_names && changed_names` (GIN) re-match; (d) an in-process LRU keyed by `(manifest_sha, row-set hash, kernel)` shares
work between cloned VMs; (e) a full re-match of 10,000 hosts is about 2 minutes of one core, chunked inside the runner's
per-tenant budget (hosts left over keep their previous fact, which ages into UNKNOWN by `max_age`, never into HOLDS).

### 1.11 Routes, settings, retention, audit

* `GET /v1/fleet/agents/{id}/kev` (**triage**; names CVEs per host, so not viewer-safe): computed from the stored `kev`
  fact. `GET /v1/assurance/advisories` (**read**): per scope the snapshot id, source, `fetched_at`, age, status,
  `rows_kev`, KEV catalogue version, staleness verdict; global data only; the "why is my host UNKNOWN" page.
* Settings (`config.py`, WP0): `assurance_kev_enabled` (true), `assurance_advisory_max_age_h` (48),
  `fleet_manifest_tenant_max_mb` (512). Collecting and matching are free (like `host_fw`); evaluating the std invariants
  stays under the existing `assurance` Team feature.
* `retention.py` (WP0): GC unreferenced `agent_manifests` after 7 days; `advisory_snapshots` keep the last 14 per
  `(source, scope)` plus every `rejected` row for 90 days; removed `advisory_fixes` rows after 30 days.
* Audit: `fleet.manifest.digest_mismatch`, `fleet.manifest.too_large`, and a system row per rejected feed snapshot.

### 1.12 Slices (each behind `assurance_kev_enabled`)

A1 vulnmatch + vercmp + fields + std YAML + CLI (library only, 100 % offline testable: WP5, WP10); A2 migration 044 + KEV
catalogue + Debian ingestion + manifest persistence + `host_kev` + Debian end to end (WP0, WP11, WP12); A3 Ubuntu, A4 RHEL
and Alma (WP13); the agent `meta` and the `known_manifest_sha` echo (WP8, WP9). Debian first: its data has the best dating
coverage (96 %) and the smallest ingest.

## 2. Section B: more read-only collectors

### 2.1 Verdict per MVP 6.2 row

| Row | P2.1 | Reason |
|---|---|---|
| Accounts | **Ship**, as two sections: `accounts` (passwd, shadow states, group) and `sudo` | Files only, cheap. Sudoers is the hard parse, so it is isolated: a sudoers failure must not make the uid-0 claim UNKNOWN. |
| authorized_keys counts and fingerprints | **Ship** as `authkeys`; fields only, no std invariant | Feeds custom "approved fingerprints" invariants. Needs `ProtectHome=read-only` (D18). |
| Listeners (rich) | **Mostly shipped in P2.** `exe_sha256`, `exe`, `unit`, `container` and socket `uid` are collected; `_compact_listeners` drops them. Delta: add `euid` and `user` per row (listeners v2), carry `exe_sha256`, `unit`, `user`, `euid` into the fact, add three fields | The gap is in the builder, not the collector. |
| Platform context | **Ship a subset:** time sync, provider (DMI), opt-in IMDS probe. Defer disk encryption and auditd/journald | 2.7 |
| Containers | **Ship** for the docker/podman-compatible socket only; containerd, CRI-O and Kubernetes nodes report UNKNOWN | gRPC is not stdlib-feasible. |
| Services and persistence | **Ship the baseline-free slice:** `/etc/ld.so.preload` and `rc.local`. Defer enabled units, cron/timers, SUID/SGID | Everything else needs a baseline or a package-ownership oracle. |
| FIM | **Defer to P2.2** | Needs baseline governance (2.7). `sshd.files[].sha256` already ships. |

New section keys: `accounts, sudo, authkeys, containers, platform, persistence`. A node holds at most 16 collector entries
(`MAX_COLLECTORS_PER_NODE`); today 5 (`sshd, firewall, listeners, patch, host_agent`), after P2.1 12 (+ six sections +
`kev`), leaving 4.

### 2.2 Cross-cutting rules (all new collectors)

**Wire and schema.** Stay on `schema: 2` and `paddock.host.posture/v2`; the six sections are OPTIONAL keys. A missing
section means "the collector did not run or was disabled", which the library reads as `no_sensor` (Unknown), never a pass.
`COLLECTOR_VERSIONS` gains `accounts:"1", sudo:"1", authkeys:"1", containers:"1", platform:"1", persistence:"1"` and
`listeners` goes to `"2"`. The envelope `collectors` map allows 32 entries (12 used). `SelfCollectors` (also
`extra=forbid`) gains six OPTIONAL `SelfCollector` entries (default `None`, keeping the "non-Optional annotation with
`None` default" trick so an explicit `null` stays refused). Negotiation is D16 (`accepts`). Roll out the server first.

**Determinism and digest.** `content_digest` strips only a fixed set of volatile fields, so a field that changes on every
run makes every post a "change" (rebuild, row, graph churn; `MIN_STORE_INTERVAL_S` 300 s). Therefore: no timestamps,
offsets, uptimes, pids, "Up 3 hours" strings or mtimes (Docker `Status` is volatile; send `State` only); every list is
sorted; every map has fixed keys; no floats. A test asserts two consecutive collections on an unchanged fixture host give
byte-identical content digests and that one field flip changes the digest.

**Size.** Typical new payload 10 to 40 KiB. Server check in `validate_posture`: the sum of `len(canon(section))` over the
six new sections is at most 256 KiB, else 422 (the per-agent store cap is 128 MiB; a bloated section multiplies by the
hourly rows). Per-collector fact caps (builder compaction): accounts 24 KiB, sudo 24, authkeys 48, containers 48,
platform 2, persistence 4, listeners rows unchanged at 200. Every list cap is re-checked server side (the agent is not
trusted).

**Runtime budget (D20).** Order: the four P2 collectors first, then `accounts` 8 s, `sudo` 12 s, `authkeys` 15 s,
`containers` 15 s, `platform` 10 s (the IMDS probe at most 3 s of it), `persistence` 2 s, combined cap 45 s inside the
240 s total. `authkeys` re-reads a home's file only if `(st_dev, st_ino, st_size, mtime_ns, ctime_ns)` changed, through a
module-level cache like listeners' `_HASH_CACHE` (a new `Ctx` is built every posture).

**Sandbox and privilege (D18).** `SystemCallFilter=@system-service` excludes `@clock`, `@mount`, `@swap`, `@reboot`; the
default action for a denied syscall is SIGSYS. So **no `ctypes` anywhere in the new collectors** (an AST test fails any
import), no `adjtimex`; `timedatectl` (D-Bus; `systemd-timedated` makes the syscall in its own process) and `chronyc` only.
`ProtectHome=yes` hides `/home`, `/root` and `/run/user`; `ProtectHome=read-only` makes them readable, not writable.
Account files under `/etc` are fine; `/etc/shadow` and `/etc/sudoers` (0440) are read with `CAP_DAC_READ_SEARCH`, `/proc/<pid>/exe` with
`CAP_SYS_PTRACE`; both are already in the bounding set. `/run/docker.sock` (0660 root:docker) is connectable by uid 0 as
owner; `AF_UNIX` is allowed and a read-only filesystem does not block `connect()`. `CAP_AUDIT_CONTROL` is not in the set,
which is why auditd is deferred. Rootless podman sockets (`/run/user/<uid>/...`) stay unreachable and uncounted (note
`rootless_unseen`). The unit text under a real systemd was **not** exercised (the sandbox has no systemd): section 9.

**Operator controls and privacy (D21).**

| Source | Never leaves the host | What is sent |
|---|---|---|
| `/etc/shadow` | hash, salt, aging fields | per-account state (`hash`/`locked`/`empty`/`unknown`) and counts per algorithm id |
| `/etc/passwd` | GECOS, home path | name, uid, gid, login-shell boolean |
| `authorized_keys` | key blob, comment, option text, `from=` patterns | count, type, `SHA256:` fingerprint, option-class counts |
| sudoers | command lines, aliases, paths, args | per rule: principals (capped), `nopasswd`, `cmd_all`, count of limited commands |
| containers | env, cmd, labels, mount paths, volumes | short id, clipped name, image id, booleans, a fixed vocabulary for sensitive mounts |
| IMDS | response bodies, credentials, identity document | HTTP status class only |
| `ld.so.preload` | n/a (the paths are the finding) | up to 20 lines, 256 characters each |

`PADDOCK_COLLECTORS_OFF=accounts,authkeys,...` disables a collector (the section is not sent; absent = Unknown on the
server). `PADDOCK_HASH_USERNAMES=1` replaces non-root, non-uid-0 names with `u:<8 hex of sha256(machine_salt+name)>`
(default off). `PADDOCK_ENABLE_IMDS=1` enables the IMDS probe (E6: off by default). Process memory does see secrets
(shadow hashes, docker `Config.Env`): never log them, never put them in an exception message (error `detail` strings are
fixed text), parse into an allow-list dict and drop the rest at once, and clear the buffers. A test greps every payload
fixture output for the hash substring after the algorithm id and for the `Config.Env` canary.

**Python 3.8 and style.** Stdlib only; `hashlib`, `http.client`, `socket`, `os.open(dir_fd=)`, bounded `re`. Not allowed:
`str.removeprefix`, `X | Y` runtime annotations, `list[str]` in runtime positions, `datetime.fromisoformat('...Z')`,
`ctypes`. The existing AST gate (`tests/collectors/test_py38.py`) and the `python:3.8` CI job apply. Every parser is a
pure function over bytes or text; collectors touch the OS only through `ctx` (add `ctx.open_nofollow`, `ctx.lstat`,
`ctx.unix_http_get` so tests inject fakes).

**Tri-state mapping (as P2).** `ok/exact/partial=false` is the only state that can yield a negative claim (an absence).
`partial=true` means a table is incomplete; `conf=approximate` means something was not understood. Both allow a positive
observation (a violation), never a HOLDS. `unavailable(*)` and `error(*)` are UNKNOWN. Applicability is written in the
predicate (D19); never emit `not_applicable` for a claim that should pass.

### 2.3 Section specs (payload shapes)

All follow `{"s":"ok","v":{...},"conf":..,"partial":..}`. `dropped` is absent unless more than 0.

**`accounts` v1.** Reads `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/login.defs` (`UID_MIN` only),
`/etc/nsswitch.conf` (reuse the sshd `nss_users_unknown` logic). No exec.

```
v = { "source": {"shadow":"read|denied|missing|truncated|error", "group":"read|denied|missing|error",
                 "nss":"files|other|unreadable", "malformed_rows":int, "suspicious_rows":int},
      "count": int,                                  # distinct passwd rows parsed
      "uid0": [{"name":str<=64, "login":bool}],      # <=16, sorted by name; EVERY row with effective uid 0
      "empty_pw": [str<=64], "empty_pw_total": int,  # <=64 sorted names whose effective password is EMPTY; total may exceed the list
      "unknown_pw": int, "hash_in_passwd": int,
      "login_users": [{"name":str<=64,"uid":int,"pw":"hash|locked|empty|unknown"}],   # <=200, login shell, root included, sorted (uid,name)
      "login_dropped": int?,                         # absent unless >0
      "hash_algs": {"yescrypt":n,"sha512":n,"sha256":n,"md5":n,"bcrypt":n,"des":n,"other":n},   # counts only, all 7 keys always
      "groups": {"docker":[str<=64], "sudo":[str<=64]},   # <=64 each; 'sudo' = union of sudo, wheel, admin; members = /etc/group list PLUS accounts whose primary gid is the group's
      "uid_min": int|null }
```

Effective password (glibc rule): the passwd field if it is not `x`, else the shadow field. `""` -> `empty`; first
character `!` or `*` -> `locked` (`!$6$..` is locked-with-hash); `$id$...` -> `hash`; 13 characters of `[./0-9A-Za-z]` ->
`hash` (DES); no shadow row for an `x` account, or any other shape -> `unknown`. Only the algorithm id is read to fill
`hash_algs`; nothing else of a hash survives the function. `partial=true` if `malformed_rows>0`, `suspicious_rows>0`,
`login_dropped`, shadow not `read`, or any list was cut; `conf=approximate` if `nss != files`. `/etc/passwd` unreadable ->
`unavailable(permission_denied)` or `error(exception)`; truncated at 4 MiB -> `error(truncated)`.

Hostile-input rules (each pinned by a fixture; probed against glibc with `getent` and Python `pwd` over a bind-mounted
file):
1. Split on `b"\n"` only, then decode with `errors=replace`. **Never `str.splitlines()`** (it also splits on `\x0b \x0c
   \x1c-\x1e \x85` and U+2028/2029; the existing `sshd.parse_passwd` does, a latent mismatch to note for the sshd owner).
2. A row is never skipped silently. glibc accepts uid fields `+0`, ` 0`, `000`, and short rows (`short:x:0:0:/bin/sh` is
   uid 0), and keeps `\x0b` inside GECOS. The old parse finds only 2 of the 6 uid-0 rows of the probe's `hostile_passwd`;
   the new one must find all 6. Canonical uid = `^(0|[1-9][0-9]{0,9})$`; a non-canonical field that `strtoul` still reads
   as a number is taken as that number AND counted in `suspicious_rows`; a row with other than 7 fields is counted in
   `malformed_rows` and still contributes its uid if readable; a NUL row is `malformed_rows`; `+`/`-` NIS markers are
   `suspicious_rows`. Any positive count makes the section `partial`.
3. Names go through `clean_str(name, 64)`; a name changed by cleaning marks the row suspicious.
4. Caps: file at most 4 MiB (`truncated` then `error`), at most 100000 rows, lists as above.

**`sudo` v1.** Reads `/etc/sudoers`, the `@includedir`/`#includedir`/`@include`/`#include` targets (depth at most 5, files
at most 64, each at most 1 MiB), the `sudoers:` line of `/etc/nsswitch.conf`. Execs: `sudo -V` (first line only) and
`visudo -c` (read-only; its output lists exactly the files sudo parsed, verified on sudo 1.9.15). Never `sudo -l`.

```
v = { "installed": bool,   # false only if no sudo binary in the fixed PATH AND /etc/sudoers ENOENT AND no sudoers.d dir
      "impl":"sudo|sudo-rs|unknown", "version":str|null, "syntax_ok":bool|null,       # visudo -c rc==0; null if visudo is missing
      "files":[{"path":str<=200,"sha256":str|null}],      # <=64, the files that were read
      "visudo_files_match": bool|null,                    # the agent's include resolution == the files visudo -c reported
      "rules":[{"p":[str<=64],"h":"all|other","r":"root|any|other","nopasswd":bool,"cmd_all":bool}],   # <=200; ONLY rules with nopasswd or cmd_all
      "n_rules":int, "n_rules_limited":int,
      "authenticate_off":"none|global|scoped|unknown",    # any `Defaults ... !authenticate`
      "nss_sudoers":bool,                                 # nsswitch 'sudoers:' names a source other than files
      "unparsed":int, "unparsed_reasons":[str] }          # sorted <=16: negation, netgroup, digest, alias_depth, alias_undefined,
                                                          # include_missing, line_too_long, sudo_rs, visudo_mismatch, syntax_error, defaults_unknown_scope
```

Parser rules: join `\`-continued lines; strip comments only where sudoers does (`#` starts a comment except
`#include`/`#includedir`/`#uid`/`#gid`, so `#500 ALL=...` is a user); split on `\n` only; ignore includedir files whose
name contains `.` or ends in `~` (probed), in C-locale lexical order; resolve `User_Alias`, `Runas_Alias`, `Host_Alias`,
`Cmnd_Alias` to depth 3 and 500 entries; tags are inherited along the command list within a rule (`NOPASSWD: a, b,
PASSWD: c`); a command list containing `ALL` (literal or through an alias) sets `cmd_all`. Only `Defaults ...
authenticate` matters; `!authenticate` under any scope sets `authenticate_off`. Anything unclassifiable (negated entries,
`+netgroup`, `sha256:` digests, undefined aliases, over-depth, an unparsable `Defaults` scope) increments `unparsed` with
a reason, and **a line that contains the token `NOPASSWD` or `authenticate` is never silently skipped**. `conf=exact` only
if `unparsed==0`, `syntax_ok==true`, `visudo_files_match==true`, `impl=="sudo"`, `nss_sudoers==false`; a `sudo-rs` host is
`approximate` until its grammar is verified by a fixture. `partial=true` if a file was unreadable or a cap bit.

**`authkeys` v1.** Reads per-user `authorized_keys` for every passwd row with a home and a login shell (root included, at
most 500 users). File names `.ssh/authorized_keys`, `.ssh/authorized_keys2`, plus the sshd collector's
`authorizedkeysfile` list from the same run (tokens `%h %u %U %%` only; any other token, or no sshd value while sshd is
installed, makes `conf=approximate`). `authorizedkeyscommand` set -> `keys_command: true`, approximate.

```
v = { "files":[{"user":str<=64,"n_keys":int,"n_bad":int,"n_ca":int,
                "types":{"ssh-ed25519":n,...},                  # <=8 keys, names from a fixed allow-list else "other"
                "opts":{"command":n,"from":n,"restrict":n,"other":n},   # counts of keys carrying an option class, never text
                "strict_ok":bool,                                # owner is the user or root, no group/world write on file or ~/.ssh
                "fps":["SHA256:<43 base64>"]}],                  # <=50 per user, sorted
      "users_scanned":int, "users_with_keys":int, "total_keys":int, "root_keys":int|null,   # null if /root is unreadable
      "unreadable_homes":int, "keys_command":bool, "dropped":int? }   # files cut past 300 users-with-keys
```

Fingerprint = unpadded base64 of `sha256(blob)` for a valid key (strict base64; the first wire-format string equals the
key type token); anything else is `n_bad`. Comments and option text are never read into the payload. Per line at most 16
KiB, per file 1 MiB, at most 100 keys per file and 2000 total. **Confused-deputy defence** (root reading user-controlled
paths): open the home directory, then `.ssh`, with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` via `dir_fd`, then the file with
`O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`; `fstat` the descriptor and require `S_ISREG` and size at most 1 MiB before reading (a
FIFO or device planted at that name must not block); read with `os.read` in a capped loop. A symlinked file or `.ssh` is
counted in `n_bad`/`unreadable_homes` and not followed. EACCES per home is counted; all homes denied gives
`unavailable(permission_denied)`, some denied gives `partial`.

**`containers` v1.** Only the local Unix socket, only `GET`, never exec, never the `docker` CLI (it honours `DOCKER_HOST`
and `~/.docker/config.json`). Sockets in order: `/run/docker.sock`, `/var/run/docker.sock`, `/run/podman/podman.sock`;
`lstat` first and require `S_ISSOCK`. `http.client.HTTPConnection` subclassed to connect an `AF_UNIX` socket; 5 s per
request; body cap 2 MiB for the list and 256 KiB per inspect. Calls: `GET /containers/json?all=1`, then per container up
to 200 `GET /containers/<id12>/json` for `HostConfig.Privileged`, `PidMode`, `CapAdd`, `SecurityOpt`. The inspect response
carries `Config.Env` and `Cmd` (secrets): the parser takes only allow-listed keys and discards the rest; **never read
`Config`**.

```
v = { "runtime":"none|docker|podman|containerd|crio|multiple|unknown",
      "readable":bool,                                   # list AND every inspect completed through a compat API
      "evidence":{"sockets":[str],"binaries":[str],"procs":[str],"state_dirs":[str]},   # fixed vocabulary, each <=8 of <=64
      "socket":{"path":str|null,"mode":str|null,"uid":int|null,"world_accessible":bool|null},   # lstat of the socket file
      "daemon_tcp":bool|null,                            # dockerd/podman on a non-loopback TCP port, from /proc/net + /proc/<pid>/comm
      "count":int,"running":int,
      "rows":[{"id":str(12 hex),"name":str<=64,"state":"running|restarting|paused|created|exited|dead","image_id":"sha256:<64 hex>"|null,
               "privileged":bool|null,"net_host":bool,"pid_host":bool,"caps_add":[str],"unconfined":bool,
               "mounts":["docker_sock","host_root","etc","proc","sys","dev","root_home","containerd_sock","crio_sock","podman_sock"],
               "n_binds":int,"ports":[{"p":int,"proto":"tcp|udp","ip":str<=45}]}],   # rows sorted by id, <=300; ports <=32
      "dropped":int? }
```

`runtime: "none"` is claimed (conf exact) only if every probe was conclusive (no socket at any of the three paths, no
`docker|dockerd|podman|containerd|crio|crun|runc` binary in the fixed PATH, no such process comm, no `/var/lib/docker`,
`/var/lib/containers`); any EACCES or unreadable `/proc` makes it approximate. A containerd/CRI-O/kubelet node is
`readable:false` (`partial=true`): every container claim is UNKNOWN by design. Engine present but the API failing ->
`error` or `unavailable(daemon_not_running)`. `partial=true` if rows were dropped or any inspect failed. `caps_add` keeps
only a fixed capability vocabulary; other binds are only counted.

**`platform` v1.**

```
v = { "time":{"synced":bool|null,"source":"timedatectl|chronyc|none","daemon":"chronyd|systemd-timesyncd|ntpd|ntpsec|other|none"},
      "provider":{"name":"aws|gcp|azure|oci|digitalocean|vmware|kvm|other|unknown","basis":"dmi"},
      "imds":{"state":"not_probed|v1_open|token_required|unreachable|not_aws|error","probed":bool} }
```

Time: `timedatectl show -p NTPSynchronized -p NTP` (rc 0 and a parsable value); fallback `chronyc tracking` (`Leap status :
Normal`, `Stratum` over 0), integers only, offsets not sent. Neither works -> `synced:null, source:"none"` (the section
stays `ok`, the field Unknown). `NTPSynchronized=yes` means the kernel clock is flagged synchronised by some NTP client,
not that the source is trustworthy nor the offset. Provider: `/sys/class/dmi/id/{sys_vendor,product_name,board_vendor,
bios_vendor,chassis_asset_tag}` (local read); it is host-self-reported, so it only scopes applicability. IMDS probe (opt-in
`PADDOCK_ENABLE_IMDS`) only when the provider is `aws`: a token-less `GET http://169.254.169.254/latest/meta-data/instance-id`
with a 2 s timeout, status only (0 body bytes read), then, only on 401, `PUT /latest/api/token` with TTL 1 to confirm v2
works. 2xx -> `v1_open`; 401 plus a working v2 token -> `token_required`; refused/timeout/other -> `unreachable` (Unknown:
a disabled endpoint cannot be told from a local firewall). Never send credentials or bodies.

**`persistence` v1 (one slice).**

```
v = {"ld_preload":{"present":bool,"entries":[str<=256]},          # <=20 non-comment lines of /etc/ld.so.preload, split on \n only
     "rc_local":{"present":bool,"executable":bool}}
```

Absence is positive evidence only if the stat is ENOENT (not EACCES). Unreadable or over 64 KiB `ld.so.preload` ->
`error(truncated)`. `LD_PRELOAD` in `/etc/environment`, `/etc/ld.so.conf.d` and per-user preload are out of scope and
said so in the std text.

**Listeners v2 (additive).** Per row `euid` (int, from `/proc/<pid>/status` `Uid:` effective) and `user` (str<=32|null,
resolved from `/etc/passwd`; null when unknown or `PADDOCK_HASH_USERNAMES` is on). Server `Listener` gains `euid:
I(0, 2**32) = None` and `user: S(32) = None` (absent allowed, null refused, same trick as `SshdConfig`). Builder
`_compact_listeners` carries `exe_sha256`, `unit`, `user`, `euid` (about 13 KB more at 200 rows).

### 2.4 Server models (`orchestrator/app/fleet_posture.py`, WP8)

`S(n)` clipped printable string of at most n, `I(lo,hi)` strict int, `L(t,n)` list of at most n, `_M` the shared
`extra="forbid"` base; every list cap is a re-check of the agent's.

```python
_PW = Literal["hash", "locked", "empty", "unknown"]
class AcctSource(_M):   shadow: Literal["read","denied","missing","truncated","error"]; group: Literal["read","denied","missing","error"]
                        nss: Literal["files","other","unreadable"]; malformed_rows: I(0,10**6); suspicious_rows: I(0,10**6)
class AcctUid0(_M):     name: S(64); login: StrictBool
class AcctLogin(_M):    name: S(64); uid: I(0,2**32); pw: _PW
class AcctHashAlgs(_M): yescrypt: I(0,10**7); sha512: ...; sha256: ...; md5: ...; bcrypt: ...; des: ...; other: ...
class AcctGroups(_M):   docker: L(S(64),64); sudo: L(S(64),64)
class AccountsV(_M):    source: AcctSource; count: I(0,10**7); uid0: L(AcctUid0,16); empty_pw: L(S(64),64); empty_pw_total: I(0,10**7)
                        unknown_pw: I(0,10**7); hash_in_passwd: I(0,10**7); login_users: L(AcctLogin,200)
                        login_dropped: I(1,10**7) = None      # MAY BE ABSENT, never null, never 0
                        hash_algs: AcctHashAlgs; groups: AcctGroups; uid_min: Optional[I(0,2**32)]

class SudoRule(_M):     p: L(S(64),8); h: Literal["all","other"]; r: Literal["root","any","other"]; nopasswd: StrictBool; cmd_all: StrictBool
class SudoFile(_M):     path: S(200); sha256: Optional[_SHA256]
_SUDO_REASONS = Literal["negation","netgroup","digest","alias_depth","alias_undefined","include_missing","line_too_long",
                        "sudo_rs","visudo_mismatch","syntax_error","defaults_unknown_scope"]
class SudoV(_M):        installed: StrictBool; impl: Literal["sudo","sudo-rs","unknown"]; version: Optional[S(32)]; syntax_ok: Optional[StrictBool]
                        files: L(SudoFile,64); visudo_files_match: Optional[StrictBool]; rules: L(SudoRule,200)
                        n_rules: I(0,10**6); n_rules_limited: I(0,10**6); authenticate_off: Literal["none","global","scoped","unknown"]
                        nss_sudoers: StrictBool; unparsed: I(0,10**6); unparsed_reasons: Annotated[List[_SUDO_REASONS], Field(max_length=16)]

class KeyOpts(_M):      command: I(0,100); from_: I(0,100) (alias "from"); restrict: I(0,100); other: I(0,100)
class KeyFile(_M):      user: S(64); n_keys: I(0,100); n_bad: I(0,10**6); n_ca: I(0,100)
                        types: Annotated[Dict[S(24), I(0,100)], Field(max_length=8)]; opts: KeyOpts; strict_ok: StrictBool
                        fps: L(Annotated[StrictStr, Field(pattern=r"^SHA256:[A-Za-z0-9+/]{43}$")], 50)
class AuthkeysV(_M):    files: L(KeyFile,300); users_scanned: I(0,10**6); users_with_keys: I(0,10**6); total_keys: I(0,10**6)
                        root_keys: Optional[I(0,10**6)]; unreadable_homes: I(0,10**6); keys_command: StrictBool; dropped: I(1,10**7) = None

_MOUNT_VOCAB = Literal["docker_sock","host_root","etc","proc","sys","dev","root_home","containerd_sock","crio_sock","podman_sock"]
class CtrPort(_M):      p: I(0,65535); proto: Literal["tcp","udp"]; ip: S(45)
class CtrRow(_M):       id: Annotated[StrictStr, Field(pattern=r"^[0-9a-f]{12}$")]; name: S(64)
                        state: Literal["running","restarting","paused","created","exited","dead"]
                        image_id: Optional[Annotated[StrictStr, Field(pattern=r"^sha256:[0-9a-f]{64}$")]]
                        privileged: Optional[StrictBool]; net_host: StrictBool; pid_host: StrictBool; caps_add: L(S(32),16)
                        unconfined: StrictBool; mounts: L(_MOUNT_VOCAB,10); n_binds: I(0,10**4); ports: L(CtrPort,32)
class CtrSocket(_M):    path: Optional[S(64)]; mode: Optional[S(5)]; uid: Optional[I(0,2**32)]; world_accessible: Optional[StrictBool]
class CtrEvidence(_M):  sockets: L(S(64),8); binaries: L(S(64),8); procs: L(S(64),8); state_dirs: L(S(64),8)
class ContainersV(_M):  runtime: Literal["none","docker","podman","containerd","crio","multiple","unknown"]; readable: StrictBool
                        evidence: CtrEvidence; socket: CtrSocket; daemon_tcp: Optional[StrictBool]; count: I(0,10**6); running: I(0,10**6)
                        rows: L(CtrRow,300); dropped: I(1,10**7) = None

class PlatTime(_M):     synced: Optional[StrictBool]; source: Literal["timedatectl","chronyc","none"]
                        daemon: Literal["chronyd","systemd-timesyncd","ntpd","ntpsec","other","none"]
class PlatProvider(_M): name: Literal["aws","gcp","azure","oci","digitalocean","vmware","kvm","other","unknown"]; basis: Literal["dmi"]
class PlatImds(_M):     state: Literal["not_probed","v1_open","token_required","unreachable","not_aws","error"]; probed: StrictBool
class PlatformV(_M):    time: PlatTime; provider: PlatProvider; imds: PlatImds
class LdPreload(_M):    present: StrictBool; entries: L(S(256),20)
class RcLocal(_M):      present: StrictBool; executable: StrictBool
class PersistenceV(_M): ld_preload: LdPreload; rc_local: RcLocal

class Sections(_M):     # six new keys, all OPTIONAL: the key may be absent, null is refused
    accounts: _section(AccountsV) = None; sudo: _section(SudoV) = None; authkeys: _section(AuthkeysV) = None
    containers: _section(ContainersV) = None; platform: _section(PlatformV) = None; persistence: _section(PersistenceV) = None
    # existing: sshd, listeners, firewall, patch, self_
class PatchManifest(_M):    # WP8 adds, one wave BEFORE the agent sends it (section 1.5)
    meta: Optional[PatchMeta] = None     # PatchMeta: foreign: L(S(200),500), modular: L(S(200),500), apt_origins: L(S(120),16); absent allowed, null refused
```

Also: `SelfCollectors` six OPTIONAL entries; `Listener` `euid`/`user`; the 256 KiB aggregate check in `validate_posture`;
`accepts` and `known_manifest_sha` on the enroll, heartbeat and posture replies (`routers/fleet.py`).

### 2.5 Builder (`host_fw.py`, WP8) and library fields (`hostfields.py`, WP6)

**Builder.** The `for name in ("sshd","firewall","listeners","patch")` tuple gains the six names; `_COMPACT` gains an entry
for each (a missing function raises `KeyError`, which `_entry` turns into an error entry). Compaction: `accounts` keeps
everything except `login_users` beyond 200; `sudo` keeps `rules`, flags and `files`; `authkeys` flattens to
`files[].user, n_keys, fps` up to a global 500 fingerprints and sets `dropped`/`fingerprints_cut`; `containers` keeps rows
up to 300; `platform` and `persistence` pass through; every entry goes through `_clip` (depth 10, strings 1000, lists
4000). The conflict machinery already flags every collector entry of a host, so the new facts inherit conflict state. **No
new section gets a coverage or edge effect in P2.1** (published container ports are a P2.2 builder input).

**Library fields.** Default usability for every field: fact `signed`, no `conflict`, effective tier at least `min_tier`
(`max_tier` configured), fresh, `status == ok`. **Monotone bool**: the accessor returns `Known(True)` on any observed
violation even when the table is partial or the fact approximate (a positive observation is real and violations win), and
`Known(False)` only when the claim is complete and exact. One helper `_known_if_found(found, complete)` implements it.
Set fields are complete-only (otherwise `Unknown`). An absent key is `Unknown(no_value)`.

| Field | Type | Rule |
|---|---|---|
| `host.accounts.non_root_uid0` | bool, monotone | True if any `uid0` row is not `root`. False iff exact, not partial, `nss=="files"`, `malformed_rows==0`, `suspicious_rows==0`, no non-root row. |
| `host.accounts.uid0_names` | set<str> | complete-only (same completeness as False above). |
| `host.accounts.has_empty_password` | bool, monotone | True if `empty_pw_total>0`. False iff exact, not partial, `shadow=="read"`, `unknown_pw==0`, `malformed_rows==0`. |
| `host.accounts.empty_password_accounts`, `.login_accounts` | set<str> | complete-only; Unknown if cut (`empty_pw_total>len(empty_pw)`, `login_dropped`). |
| `host.accounts.docker_group_members`, `.sudo_group_members` | set<str> | complete-only; need `group=="read"` and `nss=="files"`. |
| `host.sudo.installed` | bool | Known(False) only for an exact fact with `installed:false` (note `basis:sudo_absence_no_binary_no_policy`). |
| `host.sudo.passwordless_all` | bool, monotone | True if a rule with `nopasswd && cmd_all && h=="all" && r in {root,any}` is observed. False iff exact. |
| `host.sudo.nopasswd_all_principals` | set<str> | complete-only (exact). |
| `host.sudo.authenticate_disabled` | bool, monotone | True if `authenticate_off in {global, scoped}`; False iff exact and `"none"`; `unknown` -> Unknown. |
| `host.authkeys.root_key_count`, `.total_keys` | int | Unknown if `root_keys` is null, the fact is partial, or (`total_keys`) `keys_command`. |
| `host.authkeys.fingerprints`, `.users_with_keys` | set<str> | complete-only (no `dropped`, no builder cut). For `subset_of [approved...]`. |
| `host.containers.runtime` | str (choices none, docker, podman, containerd, crio, multiple, unknown) | `need exact=False`. |
| `host.containers.engine_socket_world_accessible` | bool | `runtime=="none"` exact: Known(False). Else needs `socket.world_accessible` non-null. |
| `host.containers.engine_socket_mounted` | bool, monotone | True if any LIVE row (running, restarting, paused) has a `*_sock` mount. False iff `readable`, not partial, exact (or `runtime=="none"` exact). |
| `host.containers.docker_sock_mounted`, `.privileged`, `.host_network`, `.host_pid` | set<str> (`"<id12>:<name>"`) | complete-only; `privileged` needs every row's `privileged` non-null. |
| `host.containers.running_count`, `.image_ids` | int, set<str> | complete-only. |
| `host.platform.time_synchronized` | bool | Unknown when `synced` is null. |
| `host.platform.provider` | str (choices aws, gcp, azure, oci, digitalocean, vmware, kvm, other) | `unknown` -> Unknown. |
| `host.platform.imds_v1_reachable` | bool | True iff `v1_open`; False iff `token_required`; every other state (incl. `not_probed`, `not_aws`) Unknown, so predicates must scope with `provider`. |
| `host.persistence.ld_preload_entries` | set<str> | `present:false` -> Known(empty set) (positive: ENOENT); present -> the entries; a fact with `status != ok` Unknown. |
| `host.listener.user`, `.exe_sha256`, `.unit` (param port) | set<str> | same completeness as `host.listener.process`: complete table, attribution ok, non-null in every row at that port. |

Test helpers `accounts()`, `sudo()`, `containers()`, `platform()` go into `assurance/tests/hostfix.py`.

### 2.6 Six std invariants (`stdlib/*.yaml`; each digest pinned in `test_stdlib_host.py`)

Common: `apiVersion: paddock.dev/invariant/v1`, `subjects.to: { tag: [agent, server] }`, `evidence: { min_tier:
configured, max_age: 6h }`, `coverage: { require: 1.0 }` (an estate that includes a host whose agent lacks the collector
reads UNKNOWN: E5, intended). Shipping an invariant does not change how a tenant enables it. `description` is the
operator-facing text and must state both what HOLDS means and what it does not cover.

| id | severity | assert | Description must say |
|---|---|---|---|
| `std:server-single-uid0` | high | `host.accounts.non_root_uid0 == false` | counts uid 0 as glibc reads it (`+0`, ` 0`, `000`, a short row, a row hidden behind a control character); HOLDS = no counterexample in `/etc/passwd` of a host whose account sources are files only and whose rows were all understood; says nothing about LDAP/sssd/NIS (UNKNOWN), a second user holding root through sudo or setuid, a compromised agent; a violation is reported even when other rows were not understood |
| `std:server-no-empty-passwords` | high | `host.accounts.has_empty_password == false` | effective password (passwd field, or shadow when `x`); locked accounts (`!`, `!!`, `*`) pass; hashes never leave the host; UNKNOWN when shadow is unreadable, an account is unclassified or accounts come from non-file sources; stricter than PAM `nullok`/`PermitEmptyPasswords` on purpose |
| `std:server-no-passwordless-sudo` | medium | `any: [host.sudo.installed == false, all: [host.sudo.passwordless_all == false, host.sudo.authenticate_disabled == false]]` | no NOPASSWD rule for ALL commands and no `Defaults !authenticate` in any scope, sudoers read the way sudo reads them (includes, and the file list matches `visudo -c`); stock cloud images (`ubuntu`, `ec2-user`, `admin`) ship such a rule, so expect findings; not covered: polkit, doas, sssd/LDAP sudoers (UNKNOWN), a NOPASSWD grant for one command that gives a shell, sudo-rs (UNKNOWN until verified) |
| `std:server-container-engine-not-exposed` | high | `all: [host.containers.engine_socket_world_accessible == false, host.containers.engine_socket_mounted == false]` | no LIVE container bind-mounts the engine socket (docker, podman, containerd, CRI-O) and the socket file is not world accessible; a host with no runtime passes on positive evidence; Kubernetes/containerd/CRI-O nodes and rootless podman are UNKNOWN; not covered: stopped containers, a TCP-exposed daemon, docker-group membership, other escapes (privileged, host pid, host root mount); monitoring agents often mount `docker.sock` on purpose, so copy this into a custom invariant that names them |
| `std:server-time-synchronized` | low | `host.platform.time_synchronized == true` | the kernel reports the clock disciplined by an NTP client at collection time; says nothing about the source, trust or offset; a root attacker can set the flag; hosts without systemd or chrony tooling are UNKNOWN, not failing |
| `std:server-no-ld-preload` | high | `count(host.persistence.ld_preload_entries) == 0` | `/etc/ld.so.preload` absent or empty at collection; not covered: `LD_PRELOAD` in a service environment, per-user startup files, `ld.so.conf.d`, static binaries, kernel-level hiding; not malware detection; a legitimate entry (some security products) is a finding to accept per host |

Not shipped: `std:server-imdsv2-required` (`any: [host.platform.provider != "aws", host.platform.imds_v1_reachable ==
false]`). The probe is opt-in (E6), so a default fleet would read UNKNOWN on every AWS host under coverage 1.0; the
authoritative source is `MetadataOptions.HttpTokens` from the cloud connector (not collected anywhere in the repo today).
The fields ship now, the std invariant ships with that cloud-API read (P2.2). The std count becomes 6 + 3 + 6 = 15.

### 2.7 Deferred, with reasons

* **FIM (baseline plus diff).** A baseline kept on the host is rewritable by the root being checked; a server baseline
  needs an operator route, a migration and an acknowledge flow (the machinery D now builds); legitimate updates change
  the set constantly, so without governance it is permanently VIOLATED or noisy. P2.2 with the ack route.
* **SUID/SGID inventory.** An unbounded filesystem walk on hostile trees; a verdict needs a baseline or a `dpkg -S`/`rpm -qf`
  per file. If revived: bounded roots, local filesystems only, 60 s and 3 M entry caps, `os.nice`, `partial` on any cap.
* **Enabled units, cron and timers drift.** No baseline-free judgement; without a baseline it is inventory, not assurance.
* **Disk encryption.** Absence of dm-crypt inside a VM is not evidence of an unencrypted volume (provider-level EBS/PD
  encryption is invisible); the cloud API is the source.
* **auditd/journald.** `auditctl -s` needs `CAP_AUDIT_CONTROL`, which the bounding set deliberately lacks; "a process named
  auditd exists" is not "auditing enabled with rules loaded".
* **Containers on Kubernetes/containerd/CRI-O**, **egress baseline**: gRPC is not stdlib-feasible; the egress baseline has
  the same baseline-governance problem as FIM.

## 3. Section C: `.deb` and `.rpm` packaging, signing and the repository layout

All paths relative to the repo. Scratchpad prototypes (`proto/ustar.py`, `proto/mkdeb2.py`, `proto/common.sh`,
`proto/{preinst,postinst,prerm,postrm}`, `rpmprobe/top/SPECS/paddock-agent.spec`) are references, not code to ship as is.

### 3.1 Facts from the repo that drive the design

`agent/packaging/build_zipapp.py` writes a deterministic stored-zip `.pyz` (shebang `#!/usr/bin/env python3`, release
builds `SOURCE_DATE_EPOCH=315532800`). `scripts/install-agent.sh` installs to `/usr/local/lib/paddock-agent/`, writes the
unit to `/etc/systemd/system`, writes the wrapper `/usr/local/bin/paddock` (never over a foreign `paddock`, pkg-8),
enrolls with the token on stdin, and enables and restarts only when enrolled. The repo unit is pinned by a test to the
installer's `emit_unit` output. The agent CLI's argparse `prog` is `paddock` and the Paddock CLI also ships `paddock`. The
daemon falls back to `creds.server` when `PADDOCK_SERVER` is unset, so a package install needs no `PADDOCK_SERVER` in
`agent.env` after `enroll --server URL`. `.github/workflows/release.yml` is the existing trust path: the `gate` job runs
in the `release` environment, every action is pinned by SHA, cosign v2.5.2 is installed exactly 3 times (a test asserts
3), `agent` and `images` have `needs: gate`, the `release` job signs IMAGE_DIGESTS and the SBOM sums and builds the body
from `out/SHA256SUMS`. A running agent breaks if its zipapp is replaced underneath it (a lazy import afterwards fails
with `bad local file header`, reproduced), so **the package must stop the service before unpacking and restart it after**.

### 3.2 One layout, two builders (`agent/packaging/pkgcommon.py`)

`Layout` = an ordered list of `(path, kind, mode, bytes)` plus version and interpreter; both builders consume it, so a
test asserts deb payload paths equal rpm `%files`. Inputs: the already built `paddock-agent.pyz` (never rebuilt inside the
package builder), the repo unit, the repo `LICENSE`. Owner `root:root`, constant mtime 315532800.

| Path | Mode | Notes |
|---|---|---|
| `/usr/lib/paddock-agent/paddock-agent.pyz` | 0644 | bytes identical to the release asset |
| `/usr/bin/paddock-agent` | 0755 | wrapper: `#!/bin/sh`, then `exec '/usr/bin/python3' '/usr/lib/paddock-agent/paddock-agent.pyz' "$@"` (fixed absolute interpreter, no PATH lookup) |
| `/usr/lib/systemd/system/paddock-agent.service` | 0644 | the repo unit with exactly one line replaced (`ExecStart=<PYTHON> /usr/lib/paddock-agent/paddock-agent.pyz run`); the builder asserts exactly one replacement; not a conffile (drop-ins in `paddock-agent.service.d/` override) |
| `/etc/paddock-agent/` | 0700 dir | |
| `/etc/paddock-agent/agent.env` | 0600 | deb conffile; rpm `%config(noreplace)`; a commented template with no secrets and no required setting, warning never to put a token or `PADDOCK_OPERATOR_TOKEN` there |
| `/usr/share/doc/paddock-agent/` | | `copyright` (DEP-5 with the full AGPL text inline), `changelog.Debian.gz` (stored gzip, date from the epoch), README |
| `/usr/share/man/man1/paddock-agent.1.gz` | | optional, generated deterministically from `cli.build_parser().format_help()` |

**Versions.** Tag `v0.2.0` -> deb `0.2.0-1`, rpm Version `0.2.0` Release `1`; `v0.3.0-rc1` -> `0.3.0~rc1`. The revision is
always 1 (a packaging-only fix needs a new tag). A mismatch between the tag and `paddock_agent.__version__` is a CI
warning and a release-notes line, not a failure (D22 reasoning: a hard lockstep would block releases in which the agent
did not change). **Arch**: deb `all`, rpm `noarch`. **Interpreter**: `--python` defaults to `/usr/bin/python3`; deb
`Depends: python3 (>= 3.8)`, rpm `Requires: python3 >= 3.8` (RHEL 8 python3 is 3.6, so the rpm fails dependency
resolution: fail safe; EL8 users run `install-agent.sh --python /usr/bin/python3.9`). deb fields: `Section: admin`,
`Priority: optional`, `Homepage`, `Maintainer` (D25), `Installed-Size` as the ceiling of summed KiB, `Recommends: systemd`,
`Suggests: python3-cryptography` (constant-time Ed25519, optional per owner decision O1; not Recommends), no `Conflicts` or
`Provides`.

### 3.3 The `.deb` builder (`build_deb.py`, `archive.py`, `check_deb.py`)

`build_deb.py --pyz dist/paddock-agent.pyz --tag v0.2.0 --out pkg-dist [--python] [--revision 1] [--maintainer]
[--source-date-epoch 315532800]`; output `paddock-agent_0.2.0-1_all.deb`; Python 3.8-compatible, stdlib only, no network.

* **ar**: `!<arch>\n`, members `debian-binary` (`2.0\n`), `control.tar.gz`, `data.tar.gz` in that order; mtime the epoch,
  uid and gid 0, mode 100644, odd sizes padded with `\n`.
* **tar**: a hand-written POSIX ustar writer, **not `tarfile`** (probed: stdlib `tarfile` gives different bytes on 3.8 and
  3.13; the hand-written writer gave one sha256 for the whole `.deb` on 3.8, 3.11, 3.12 and 3.13): explicit 512-byte
  headers, uid=gid=0, uname=gname=`root`, magic `ustar\0`, version `00`; long paths split into prefix and name; dirs end in
  `/`; names start with `./`; entries sorted with directories as entries; padded to 10240; no symlinks or hardlinks.
* **gzip**: hand-assembled from STORED deflate blocks (fixed header, mtime 0, OS 3; crc32 and isize trailer); no zlib
  deflate, so no zlib-version dependence (the zipapp's own rule); about +290 KB per package. No xz or zstd.
* **control.tar**: `./`, `conffiles` (exactly `/etc/paddock-agent/agent.env`), `control`, `md5sums` (every non-conffile),
  `preinst`, `postinst`, `prerm`, `postrm` (0755). No `templates`/`config` (no debconf).
* **`check_deb.py`** (a lintian-style pure-Python reader over the built bytes): ar layout and order; control field syntax
  (no trailing whitespace, synopsis under 80 characters); md5sums match; every tar entry uid/gid 0, root/root, no
  setuid/setgid, mode in the allowed set, path under `./` with no `..`, sorted; maintainer scripts start `#!/bin/sh`, contain
  `set -e`, mode 0755, `dash -n` clean (when dash exists), `shellcheck -s sh` clean (when present), no bashisms (`[[`,
  `$'`, `source `, `==` in `[`, arrays, `function `); and **no `curl|wget`, no `fet_`, no `TOKEN`, no `enroll` call, no
  `systemctl enable`/`deb-systemd-helper enable`/`--now`, `rm -rf` only inside the guarded purge branch.**

### 3.4 Maintainer scripts (one shared helper block, `agent/packaging/pkg/common.sh`)

Inlined into every script. Helpers: `PKG_ROOT` is `${DPKG_ROOT:-}` with `/` treated as empty (staged install, tests; when
non-empty nothing outside it is touched and systemd is invoked only through `PADDOCK_PKG_TEST_SYSTEMCTL`, honoured only
when `PKG_ROOT` is non-empty); `pk_systemctl` returns 0 silently when `/run/systemd/system` is absent (container builds,
chroots); `pk_secure_dir DIR MODE` refuses a symlink or non-directory, creates with `mkdir -p -m`, refuses a directory not
owned by the installing uid, then chmods (failure exits 1 and aborts configuration: the fail-safe); `pk_enrolled` is
`[ -f $STATE_DIR/credentials.json ]` only (never read); `pk_refuse_script_install` fails if
`/usr/local/lib/paddock-agent/paddock-agent.pyz` or `/etc/systemd/system/paddock-agent.service` exists (a same-named unit
in `/etc` overrides the package unit; message: `sh install-agent.sh --uninstall` keeps keys and credentials, then retry);
`pk_stop_for_upgrade` (if active: create `/run/paddock-agent.was-active`, `systemctl stop`);
`pk_restart_after_upgrade` (if the marker is a regular non-symlink file: delete it, `systemctl restart`).

| Script | Behaviour |
|---|---|
| deb `preinst` (`install\|upgrade`) | `pk_refuse_script_install`; on `upgrade`: `pk_stop_for_upgrade` (the NEW package's script, so it does not depend on the old version's) |
| deb `postinst configure` | `pk_secure_dir` on `/var/lib/paddock-agent` and `/etc/paddock-agent` (0700); `daemon-reload`; first install (`$2` empty): print the next steps only (`printf %s "$TOKEN" \| sudo paddock-agent --server https://YOUR-PADDOCK enroll --token-stdin`, then `sudo systemctl enable --now paddock-agent`); else `pk_restart_after_upgrade`. **Never enables, never starts a fresh install, never reads, prints or stores a token.** |
| deb `prerm remove\|deconfigure` | stop, then `disable`; not on `upgrade` |
| deb `postrm` | `remove`: `daemon-reload` only (state and conffile kept). `purge`: `daemon-reload`; if `/var/lib/paddock-agent/purge-on-package-purge` is a regular file (not a symlink) inside a non-symlink state dir, `rm -rf -- $STATE_DIR` and say so, else print "kept /var/lib/paddock-agent (signing key and credentials); create <marker> before purging, or delete by hand"; `rmdir /etc/paddock-agent`; always print "the agent is still registered on the server: revoke it in Paddock" |
| rpm `%pre` | `$1` 1 install, 2 upgrade: `pk_refuse_script_install`; if 2, `pk_stop_for_upgrade` |
| rpm `%post` | `pk_secure_dir`, `daemon-reload`; `$1`=1 next steps, `$1`=2 `pk_restart_after_upgrade`. **No `%systemd_post`** (it runs `systemctl preset`, which can enable on some distros) |
| rpm `%preun` (`$1`=0) | stop and `disable` |
| rpm `%postun` (`$1`=0) | `daemon-reload` and an informational "kept /var/lib/paddock-agent"; rpm has no purge, erase never deletes state, the docs give the manual `rm -rf` |

Upgrade and downgrade take identical paths (a downgrade across a state-format or wire change is unsupported and the docs
say so). A deliberately stopped agent stays stopped (the marker exists only if it was active). The marker file is the
explicit purge config because an environment variable does not reliably survive apt and sudo. Probe results with real
`dpkg --root=R --force-script-chrootless --force-depends` (dash, stub systemctl) cover first install, upgrade while active,
downgrade while inactive, refusal over a script install, remove, purge with and without the marker, and a symlinked state
dir (section 8 turns them into tests).

### 3.5 The `.rpm` (`build_rpm.py`): spec generation plus `rpmbuild`

No pure-Python rpm writer (D23). `build_rpm.py` writes the stage tree from the same `Layout`, generates `paddock-agent.spec`
from a template and optionally runs `rpmbuild -bb --nodeps` with a temp `_topdir`, `SOURCE_DATE_EPOCH=315532800` and the
payload from `%{_sourcedir}/root` (no `%prep`/`%build` fetch, no build-time network). Header defines (verified with rpmbuild
4.18): `%define _buildhost paddock-release`, `source_date_epoch_from_changelog 0`, `use_source_date_epoch_as_buildtime 1`,
`clamp_mtime_to_source_date_epoch 1`, `build_mtime_policy clamp_to_source_date_epoch`, `_binary_payload w9.gzdio`,
`_binary_filedigest_algorithm 8`, `_build_id_links none`, `%global debug_package %{nil}`, `__brp_mangle_shebangs %{nil}`
(Fedora/EL `redhat-rpm-config` would rewrite the pyz shebang and break byte identity with `SHA256SUMS`),
`__os_install_post %{nil}`, `AutoReqProv: no` plus an explicit `Requires: python3 >= 3.8`. `%files` uses explicit `%attr`
(`%dir %attr(0700,root,root) /etc/paddock-agent`, `%config(noreplace) %attr(0600,...) agent.env`, the pyz 0644, `%license`),
one `%changelog` entry dated `Tue Jan 01 1980`. Reproducibility is claimed **only for the same rpm version** (the release
notes record `rpmbuild --version`; the probe gave one sha256 across TZ, umask 077, touched stage files and another topdir).

### 3.6 Signing (D24)

* **deb**: apt verifies the repository, not each `.deb`: sign `dists/stable/InRelease` (clearsigned) and `Release.gpg`
  (detached, armored). No `debsigs` (nothing on a stock host verifies it). Each release also gets detached `.asc` files for
  the `.deb` and `.rpm`.
* **rpm**: dnf checks per-package signatures, so `rpmsign --addsign` is required (it changes the file bytes, so it runs
  BEFORE digests are computed); `repodata/repomd.xml.asc` supports `repo_gpgcheck=1`.
* **Key**: RSA 4096 (works on old gpgv, EL8 rpm and FIPS EL9; Ed25519 does not everywhere); an offline cert-only primary
  with a signing subkey (2-year expiry); only `gpg --export-secret-subkeys` goes to CI. Secrets of the `release`
  environment: `PADDOCK_PKG_GPG_KEY` (armored subkey), `PADDOCK_PKG_GPG_PASSPHRASE`; variable `PADDOCK_PKG_GPG_FPR`; any job
  that reads them declares `environment: release`. The job imports into an ephemeral `GNUPGHOME` made with a SHORT path
  (`mktemp -d /tmp/g.XXXX`: gpg-agent sockets fail on long paths, which broke the first probe), refuses to sign if the
  imported primary fingerprint differs from `PADDOCK_PKG_GPG_FPR`, passes the passphrase through stdin
  (`--pinentry-mode loopback --passphrase-fd 0`, never argv), deletes the home on exit, then verifies InRelease and the rpms
  against the committed public key `docs/trust/paddock-archive-keyring.asc` (written by the owner, public only; the builder
  never creates it). **No key, no repository**: without the secrets the job skips GPG, the repo tree and the rpm signature,
  and the release carries only unsigned packages covered by the cosign-signed `PACKAGE_SHA256SUMS`; the docs say those need
  manual verification. A test greps `agent/packaging`, `.github/workflows` and `docs` for `PRIVATE KEY`.
* **cosign keyless**: `PACKAGE_SHA256SUMS` (digests of the `.deb`, `.rpm`, `.asc` files, SBOMs and the public key) is generated
  and signed in the existing `release` job (cosign is already installed there; the installer count stays 3) and produces
  `PACKAGE_SHA256SUMS.sigstore.json`. It is **not** folded into `SHA256SUMS`.
* **Provenance**: `actions/attest-build-provenance` (the same pinned SHA as `release.yml`, `e8998f949152b193b063cb0ec769d69d929409be`)
  over the packages and `actions/attest-sbom` (v2.4.0 `bd218ad0dbcb3e146bd073d1d9c6d78e08aa8a0b`, looked up with `git
  ls-remote`) once per package; `gh attestation verify <file> --repo OWNER/REPO`.

### 3.7 Repository layout (`build_repo.py`)

```
apt/pool/main/p/paddock-agent/paddock-agent_X-1_all.deb
apt/dists/stable/main/binary-{all,amd64,arm64,armhf,i386,ppc64el,riscv64,s390x}/Packages and Packages.gz
apt/dists/stable/Release, Release.gpg, InRelease
yum/paddock-agent-X-1.noarch.rpm   yum/repodata/* (+ repomd.xml.asc)   yum/paddock.repo
paddock-archive.gpg (binary keyring for apt signed-by)   paddock-archive.asc
```

apt: a pure-Python `Packages` writer takes the control fields from the `.deb` and adds `Filename`, `Size`, `MD5sum`, `SHA1`,
`SHA256`; `Packages.gz` is stored gzip (deterministic); `Release` has Origin, Label, Suite and Codename `stable`, `Date`
(passed in, so a pure function of its inputs), `Architectures: all amd64 arm64 armhf i386 ppc64el riscv64 s390x`,
Components `main`, SHA256 of every index; `Valid-Until` off by default and settable with `--valid-until` (without it a stale
mirror is accepted: the freeze-attack gap, documented); `--existing DIR` keeps older pool entries installable. Probe: apt
2.8.4 accepted this layout against a `file://` source with `signed-by=<keyring>`. yum: `createrepo_c --update --checksum
sha256 yum/` (CI only), `gpg --detach-sign --armor repodata/repomd.xml`; `paddock.repo` has `gpgcheck=1`,
`repo_gpgcheck=1`, `gpgkey=<host>/paddock-archive.asc`; a flat noarch repo serves any architecture. **Hosting**: always
attach `paddock-agent-repo-X.tar.gz` to the release; an opt-in `publish-repo` job (`needs: packages`, only when
`vars.PACKAGES_PUBLISH == 'true'` and the key exists, `environment: release`, `contents: write`) commits the tree to an
orphan `packages` branch with `GITHUB_TOKEN`; the owner enables Pages from that branch (safe while docs Pages deployment
stays off).

### 3.8 SBOM, release notes, workflows

* `agent/packaging/sbom.py`: a deterministic SPDX 2.3 JSON per package (created = the epoch; `documentNamespace` a URL with
  the sha256 of the sorted payload manifest; `paddock-agent` with versionInfo, supplier, `downloadLocation` the tag
  archive, `licenseDeclared AGPL-3.0-only`, `filesAnalyzed true`, a package verification code, purl
  `pkg:generic/paddock-agent@X`; every payload file with SHA1 and SHA256; `python3 >= 3.8` as a runtime dependency with
  NOASSERTION; an explicit "no third-party code bundled; stdlib only; the vendored RFC 8032 signer is in-tree"). Not syft
  (it reads installed-package databases and would find nothing in a stage tree). CI validates with `pyspdxtools -i`.
  CycloneDX is deferred.
* `agent/packaging/render_release_notes.py` produces the "## Host agent packages" section: file names, the
  `PACKAGE_SHA256SUMS` block, the `rpmbuild --version`, and the verification commands: `cosign verify-blob` on
  `PACKAGE_SHA256SUMS`; `gh attestation verify`; for the deb `dpkg-deb --fsys-tarfile X.deb | tar -xO
  ./usr/lib/paddock-agent/paddock-agent.pyz | sha256sum` (must equal the `paddock-agent.pyz` line of `SHA256SUMS`); for the
  rpm `rpm -qp --dump X.rpm | grep paddock-agent.pyz`. It repeats the existing caveat that digests in notes are not
  independent of the release.
* `release.yml` (WP16): a new job `packages` (`needs: [gate, agent]`, `environment: release`, permissions `contents:
  read`, `id-token: write`, `attestations: write`): checkout, setup-python 3.12, download `release-agent-pyz`,
  `apt-get install rpm createrepo-c lintian`, build deb and rpm, `check_deb.py` and `build_rpm.py --check`, lintian
  (`--fail-on error`), container smoke tests (`debian:12` and `ubuntu:22.04` install the deb and run `paddock-agent
  --version`; `rockylinux:9` and `fedora` install the rpm), signing if the secrets exist, SBOMs, attestations, upload
  `release-agent-packages` and `repo-agent`. The `release` job gains `needs: [gate, images, agent, packages]`, the
  `PACKAGE_SHA256SUMS` signing, the notes section and the new globs. Existing pinned tests keep holding: `needs` starting
  with `gate`, every `uses:` a 40-hex SHA, exactly 3 cosign-installer steps. `ci.yml` (WP16): a job `agent-packages` in
  `container: debian:12` (root) installing `dpkg-dev python3-pytest gnupg rpm shellcheck lintian` and running `pytest -q
  agent/packaging/tests` so the dpkg `--root`, apt `file://` and rpmbuild tests run for real; `agent-py38` keeps the
  stdlib-only parts on 3.8.

### 3.9 Installer, agent source, docs

* `scripts/install-agent.sh` (WP14): in the real-run path and the dry-run plan, if `$ROOT/usr/lib/paddock-agent/paddock-agent.pyz`
  exists, die with "the agent is installed from a package: upgrade it with apt/dnf, or remove the package first (state is
  kept)"; header comment mentions the package path; shellcheck covers the new lines.
* `agent/paddock_agent/platform_block.py` (WP14): `DEFAULT_PROTECTED` gains `/usr/lib/paddock-agent`,
  `/usr/bin/paddock-agent`, `/usr/lib/systemd/system/paddock-agent.service`, `/etc/systemd/system/paddock-agent.service`,
  so `quarantine_file` can never move the agent's own files; a test pins it.
* Docs (WP16): `AGENT_V2.md` section 2.1 "Install from a package" (apt and dnf flows with fingerprint pinning, upgrade,
  remove and purge semantics, migration from the script installer, the EL8 limitation, a cloud-init example that says
  user-data stays on the instance so use a short-TTL `max_uses` token; deliberately **no `curl | sh` one-liner**, the token
  needs stdin), `FLEET_WIRING.md` section 3, `agent/README.md`, `docs/trust/VERIFY.md` (a package-verification section),
  `PROVABLE_CONTAINMENT_MVP.md` 6.5 is updated by WP17 (deb/rpm and cloud-init done; Terraform and Ansible still open).
  These docs are pinned by tests in `agent/packaging/tests/test_installer_p2x*.py` and `agent/tests/test_p2x_agent_r3.py`:
  rerun them after every edit.

## 4. Section D: the identity trust root (pairing and conflict acknowledgement)

### 4.1 Why, and what a pairing does and does not attest

As built in P2, `_ipmap.PRIVATE_PEER_IS_PROOF` is `False`, so `corroborate()` never merges: every agent is node
`agent:<uuid>`, basis `claimed` (P2 11 items 2, 3 and 9; 13.7 owner decisions 2 and 3). An instance that runs an agent has
two nodes (`asset:<uuid>` with no host facts and `agent:<uuid>` with them), so reach and exposure invariants read the
instance UNKNOWN; zone placement rests on two unverified hints; and the external-scan cross-check
(`host_fw._scan_conflicts`, "mine" = the agent ref, `ip:<claimed>`) can only match scan edges resolved to the agent's
CLAIMED addresses.

A pairing attests: *agent row A is the machine that is cloud asset X*, asserted by an admin with a justification. It
changes **identity only**: node ref, node addresses, zone source, which edges and coverage the facts attach to. It does
**not**: lift a tier (E2), bypass any P2 gate, or hide conflicts. A compromised host that really is X can still sign
lies (P2 11 item 1, unchanged); what pairing removes is the route "rogue host Y borrows X", because Y cannot make an
admin pair its agent id.

### 4.2 Schema: `schema/045_agent_identity.sql` (WP0; runs before 099, which adds RLS)

```sql
CREATE TABLE IF NOT EXISTS fleet_agent_pairings (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  agent_id        UUID NOT NULL REFERENCES fleet_agents(id) ON DELETE CASCADE,
  asset_id        UUID NOT NULL DEFAULT gen_random_uuid(),   -- assets.id; NO FK on purpose: a deleted asset makes the pairing inert, not erased
  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','ended')),
  justification   TEXT NOT NULL DEFAULT '',                  -- >= 3 characters enforced by the app (a length CHECK would break the sweep default)
  paired_by       TEXT NOT NULL DEFAULT '', paired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  asset_canonical TEXT NOT NULL DEFAULT '',                  -- ARN snapshot for the audit trail
  checks          JSONB NOT NULL DEFAULT '{}'::jsonb,        -- what the server compared at pairing time
  ended_at TIMESTAMPTZ, ended_by TEXT, ended_reason TEXT NOT NULL DEFAULT '',   -- unpaired | agent_revoked | rekeyed | superseded
  CONSTRAINT fleet_agent_pairings_end_chk CHECK ((status = 'ended') = (ended_at IS NOT NULL)));
CREATE UNIQUE INDEX IF NOT EXISTS uq_pairing_active_agent ON fleet_agent_pairings (tenant_id, agent_id) WHERE status = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS uq_pairing_active_asset ON fleet_agent_pairings (tenant_id, asset_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_pairing_agent ON fleet_agent_pairings (tenant_id, agent_id, paired_at DESC);
-- a ledger: rows are never deleted or re-pointed; only status / ended_* change.

CREATE TABLE IF NOT EXISTS fleet_conflict_acks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
  agent_id UUID NOT NULL REFERENCES fleet_agents(id) ON DELETE CASCADE,
  kind  TEXT NOT NULL DEFAULT 'agent_closed_scan_open' CHECK (kind IN ('agent_closed_scan_open')),
  proto TEXT NOT NULL DEFAULT 'tcp' CHECK (proto IN ('tcp','udp')),      -- conflicts are expanded per proto ('any' scan edges -> tcp+udp)
  port  INTEGER NOT NULL DEFAULT 1 CHECK (port BETWEEN 1 AND 65535),
  through_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),                    -- the newest scan observation of this (proto, port) the operator looked at
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','cleared','superseded','expired')),
  justification TEXT NOT NULL DEFAULT '', acked_by TEXT NOT NULL DEFAULT '', acked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days',
  cleared_by TEXT, cleared_at TIMESTAMPTZ, cleared_reason TEXT NOT NULL DEFAULT '',
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb);                          -- the conflict record as shown to the operator
CREATE UNIQUE INDEX IF NOT EXISTS uq_conflict_ack_active ON fleet_conflict_acks (tenant_id, agent_id, kind, proto, port) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_conflict_ack_agent ON fleet_conflict_acks (tenant_id, agent_id, status, expires_at);
```

No data backfill. No `auth_lookup` policy: both tables are only read inside a tenant context.

### 4.3 Routes and RBAC (handlers thin in `routers/fleet.py`; logic in the new `app/fleet_pairing.py`)

Same style as `fleet_posture.revoke_agent`: one transaction, lock order = agent row `FOR UPDATE` first, then pairing rows,
`audit.record(..., con=con)` inside the transaction, `retry_on_deadlock`. Capability names are those of
`auth.required_capability` (`read`, `triage`, `admin`). Unmatched mutating methods already default to `admin`, but **every
rule below is added explicitly by WP0** and pinned by a test (a GET without an explicit rule would be `read`).

| Route | Capability | Notes |
|---|---|---|
| `PUT /v1/fleet/agents/{agent_id}/pairing` | admin; `billing_gate.require_paid("assurance")` | body `PairingIn`; 200 `PairingOut`; idempotent for the same asset (`changed=false`) |
| `DELETE /v1/fleet/agents/{agent_id}/pairing?justification=` | admin; **never** billing-gated | justification at least 3 characters is a REQUIRED query parameter (foreign and random ids both 422 identically); 200 `PairingOut(status='ended')` |
| `GET /v1/fleet/agents/{agent_id}/pairing` | triage | reveals asset addresses and the operator justification; 200 or 404 when never paired |
| `GET /v1/fleet/agents/{agent_id}/pairing/candidates` | triage | read-only helper: up to 20 VM assets (`cloud_resource`, resource type instance/virtual_machine/vm/compute_instance, `last_seen` inside the asset max age) whose private/public ips intersect the agent's claimed ips, each with the `checks` block; creates nothing |
| `GET /v1/fleet/pairings?status=active\|ended&asset_id=&limit=&offset=` | triage | the ledger |
| `GET /v1/fleet/agents/{agent_id}/conflicts` | triage | current conflicts of the agent's node (from `reach_node_facts` source `host_fw`, `facts->'host_agent'->'data'->'conflicts'`) joined with acks; the response says `as_of` (fact `observed_at`) and the graph build time |
| `POST /v1/fleet/agents/{agent_id}/conflicts/acks` | admin | body `ConflictAckIn`; 201 `ConflictAckOut` |
| `DELETE /v1/fleet/agents/{agent_id}/conflicts/acks/{ack_id}?justification=` | admin | 200 `ConflictAckOut(status='cleared')`; the conflict is back from the next build |

No four-eyes (D26). The asset lookup uses the same clearance filter as `/v1/assets`: a hidden asset answers exactly like a
missing one (404 `{"detail":"asset not found"}`), so the route is not an existence oracle across clearance or tenants
(`test_api_isolation_sweep` calls GET/PUT/DELETE with foreign ids and compares bodies with a random id).

Pydantic (all `extra="forbid"`):

```python
class PairingIn(BaseModel):      asset_id: UUID; justification: str (min 3, max 1000, stripped); acknowledge_mismatch: bool = False
class PairingChecks(BaseModel):  claimed_ips: list[str]; asset_ips: list[str]; claimed_subset: bool|None; observed_peer: str|None
                                 peer_direct: bool; peer_in_asset: bool|None; asset_kind: str; asset_last_seen: datetime|None
class PairingEffective(BaseModel): node_ref: str; basis: Literal['paired','claimed']
                                 state: Literal['active','inert_asset_missing','inert_asset_stale','inert_asset_not_vm','inert_agent_not_live','peer_mismatch']; note: str
class PairingOut(BaseModel):     id: UUID; agent_id: UUID; asset_id: UUID; asset_canonical: str; status: Literal['active','ended']
                                 justification: str; paired_by: str; paired_at: datetime; ended_at/ended_by/ended_reason
                                 checks: PairingChecks; effective: PairingEffective; changed: bool
class ConflictAckIn(BaseModel):  kind: Literal['agent_closed_scan_open'] = 'agent_closed_scan_open'; proto: Literal['tcp','udp']
                                 port: int (1..65535); scan_seen_at: datetime   # echo of the observation the operator looked at
                                 justification: str (min 10, max 1000); ttl_hours: int = 168 (1..720)
class ConflictAckOut(BaseModel): id, agent_id, kind, proto, port, through_seen_at, status, justification, acked_by, acked_at, expires_at, cleared_by, cleared_at, cleared_reason
class ConflictOut(BaseModel):    kind: str; proto: str; port: int; scan_seen_at: datetime; ackable: bool; ack: ConflictAckOut|None
```

`AgentOut` gains `paired_asset_id: UUID|None`; `AgentDetailOut` gains `pairing: PairingOut|None` (the viewer-safe subset: no
justification, no addresses). The generated files are regenerated in WP4.

### 4.4 `PUT /pairing` algorithm (one transaction)

1. `SELECT id, status, revoked_at, legacy, identity, node_ref FROM fleet_agents WHERE id=$1 FOR UPDATE`: 404 (generic) if
   absent; 409 `agent_not_live` if revoked or legacy; 409 `agent_has_no_active_key` when no `fleet_agent_keys` row has
   `status='active'` (a pairing is meaningless for an agent that cannot sign).
2. Asset: `SELECT id, kind, canonical, last_seen, metadata FROM assets WHERE id=$2` (clearance-filtered) -> 404 `asset not
   found`. Require `kind='cloud_resource'` and `_ipmap.node_kind(...) == 'cloud_instance'` else 422 `asset_not_a_vm`;
   require `last_seen >= now - assurance_pairing_asset_max_age_h` (72 h) else 409 `asset_stale`.
3. An existing active pairing of this agent: same asset -> 200 `changed=false`; another asset -> 409 `agent_already_paired`
   `{asset_id}`. An existing active pairing of this asset by another agent -> 409 `asset_already_paired` `{agent_id}`
   (`uq_pairing_active_asset` makes two agents on one asset impossible; a `UniqueViolation` from a race maps to the same
   409). To move: DELETE then PUT (explicit; no silent replace).
4. Checks: `claimed = _ipmap.claimed_ips(identity)`; `asset_ips` = the union of the asset's private and public ips
   (metadata `private_ips`, `public_ips`, `ips`, `ip` via `_ipmap._ips_in`); `claimed_subset = claimed <= asset_ips` (None
   when no claim); `observed_peer` from `identity.peer_ip` with `identity.peer_proxied is False` (direct);
   `peer_in_asset` = peer in `asset_ips` when the peer is private and direct, else None. If `claimed_subset` is False (or
   `peer_in_asset` is False) and not `acknowledge_mismatch` -> 409 `identity_claims_disagree` with the checks (an
   operator-mistake guard, NOT a proof); with the flag the pairing is stored with `checks.acknowledged_mismatch=true`.
5. Insert the pairing; `UPDATE fleet_agents SET node_ref='asset:<id>', identity=jsonb_set(jsonb_set(identity,'{basis}','"paired"'),'{note}','""')`;
   `finding_follow.migrate_targets(con, {'agent:<id>': 'asset:<id>'})` (host-config findings keep their id, SLA clock and
   tickets); `fleet_posture.invalidate_assurance(con)`; `audit.record(action='fleet.pairing.create', resource_type='fleet_agent',
   details={asset_id, asset_canonical, justification, checks, acknowledge_mismatch}, con=con)`.

`DELETE`: `UPDATE ... SET status='ended', ended_at=NOW(), ended_by, ended_reason='unpaired' WHERE agent_id=$1 AND
status='active' RETURNING asset_id` (404 `no active pairing` otherwise); `node_ref` back to `agent:<id>`, basis `claimed`;
`migrate_targets({'asset:<id>': 'agent:<id>'})`; invalidate; audit `fleet.pairing.end`.

**Cascades (same transactions as the existing code).** `fleet_posture.revoke_agent`: after the agent row lock, end the
pairing (`ended_reason='agent_revoked'`) and clear its acks (`status='cleared', cleared_reason='agent_revoked'`); leave
`fleet_agents.node_ref` as `asset:X` so `TOMBSTONES_SQL` (it matches `target_ref IN ('agent:'||id, a.node_ref)`) keeps the
finding's tombstone on `asset:X`; a live agent that later decides the same node wins (existing `host_fw._tombstones`
rule). `fleet_enroll._rekey` (it already resets `node_ref` to `agent:<id>` and identity to claimed but moves no findings and
ends no pairing): the same two UPDATEs (`ended_reason='rekeyed'`) plus `migrate_targets({old node_ref: 'agent:<id>'})`,
because a re-key token can rebind the row to a different host. A signed key ROTATION (continuity of the old key) keeps the
pairing. A deleted agent row cascades.

### 4.5 What the builder does with a pairing

A pure function in `builders/_ipmap.py` (shared by ingest and builder so they cannot diverge, the same principle as
`corroborate`):

```python
@dataclass(frozen=True) class PairingRow: agent_id; pairing_id; asset_ref; node_kind; asset_ips: tuple[str,...]; asset_last_seen: Optional[datetime]
Decision gains defaults basis: str = 'claimed', conflict: str = ''           # Decision(ref, note, basis, conflict)
def pairing_decision(claim, row, now, max_age, peer_shared) -> Decision:
    no row                              -> Decision(None, '')                        # falls through to corroborate(), which stays inert
    row.node_kind != 'cloud_instance'   -> Decision(None, 'pairing_inert:asset_not_vm')
    asset missing (LEFT JOIN null)      -> Decision(None, 'pairing_inert:asset_missing')
    asset_last_seen older than max_age  -> Decision(None, 'pairing_inert:asset_stale')
    else  Decision(row.asset_ref, '', basis='paired', conflict=peer_conflict)
    peer_conflict = 'paired_peer_mismatch' iff claim.direct and claim.peer is private (not is_public_ip) and not peer_shared and claim.peer not in asset_ips, else ''
```

Loader: `host_fw.PAIRINGS_SQL = SELECT p.id AS pairing_id, p.agent_id, p.asset_id, a.id AS a_id, a.kind, a.last_seen,
jsonb_build_object('resource_type',a.metadata->'resource_type','private_ips',...) AS md FROM fleet_agent_pairings p LEFT JOIN
assets a ON a.id = p.asset_id WHERE p.status='active'`; `HostFwRows.pairings`; `_resolve_identities(agents, amap,
pairings, now)` applies `pairing_decision` first and `corroborate` second. For a paired agent: ref `asset:X`, basis
`paired`, **`node_ips` = the asset's ips only** (never the host's claimed ips), `addressable` True if any asset ip is
public, claimed kept for display; no `NodeOut` is emitted for it (the asset node comes from `aws_sg` or the loader's
default-kind path: `graph_loader._asset_ids` derives the asset id from any `asset:` ref, so zone and addresses resolve
from asset metadata). Effects (each a one-line change, each tested):

1. **Facts** attach to `asset:X` (source `host_fw`); the loader auto-tags the node `agent`, so the std host invariants
   judge it once the operator (or a connector) labels it `server`.
2. **Coverage `in`** (tier configured, source `host_fw`) lands on `asset:X` NEXT TO `aws_sg`'s `in` coverage (different
   source). The union is sound: a connection must pass BOTH the security group and the host firewall, so each complete
   source is an upper bound; edges from both sources are drawn (more edges, never fewer; the cost is precision, not
   soundness). This removes P2's "instance node has no host facts" blind spot.
3. **Zone** resolves from the cloud asset's addresses against declared zone CIDRs, independent of the host's claim (a
   declared label still wins): closes P2 11 item 3 for paired hosts.
4. **Cross-validation gets stronger**: `_scan_conflicts` "mine" now includes `asset:X`, so `external_exposure`'s scan edges
   (internet -> `asset:X` for the instance's public IP) are compared with the agent's model.
5. `paired_peer_mismatch` is emitted as a conflict entry `{kind, proto:'any', port:0, scan_seen_at: observed}` on every
   collector entry: no coverage, UNKNOWN, **not acknowledgeable**.
6. **Inert fallback**: any `pairing_inert` state returns the agent to `agent:<uuid>`/`claimed` with the note
   `pairing_inert:<why>` (`identity_note` of the `host_agent` fact): never silently dropped, never auto-ended.
7. Two agents on one asset is impossible (unique index); a rogue second agent that merely CLAIMS the asset's addresses
   stays `agent:<uuid>` and does not demote the paired one (claims never own addresses: the existing rule).

**Ingest mirror**: `fleet_posture._resolve_node` reads the active pairing (one SELECT joined to assets) and calls
`pairing_decision`; only then `corroborate()`. A new `fleet_pairing.reconcile(con, now)` runs in `runner.build_tenant`
BEFORE the builders (tenant context): it marks expired acks `expired`, and for each active pairing whose effective state
differs from `fleet_agents.node_ref`/`identity.basis` it updates the columns, calls `finding_follow.migrate_targets` and
writes one audit row `fleet.pairing.inert` or `fleet.pairing.restored` per transition. The builder never writes.

**An asset that disappears.** `assets` rows persist after a connector stops seeing an instance (terminated instances are
skipped; `last_seen` just stops advancing): `last_seen` older than 72 h -> `inert_asset_stale`; row gone ->
`inert_asset_missing`; resource type changed -> `inert_asset_not_vm`. A replaced instance (new ARN, new asset uuid) goes
stale and the operator re-pairs. Autoscaled and golden-image fleets cannot use pairing (one asset, one agent); they rely
on declared zone labels and `agent:` nodes, and `AGENT_V2.md` says so.

### 4.6 Scan-conflict acknowledgement

The P2 conflict `agent_closed_scan_open`: the external scan saw `(proto, port)` open on the node inside the external window
(`assurance_external_max_age_h`, 168 h) and the agent models it closed (exact firewall, complete listener table). It is
sticky and clears only on a later completed full-port TCP scan that started after the last observation, or when the
observation ages out; UDP and `any` observations are never cleared by a scan.

**What an ack clears: only that conflict record, for coverage purposes** (the node may get `in` coverage again if every
other gate passes). It never changes a verdict directly, never changes a tier, never touches another conflict kind
(`agent_scan_check_budget_exceeded` and `paired_peer_mismatch` give 422 `not_ackable`).

Binding: `(agent_id, kind, proto, port, through_seen_at)`. `POST` requires the conflict to be present in the node's CURRENT
facts and `scan_seen_at` to equal the observation shown (409 `no_such_conflict` / `conflict_changed`), so a blind pre-ack is
impossible. The builder computes conflicts exactly as today, then partitions: a conflict is acknowledged iff an ACTIVE ack
exists with the same proto and port, `ack.expires_at > now` and `c.scan_seen_at <= ack.through_seen_at`. A LATER
observation is not covered: the conflict is re-raised with the new timestamp. Default expiry 168 h, maximum 720 h
(`assurance_conflict_ack_max_h`); `reconcile` sets `expired`; a re-ack supersedes the previous active row; revoke and
re-key clear acks; `DELETE` clears at once.

**Disclosure (nothing silent).** The `host_agent` fact's `data` gains `conflicts_acknowledged: [{kind, proto, port,
scan_seen_at, ack_id, acked_by, expires_at}]` (`store.digest_view` ignores the `*_at` keys inside it, as it does for
`data.conflicts`); the coverage detail gains `acknowledged_conflicts: n` (visible in `/v1/assurance/coverage`); every ack
and clear is an audit row (`fleet.conflict.ack`, `fleet.conflict.ack_clear`) with the justification and the conflict
record. P3 must count acknowledged conflicts like it counts `exceptions`. Builder: `HostFwRows.acks` (`ACKS_SQL = SELECT id,
agent_id, kind, proto, port, through_seen_at, expires_at, acked_by FROM fleet_conflict_acks WHERE status='active' AND
expires_at > $1`); `_agent_out` calls a pure `_apply_acks(conflicts, acks_of_agent, now) -> (open, acked)` right after
`_scan_conflicts`; the coverage gate sees only `open`.

## 5. Section E: cloud ENI coverage (builders-7)

### 5.1 The exact false-HOLDS mechanism (reproduced: `probe_builders7.py` prints HOLDS)

1. `aws_sg.add_source`, `stype == 'sg'`: when the referenced SG is synced AND has at least one MODELLED member
   (instance/db/lb in `self.members`) it draws edges ONLY from those members and sets `net=None`: no world edge. Only
   "zero modelled members" widens to world-open (`unmodeled_sg_members`).
2. `process()` still asserts direction `in` coverage for the destination because ITS OWN security groups are complete.
3. The evaluator's unknown-edge rule invents an unknown edge `u -> v` only between nodes IN THE GRAPH with `u` blind outbound
   and `v` blind inbound. The destination is covered inbound, so nothing is added; an ENI that is not a node cannot be added.
4. So a Lambda (VPC), Fargate task, EKS pod ENI, VPC interface endpoint, ElastiCache/OpenSearch node or EFS target in the
   referenced SG (also in another world-open SG we do not model for it) can reach the database over the SG rule, but no
   node, edge or unknown edge represents it: `std:no-internet-to-datastore` reads HOLDS. Same hole when a
   `DescribeInstances` page fails (`connector._pages` swallows errors into warnings and returns a PARTIAL list).

**Builder contract rule (new, written into the `aws_sg` docstring and ASSURANCE_P1 section 12):** *every set-valued source
must denote its COMPLETE membership or add a residual node.* Anything that is not a node is invisible to the evaluator;
soundness lives in the builders.

### 5.2 The fix: a residual node and an edge, proven away only by a complete inventory

* `refs.py`: `KINDS += ('estate',)`, `_PREFIXES += ('estate',)`, `estate_ref(account, region, vpc)` ->
  `estate:<12-digit account>:<region>:<vpc-id|none>` (validated, canonical, at most 128 characters); `parse_ref` and
  `is_valid_ref` support it. `store.py` kind validation accepts it.
* `aws_sg._Sg` gains `vpc_id`, `eni_inventory`, `eni_members` (read from the SG asset metadata). For a rule whose source
  type is `sg` and whose key is in `self.sgs`:
  ```
  residual = membership_unproven(sg, modelled_members_of_sg)
  if residual: add_edge(src=estate_ref(dst.account, dst.region, sg.vpc_id), dst, rule, flags={'unmodeled_members'}, lists={'via_sg': gid})
               register node estate (NodeOut kind 'estate', attrs {account_id, region, vpc_id, sgs:[...]})
  membership_unproven = NOT ( eni_inventory.complete is True and read_at fresh (the SG's last_seen within 1 h of read_at)
                              and eni_members.truncated is False
                              and every instance id in eni_members.instances is a modelled member of THIS SG
                              and every lb name in eni_members.lbs matches a modelled cloud_lb member
                              and eni_members.unmodeled.count == 0 )
  ```
  The existing "no modelled member -> world-open" behaviour stays for an UNSYNCED or cross-account SG; for a synced SG
  with zero modelled members and a complete inventory, the estate edge replaces world-open (narrower, still sound). Never
  both for one rule.
* The estate node never gets coverage in either direction, so unknown edges `internet -> estate` and `modelled-blind ->
  estate` exist and `estate -> dst` is a known configured edge: the verdict is UNKNOWN `possible_via_unknown_edges` with a
  readable witness `internet -(unknown)-> estate:... -(configured)-> db` (`probe_estate_fix.py`). `graph_loader` emits
  estate nodes `zone_unknown: true` (they may sit in any declared zone CIDR) and skips them in CIDR expansion (zone
  invariants then also read UNKNOWN: `probe_estate_zone.py`). The library adds `estate` to `evaluate.PSEUDO_KINDS` (not
  coverable, outside the coverage universe); without it the node only lowers the relevant ratio. **After that change the
  probe must still give UNKNOWN with the same witness** (a pinned regression test; section 8).
* **No operator override label** (D31). Remedies for the operator: grant `ec2:DescribeNetworkInterfaces`, move
  non-modelled services to their own SG, or add a time-boxed `allow:` exception on the invariant (existing, audited).

### 5.3 The AWS connector change (`integrations/connectors/aws.py`, WP2)

Today: DescribeRegions, DescribeSecurityGroups (ingress only; `normalize_ingress` -> `metadata.ingress_rules`,
`ingress_truncated`), DescribeInstances (instance ENIs only), ELB/ELBv2, RDS `DescribeDBInstances`, IAM, S3, Route53. Not
read: DescribeNetworkInterfaces, DescribeVpcs, NACLs, route tables, egress rules, Lambda/ECS/EKS/endpoints. The metadata
upsert is a SHALLOW merge, so a failed read must overwrite stale fields explicitly.

In `_region()`, after instances/SGs and LBs: `eni = self._pages_ok(st, f'ec2:DescribeNetworkInterfaces[{region}]', ec2,
'describe_network_interfaces', 'NetworkInterfaces')` returning `(items, ok)` (`_pages_ok` sits next to `_pages` and
records `st.region_ok[region]=False` when ANY page fails). Classify each ENI: `instance` (`Attachment.InstanceId` in
`st.instances`), `lb` (`Description` `ELB app/<name>/..`, `ELB net/<name>/..` or `ELB <name>` with `<name>` among the LBs
just described), else by `InterfaceType`/`RequesterId`/`Description`: `lambda`, `ecs` (description starts `arn:aws:ecs`),
`rds` (`RDSNetworkInterface`, treated as UNMODELLED on purpose, D32), `vpce` (`InterfaceType vpc_endpoint`),
`nat_gateway`, `other`; status `available` (detached) counts as a member. Per SG accumulate `instances` (cap 512 ids,
sorted), `lbs` (cap 128 names), `unmodeled {count, kinds{kind:n}, sample[<=10 {id, kind, public}]}`, `truncated`.
`_security_group_findings` writes into each SG asset `md['eni_inventory'] = {'complete': ok, 'read_at': iso, 'region',
'eni_total': n}` and `md['eni_members'] = {...}` (or `{}` with `complete: False` when the read failed or AccessDenied, so
a stale `complete: true` is always overwritten). The same pull sets `md['inventory_complete'] = False` on SG and instance
assets of a region whose DescribeInstances/DescribeSecurityGroups paging failed, and `aws_sg` treats such a node as blind
(withdraws coverage): this closes the partial-page variant. IAM: add `ec2:DescribeNetworkInterfaces` to
`docs/INTEGRATIONS-CONTEXT.md` (list near lines 191 to 193) and the connector's least-privilege doc and test; AccessDenied
degrades to `complete=False` plus a `st.warnings` entry and the `aws_sg` note `N SG(s) referenced by rules have
unenumerated members (ENI inventory missing)` so the cause is obvious.

**Staged scope.** P2.1 ships the estate residual and the ENI inventory (the completeness proof). Per-ENI nodes
(`cloud_eni` with their own SG coverage, so Lambda/Fargate become precise) are P2.2 and not needed for soundness. The ENI
inventory is a point-in-time read: an interface created after the sync and placed in a referenced SG is invisible until
the next pull; the exposure is bounded by evidence `max_age` (24 h for the std reach invariants) and equals the existing
limit for SG rule edits.

## 6. Section F: lifecycle residuals

### 6.1 runner-4: disabled and deleted invariants (WP3; schema in `046_assurance_lifecycle.sql`, WP0)

Today `PUT enabled=false` and `DELETE` both set `enabled=false` (`routers/assurance.py` `put_invariant`/`delete_invariant`);
the runner selects `WHERE enabled`, so findings of such invariants are never touched again (correct: closing would be a
false verification) but are indistinguishable from live ones. **Annotate, never close (D33).**

```sql
ALTER TABLE invariants ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ, ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ,
                       ADD COLUMN IF NOT EXISTS disabled_by TEXT;
-- backfill: disabled_at = updated_at WHERE NOT enabled (per-tenant loop with set_config('app.tenant_id'), as 041/042 do)
CREATE INDEX IF NOT EXISTS idx_findings_invariant_state ON findings ((metadata->>'invariant_state'))
  WHERE rule_source='invariant' AND metadata ? 'invariant_state';
```

State machine: `active --PUT enabled=false--> disabled (disabled_at, disabled_by)`; `active|disabled --DELETE--> archived
(archived_at, enabled=false)`; `disabled|archived --PUT enabled=true--> active` (clears the timestamps,
`last_graph_version=NULL` as today). Runner-detected states: `invalid_definition` (compile failure, already UNKNOWN) and
`not_entitled` (`runner._entitled` false). In the same transaction as the toggle:

```sql
UPDATE findings f SET metadata = f.metadata || jsonb_build_object('invariant_state', $state, 'invariant_state_at', to_jsonb(now()))
  FROM invariants i WHERE i.id=$1 AND f.rule_source='invariant' AND f.status IN ('open','triaged')
   AND (f.rule_id = 'invariant:'||i.invariant_id OR starts_with(f.rule_id,'invariant:'||i.invariant_id||'@'));
```

On re-enable: `metadata = metadata - 'invariant_state' - 'invariant_state_at'` for the same selector. `bulk_upsert` merges
metadata with `||`, so the annotation survives refreshes. A runner housekeeping step `reconcile_orphans` (once per tick
per tenant, idempotent) repairs drift for `invalid_definition`/`not_entitled` and for std invariants toggled elsewhere.
Invariants that must hold (tests): no `findings_sync` path closes a finding whose invariant is not enabled; disabling never
changes finding status; re-enabling re-evaluates first and the ordinary rules decide.

New route `POST /v1/invariants/{invariant_id}/findings/release` (**admin**, never billing-gated), body `{justification:
str(10..1000)}`: allowed only when the invariant is NOT active (409 `invariant_active` otherwise); sets `status='wontfix'`,
`status_reason='invariant <state>: <justification>'`, `status_by`, `status_changed_at`, leaves `fix_verified_at` NULL,
writes `lifecycle.record_history` per row and one audit row; returns `{released: n}`. It is a human decision, not a
verification; a later re-enable does NOT reopen it (the machine never undoes `wontfix`; operators `PATCH` to reopen).
`GET /v1/invariants/{id}` gains `state`, `open_findings`, `findings_not_rechecked`.

### 6.2 `invariant_runs` retention (WP3; DDL in 046)

Rows are written on verdict/digest change or once a day per invariant (`runner._record`, `HEARTBEAT=1d`) and carry the full
`compact_result` JSON (witnesses, up to 200 blind spots, up to 5000+5000 target refs, `passing_targets` up to 5000), up to
MBs per row; nothing deletes them (P1 12). Policy:

* **Compact** rows older than `assurance_runs_compact_days` (30): keep invariant, digest, verdict, reasons, `evaluated_at`,
  `valid_until`, `evidence_tier`, coverage, `violation_count`, `graph_version`, `doc_sha`, assertion, the first 5
  witnesses and `blind_spot_summary`; drop `violating_targets`, `unproven_targets`, `passing_targets`, `blind_spots`,
  `boundaries_reached` and exception detail; set `compacted_at`.
* **Delete** rows older than `RETENTION_INVARIANT_RUNS_DAYS` (365; `<=0` keeps all) EXCEPT the newest row of each
  `(tenant, invariant)` (so "since when" always has an anchor) and EXCEPT rows with `pinned`.

```sql
ALTER TABLE invariant_runs ADD COLUMN IF NOT EXISTS compacted_at TIMESTAMPTZ, ADD COLUMN IF NOT EXISTS pinned BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_invariant_runs_evaluated ON invariant_runs (tenant_id, evaluated_at);
CREATE INDEX IF NOT EXISTS idx_invariant_runs_uncompacted ON invariant_runs (tenant_id, evaluated_at) WHERE compacted_at IS NULL;
```

Delete: `retention.configured_policies()` gains `Policy('invariant_runs','evaluated_at', _env_days('RETENTION_INVARIANT_RUNS_DAYS',
365), where="NOT pinned AND EXISTS (SELECT 1 FROM invariant_runs n WHERE n.invariant_id = invariant_runs.invariant_id AND
n.tenant_id = invariant_runs.tenant_id AND n.evaluated_at > invariant_runs.evaluated_at)")` (the existing `_purge_one` runs
per tenant under RLS; the correlated reference is valid inside its `SELECT ctid FROM "invariant_runs"` subquery; add the
table to the retention docstring; WP0). Compaction: a new `app/assurance/housekeeping.py` `compact_runs(con, days, batch)`:
a bounded `UPDATE ... WHERE compacted_at IS NULL AND NOT pinned AND evaluated_at < now() - make_interval(days=>$1) AND id IN
(SELECT id ... LIMIT $2)` building the result from `result->'key'` plus the first 5 of `result->'witnesses'`; called per
tenant from `scheduler.py` next to `run_retention` (same advisory-lock pattern); one audit row per tenant per run only
when `n > 0`. `pinned` is unused until P3 attestations reference run ids.

### 6.3 The spoofable leftmost `X-Forwarded-For` (WP0)

`auth.client_ip()` returns the LEFTMOST entry when the socket peer is in `TRUSTED_PROXY_CIDRS` (default `127.0.0.1/32,
::1/128`; Helm default empty). A proxy that appends (nginx, ALB) leaves client-written entries in front, so the leftmost
is attacker-chosen: forged audit ip, per-IP limiter bypass or evasion, victim lockout via login/enroll keys.
`auth.client_ip_strict` (Nth from the RIGHT, `TRUSTED_PROXY_HOPS`, all header lines joined, fail closed; returns the
`ClientAddr` str subclass) already exists. There are 24 call sites (`auth.py` public limiter and the per-request audit ip,
`routers/auth.py` login lockout key, `routers/sso.py` x2, `routers/scim.py`, `routers/sensors.py` via `_client_ip`,
`routers/ingest.py`, `routers/integrations_inbound.py`, `growth/trust.py` x2, `growth/exposure.py` x2, `routers/msp.py`
x10, `routers/fleet.py` revoke audits; fleet enroll is already strict).

Fix, in one function, no per-site edits: `def client_ip(request): return client_ip_strict(request)`, cached on
`request.state.client_addr` (computed once per request and used by the middleware audit and the handlers). `ClientAddr`
is a plain `str`, so every limiter, audit row and JSON consumer is unchanged; the audit row gains `details.ip_proxied=true`
when `ClientAddr.proxied`. A WARNING log when `TRUSTED_PROXY_CIDRS` is non-empty and an incoming chain is shorter than
`TRUSTED_PROXY_HOPS` (a misconfiguration signal; it fails closed to the peer address = a shared limiter bucket,
availability only). Docs (WP17): `GROWTH.md`, `OPERATIONS.md` and the Helm values comment: list ingress addresses ONLY and
set `trustedProxyHops` to the number of APPENDING proxies. The test that pins the old behaviour
(`tests/test_hardening_units.py::test_xff_honoured_from_trusted_proxy`, `'198.51.100.4, 10.0.0.1'` -> `'198.51.100.4'`) is
rewritten (new expectation `'10.0.0.1'`, the client-written prefix is ignored; the comment says why). A static guard test:
no module under `app/` applies `.split(',')[0]` to an `x-forwarded-for` header outside `auth.py`. Sensors keep their own
`X-Sensor-Client-IP` (service principal only), unchanged.

### 6.4 An invalid `assert:` hides other schema errors (WP1)

Reproduced: `severity: urgent` with `assert: nonsense` yields only `(document): Value error, assert: position 8 ...`; with
`assert: unreachable` the severity error appears. Cause: `Invariant._host_assert` is a `mode='before'` model validator that
RAISES on `X.ExprError`; pydantic aborts the model, no field validator runs, and the message is labelled `(document): Value
error, `. Fix (D36): `parse_invariant` passes `context={'assert_problems': []}` to `Invariant.model_validate`. `_host_assert(cls,
data, info)` on `ExprError` (or the bad-type branch) appends `('assert', message)` to `info.context['assert_problems']`
when a context exists (else raises exactly as today) and returns `data` with `assert` replaced by the placeholder
`covered` so field validation continues; `_shape(self, info)` returns early when the context holds an assert problem (so the
placeholder adds no bogus "covered needs subjects.to" noise). `parse_invariant` then raises `ParseError` with `problems =
['assert: <msg>'] + the field errors` (loc-prefixed, `Value error, ` stripped for this one); if the model validated but an
assert problem exists, it raises with just that. **The placeholder path never yields an `Invariant`**; digests of VALID
documents are unchanged. `compile.py`: `_compile_host` collects every leaf whose `min_tier` exceeds the field's reachable
tier into one `CompileError` message list. `orchestrator/tests/test_assurance_api.py` (the `assert: nonsense` case near line
155) is updated to expect both problems when both are wrong.

### 6.5 Sensor scope declaration (WP3)

Today: `PUT /v1/assurance/sensor-scopes/{sensor_uuid} {cidrs (<=64, canonical, /0 refused), justification}` (admin, paid),
`DELETE ?justification=`, `GET` lists scopes plus active sensors without one (table `sensor_scopes`, schema 040).
`sentry_flows` gives `observed` coverage only to a node whose EVERY address is inside a declared scope of an online sensor
that sighted it; a sensor with no scope covers nothing. Gaps: the sensor reports interface names and MACs only, no CLI
helper exists, nothing tells the operator what to declare, a scope wider than reality is accepted silently.

1. `GET` items gain `observed {prefixes:[<=32 IPv4 /24 prefixes seen as flow src or dst by THIS sensor in the last 7 d with
   counts and last_seen], truncated}`, `declared_but_unobserved` (declared CIDRs with no observed address inside),
   `observed_outside_scope`, `suggested_cidrs` (the /24s merged to at most 16 supernets no shorter than /16). SQL over
   `reach_flow_obs` (has `sensor_id`): `WITH ends AS (SELECT sensor_id, src_ip AS ip, last_seen FROM reach_flow_obs WHERE
   last_seen >= $1 AND src_ip ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' UNION ALL SELECT sensor_id, dst_ip, last_seen FROM
   reach_flow_obs WHERE last_seen >= $1 AND dst_ip ~ <same>) SELECT sensor_id, host(set_masklen(ip::inet,24)) || '/24' AS
   prefix, count(*) AS flows, max(last_seen) AS last_seen FROM ends GROUP BY 1,2 ORDER BY flows DESC LIMIT 2000`
   (`reach_flow_obs` keeps a bounded window; the response says which window it saw).
2. `PUT` refuses prefixes shorter than /16 (IPv4) or /48 (IPv6) unless `allow_wide=true` AND `justification` is at least 20
   characters (422 `scope_too_wide`), recorded in the audit details; the response gains `warnings: [...]` (a declared CIDR
   with no flows from this sensor in 7 d; a scope declared on an offline or revoked sensor).
3. `GET /v1/sensors` rows gain `scope_declared: bool` (WP3 owns `routers/sensors.py`); the existing state note "N sensors
   have no declared scope" is left as it is (no builder change).
4. CLI (`cli/paddock_cli`, stdlib only, `PADDOCK_API_KEY` from the environment like `upload.py`, never on argv): `paddock
   assurance scopes list|suggest <sensor>|set <sensor> --cidr C ... --why TEXT [--allow-wide]|clear <sensor> --why TEXT`.
5. The declared scope stays an accountability record (`set_by`, `justification`, `set_at`); the docs say observed
   coverage proves "no such traffic seen", not "impossible".

## 7. Work packages, file ownership and waves

**Rules.** (1) Ownership is per wave: a file may be owned by several packages, never by two packages of the same wave; a
later owner lists the earlier one in `depends_on`. (2) At most **two** packages run concurrently, so the 18 packages form
nine waves. (3) A package's own gates (section 8.1) are green before its wave ends; the wave after starts from a green
tree. (4) A package that adds or changes a route or a response model regenerates the three generated files in the same
change (`python scripts/export_openapi.py && python sdk/python/codegen.py && node sdk/typescript/scripts/codegen.mjs`;
CI runs them with `--check`); no wave has two such packages. (5) `auth.py`, `config.py`, `retention.py`, the three
migrations, `test_isolation_sweep.py` and `test_isolation_keys.py` belong to **WP0 only**; WP0 adds every RBAC rule and
setting for routes later packages implement (a rule for a route that does not exist yet is harmless and is pinned by
`test_p21_rbac.py`, which calls `required_capability` directly). (6) No package edits `dashboard/` (P6). (7) Doc files
are owned like code files; the doc-pinned tests (`-k "doc or pkg9 or readiness"`, the agent suite and
`agent/packaging/tests`) are rerun by the owner after every doc edit.

| Wave | WP | Scope | Owns (files) | depends_on |
|---|---|---|---|---|
| 1 | **WP0 SEAM** | schema 044/045/046; `client_ip` strict; all RBAC rules; all settings; retention policies; sweep allow-list | `schema/044_advisories.sql`, `045_agent_identity.sql`, `046_assurance_lifecycle.sql`; `orchestrator/app/{auth,config,retention}.py`; `orchestrator/tests/{test_isolation_sweep,test_isolation_keys,test_migrate,test_hardening_units,test_retention}*.py`; new `tests/test_p21_rbac.py`, `tests/test_p21_schema.py` | none |
| 1 | **WP1 LIB-CORE** | invalid-assert collection (F4), collect all compile errors, `estate` pseudo kind, library 0.4.0 | `assurance/paddock_assurance/{model,parse,compile,evaluate,__init__}.py` (evaluate: `PSEUDO_KINDS` only); `assurance/tests/test_parse_collect.py`, `test_estate_pseudo.py` (new) and the existing parse/compile tests; `orchestrator/tests/test_assurance_api.py` | none |
| 2 | **WP2 ESTATE-AWS** | builders-7: estate node and edge, ENI read, completeness proof; dependency pin | `orchestrator/app/assurance/{refs,graph_loader,store}.py`; `builders/aws_sg.py`; `orchestrator/app/integrations/connectors/aws.py`; the orchestrator's `paddock-assurance>=0.4.0` pin; `docs/INTEGRATIONS-CONTEXT.md`; `tests/test_assurance_aws_builders7.py`, `test_aws_connector.py`, `test_assurance_refs*.py` | WP1 |
| 2 | **WP3 LIFECYCLE** | runner-4 annotation and release route, `invariant_runs` compaction, sensor-scope advisories and CLI | `orchestrator/app/routers/assurance.py`; `app/assurance/{runner,housekeeping}.py`; `app/scheduler.py`; `app/routers/sensors.py`; `cli/paddock_cli/**`, `cli/tests/**`; `tests/test_assurance_lifecycle.py`, `test_assurance_runs_retention.py`, `test_assurance_sensor_scope.py`; generated files | WP0 |
| 3 | **WP4 TRUST-ROOT** | pairing and conflict acknowledgement: module, routes, builder, cascades | `orchestrator/app/fleet_pairing.py` (new); `app/routers/fleet.py`; `app/fleet_posture.py` (`_resolve_node`, `revoke_agent`); `app/fleet_enroll.py`; `app/assurance/builders/{_ipmap,host_fw}.py`; `app/assurance/{store,runner}.py`; `tests/test_fleet_pairing*.py`, `test_fleet_conflict_ack.py`, `test_assurance_host_fw_pairing.py`; generated files | WP0, WP2, WP3 |
| 3 | **WP5 VULNMATCH-LIB** | the pure matcher: version comparators, model, match, scopes, leaf | `assurance/paddock_assurance/vulnmatch/**`; `assurance/tests/{test_vercmp,test_vulnmatch}.py`; `assurance/tests/fixtures/vulnmatch/**` | none |
| 4 | **WP6 HOSTCFG-LIB** | six std invariants and the new field accessors | `assurance/paddock_assurance/{hostfields.py,render.py,stdlib/server-*.yaml}`; `assurance/tests/{hostfix,oracle_host,test_hostfields*,test_stdlib_host,test_hostmutation,test_hostoracle}.py`; `assurance/examples/**` | WP1 |
| 4 | **WP7 AGENT-IDENT** | agent seam (registry, budgets, off switch, `accepts`), `accounts`, `sudo`, `authkeys`, unit `ProtectHome=read-only` | `agent/paddock_agent/{collectors/{__init__,health,accounts,sudo,authkeys}.py,runner.py,config.py,agent.py}`; `agent/systemd/paddock-agent.service`; `scripts/install-agent.sh` (unit heredoc); `docs/AGENT_V2.md` (section 3 only); `agent/PAYLOAD.md`; `agent/tests/**` for these | none |
| 5 | **WP8 SERVER-B** | server models for the six sections, `accepts` and `known_manifest_sha` replies, `PatchManifest.meta`, `host_fw` compaction | `orchestrator/app/fleet_posture.py` (models, validation, replies); `app/routers/fleet.py` (reply fields); `app/assurance/builders/host_fw.py` (section loop, `_COMPACT`, listeners); `tests/test_fleet_posture.py`, `test_fleet_p21_models.py`, `test_assurance_host_fw.py`; generated files | WP4 |
| 5 | **WP9 AGENT-OTHER** | `containers`, `platform`, `persistence`, listeners v2, patch `meta` | `agent/paddock_agent/collectors/{containers,platform,persistence,listeners,patch,__init__}.py`; `runner.py` (`unix_http_get`); `agent/PAYLOAD.md`; `agent/tests/**` for these | WP7 |
| 6 | **WP10 KEV-LIB** | `host.kev.*` fields, `Known.until`, reasons, three std YAMLs, `kev explain` | `assurance/paddock_assurance/{hostfields,evaluate,hostconfig,cli,render}.py`; `stdlib/kev-patched-within-{7,14,30}d.yaml`; `assurance/tests/{test_hostfields_kev,test_kev_std,test_hostmutation}.py` | WP5, WP6 |
| 6 | **WP11 INTEL-1** | KEV catalogue, shared advisory machinery, Debian, swap, loops | `intel/app/sources/kev_catalogue.py`; `intel/app/sources/advisories/{__init__,common,scopes,debian}.py`; `intel/app/{db,main,config}.py`; intel dependency on `paddock-assurance`; `intel/tests/**` + fixtures | WP0, WP5 |
| 7 | **WP12 KEV-SERVER** | manifest persistence at ingest, `host_kev` builder, routes, finding text | `orchestrator/app/fleet_posture.py` (ingest persistence); `app/routers/fleet.py` (kev route); `app/routers/assurance.py` (advisories route); `app/assurance/builders/{host_kev,__init__}.py`; `app/assurance/findings_sync.py`; `graph_loader.py` only if the two-source merge test fails; `tests/test_assurance_host_kev.py`, `test_fleet_manifest.py`; generated files | WP3, WP8, WP10, WP11 |
| 7 | **WP13 INTEL-2** | Ubuntu, RHEL OVAL and Alma ingestion | `intel/app/sources/advisories/{ubuntu,rhel_oval,alma}.py`; `intel/app/{db,main}.py`; `intel/tests/**` + fixtures | WP11 |
| 8 | **WP14 PKG-BUILD** | the packaging toolchain and its tests | `agent/packaging/{pkgcommon,archive,build_deb,check_deb,build_rpm,build_repo,sbom,render_release_notes}.py`; `agent/packaging/pkg/**`; `agent/packaging/tests/test_{pkg_layout,archive,build_deb,deb_scripts,deb_dpkg_root,build_rpm,build_repo,sbom,installer_package_coexist}.py`; `scripts/install-agent.sh` (package refusal); `agent/paddock_agent/platform_block.py`; its agent test | WP7 |
| 8 | **WP15 INTEGRATION** | real collectors through the real server for every section; end-to-end tests | `orchestrator/tests/{p2_support,test_p2x_integration,test_assurance_p21_e2e,test_assurance_p2_e2e}.py` | WP4, WP9, WP12, WP13 |
| 9 | **WP16 PKG-RELEASE** | release and CI workflows, operator docs | `.github/workflows/{release,ci}.yml`; `docs/{AGENT_V2,FLEET_WIRING}.md`; `docs/trust/VERIFY.md`; `agent/README.md`; `agent/packaging/tests/test_pkg_release_pins.py` (+ adjustments to `test_installer_p2x*.py`) | WP14 |
| 9 | **WP17 FINAL** | docs sync, generated-file check, status section, full gate run | `docs/{ASSURANCE_P1,ASSURANCE_P2,ASSURANCE_P2_1,READINESS,PROVABLE_CONTAINMENT_MVP,GROWTH,OPERATIONS}.md`; `deploy/helm/paddock/values.yaml` (comments only) | all |

The order inside the waves follows risk: the two soundness fixes and the seam first (wave 1 to 3), identity before the
collectors, the collectors before the KEV server (it needs the models), packaging last because nothing else depends on
it. Why these pairs never share a file: wave 1 splits `orchestrator/` from `assurance/`; wave 2 splits the AWS builder
files from the router/runner files; wave 3 `orchestrator/` from the pure `vulnmatch/` directory; wave 4 `assurance/` from
`agent/`; wave 5 `orchestrator/` from `agent/`; wave 6 `assurance/` from `intel/`; wave 7 `orchestrator/` from `intel/`;
wave 8 `agent/packaging` from `orchestrator/tests`; wave 9 workflows and operator docs from the status docs.

### 7.1 Route and RBAC index (all new routes; every rule is added by WP0 and pinned)

| Route | Capability | Owner WP |
|---|---|---|
| `GET /v1/fleet/agents/{id}/kev` | triage | WP12 |
| `GET /v1/assurance/advisories` | read | WP12 |
| `PUT\|DELETE /v1/fleet/agents/{id}/pairing` | admin (PUT also `require_paid("assurance")`) | WP4 |
| `GET /v1/fleet/agents/{id}/pairing`, `.../pairing/candidates`, `GET /v1/fleet/pairings` | triage | WP4 |
| `GET /v1/fleet/agents/{id}/conflicts` | triage | WP4 |
| `POST /v1/fleet/agents/{id}/conflicts/acks`, `DELETE .../acks/{ack_id}` | admin | WP4 |
| `POST /v1/invariants/{invariant_id}/findings/release` | admin (never billing-gated) | WP3 |
| changed: `GET /v1/assurance/sensor-scopes` (advisories), `PUT .../sensor-scopes/{id}` (`allow_wide`), `GET /v1/sensors` (`scope_declared`), `GET /v1/invariants/{id}` (`state`) | unchanged | WP3 |
| changed: enroll/heartbeat/posture replies (`accepts`, `known_manifest_sha`), `AgentOut.paired_asset_id`, `AgentDetailOut.pairing` | unchanged | WP8, WP4 |

Agent-principal rules are unchanged. `PUT` of a pairing is billing-gated like zone and label writes; a Community tenant
therefore cannot pair and keeps `agent:` nodes with UNKNOWN reach verdicts (P2 behaviour); withdrawing trust is never
gated.

### 7.2 Settings and environment

`config.py` (WP0): `assurance_kev_enabled` (true), `assurance_advisory_max_age_h` (48), `fleet_manifest_tenant_max_mb`
(512), `assurance_pairing_asset_max_age_h` (72), `assurance_conflict_ack_max_h` (720), `assurance_runs_compact_days`
(30); env `RETENTION_INVARIANT_RUNS_DAYS` (365). Intel: `ENABLE_ADVISORIES`, `ADVISORY_SOURCES`, `ADVISORY_CACHE_DIR`,
`ADVISORY_HOSTS`. Agent: `PADDOCK_COLLECTORS_OFF`, `PADDOCK_HASH_USERNAMES`, `PADDOCK_ENABLE_IMDS`.

## 8. Verification gates and the adversarial-test list

### 8.1 Gates (each package runs its own before its wave ends; WP17 runs all)

* `assurance`: `pytest -q`, `ruff check .`. New suites carry the property and brute-force-oracle culture of P0 and the
  mutation checks of 8.3.
* `agent`: `pytest -q agent/tests`, `pytest -q agent/packaging/tests`, `ruff check .`, the Python 3.8 AST gate, and a real
  CPython 3.8 run of the collector tests; `shellcheck -s sh` on the generated maintainer scripts when available.
* `intel`: `pytest -q intel/tests`, `ruff check .`; `test_kev.py::test_sync_marks_known_cves` stays green.
* `orchestrator`, **one pytest session at a time** (the `pytest-postgresql` template database name is fixed), once
  normally and once with `ORCH_TEST_APP_ROLE=1`: the P1 and P2 gate lists plus `test_isolation_sweep.py`,
  `test_isolation_keys.py`, `test_api_isolation_sweep.py`, `test_migrate.py`, `test_public_surface_adversarial.py`, every
  new `test_*p21*`/`test_fleet_pairing*`/`test_fleet_conflict_ack.py`/`test_assurance_host_kev.py`/`test_fleet_manifest.py`.
* Generated files regenerate and pass `--check`; `ruff check .` at the repo root; the doc-pinned tests after every doc edit.
* Doc check: `grep -n "sign-off\|sign off" CLAUDE.md` shows the standing-approval wording (no step waits for UI approval).

### 8.2 Definition of done: one end-to-end test per section (`WP15`; real collectors, real server models, real Postgres, two tenants)

* **A.** A `FixtureHost` with an old `libc6` on Debian 12 and a stored current snapshot: `std:kev-patched-within-14d`
  VIOLATED with a finding and the witness text; the manifest changes to the fixed version: HOLDS at tier `configured` with
  the basis notes; the snapshot aged past 48 h: UNKNOWN `advisory_stale`; a tampered manifest digest: rejected, audited,
  UNKNOWN `manifest_missing`/`manifest_not_current`; an unsupported distro and a containerised agent: UNKNOWN; tenant B
  sees nothing.
* **B.** For each of the six sections: the real collector on fixtures -> the server models accept it -> the fact -> the std
  invariant gives HOLDS, VIOLATED and UNKNOWN in the cases of 8.4; two consecutive collections have byte-identical content
  digests; an agent without the section (legacy) reads UNKNOWN under coverage 1.0; an old server (no `accepts`) never
  receives a new section.
* **D.** An unpaired instance reads UNKNOWN for a reach invariant; after pairing it reads HOLDS at tier `configured`; the
  zone is resolved from the asset and beats a lying claim; an external scan that contradicts the agent gives a conflict and
  UNKNOWN; an acknowledgement restores coverage and a later observation re-raises it; revoking and re-keying end the
  pairing; an asset aged past 72 h makes the pairing inert; tenant B sees nothing.
* **E.** The `probe_builders7.py` estate gives UNKNOWN (never HOLDS) without ENI data, HOLDS with a complete inventory and
  no unmodelled member, UNKNOWN again with one Lambda ENI.
* **F.** A disabled invariant leaves its findings open and annotated; the release route marks them `wontfix`; runs
  compact and purge keep the newest row; a forged `X-Forwarded-For` prefix changes no audit ip and no limiter key; an
  invalid assert reports every problem.
* **C.** A built `.deb` installs, upgrades, downgrades, removes and purges in a `dpkg --root` tree with the lifecycle of
  3.4; apt `update` and `download` succeed against the generated `file://` repo with an ephemeral key; the `.rpm` builds twice
  to the same sha256 and `rpm -qp --dump` shows the input pyz digest.

### 8.3 Mutation checks (a rule broken in a scratch copy; the suite MUST fail; recorded in the package's report)

* **A**: drop the `<` direction of the version comparison; compare source versions for kernels; count installed instead of
  running kernels; drop the strict `>` in the overdue test; read dates at end of day; treat an undated fix as dated; drop the
  `kev_ids_sha` check; drop the first-sighting clamp; let an unknown item beat a definite violation; let `Known(False)` ignore
  `open_truncated`; ignore the `distro_unsupported` check for derivatives.
* **B**: flip the monotone-bool rule; drop the `nss == files` requirement; drop `suspicious_rows`; treat `unknown_pw` as
  clean; use `splitlines()` in the passwd parser; skip a sudoers line containing `NOPASSWD`; follow a symlinked
  `authorized_keys`; copy `Config.Env` into the payload.
* **D**: drop the peer check; drop the asset `last_seen` gate; let claimed ips into `node_ips`; let a later observation
  hide behind an old ack; let `agent_scan_check_budget_exceeded` be acknowledged.
* **E**: drop the estate edge; drop the `unmodeled.count == 0` condition; accept a stale `complete: true`; accept a
  truncated inventory.
* **F**: close a finding on disable; keep the leftmost `X-Forwarded-For`; let the placeholder `assert` produce an
  `Invariant`; delete the newest run.
* **C**: let a script call `systemctl enable`; let `rm -rf` run outside the purge branch; ship the pyz mode 0755; sign
  without the fingerprint check.

### 8.4 What a hostile reviewer must be unable to do

| # | Attack | Required outcome | Where |
|---|---|---|---|
| 1 | Edit the package list after signing | digest mismatch: stored nothing, audit row, host UNKNOWN | WP12 |
| 2 | Claim a derivative or EOL distro, or a codename that does not match the packages | UNKNOWN `distro_unsupported` / `release_eol` / `os_identity_inconsistent` | WP5, WP12 |
| 3 | Use version-string tricks (epoch, `~`, `+esm`, `v` prefix, unicode digits, 10 KB strings, empty revision) | correct order or `version_unparsable` UNKNOWN, never "patched" | WP5 |
| 4 | Name a package so it maps to the kernel or to another source | alias maps are closed; the running-kernel rule needs the collector's package | WP5 |
| 5 | Set `livepatch` or hide the kernel to dodge a kernel CVE | UNKNOWN, never HOLDS | WP5 |
| 6 | Make a newly listed KEV CVE read "patched" (race with a feed refresh) | `advisory_behind_kev` UNKNOWN; swap atomic | WP11, WP12 |
| 7 | Feed intel a shrunken, rolled-back, duplicate-key, entity-bomb or bz2-bomb file | rejected snapshot, previous `current` stays and ages into UNKNOWN | WP11, WP13 |
| 8 | Delay the clock with a future `dateAdded` or advisory date | clamped to first sighting | WP5, WP11 |
| 9 | Read another tenant's manifest (same sha in two tenants) or write a global advisory table | separate rows; global tables writable only by the platform tenant | WP0, WP12 |
| 10 | Send a 8000-package or 1 MiB manifest repeatedly to burn the matcher | caps, input key reuse, per-tenant budget; leftover hosts age into UNKNOWN | WP12 |
| 11 | Pass a custom N (negative, huge, float) in an invariant | compile error outside 0..3650; N is in the digest | WP10 |
| 12 | Hide a second uid-0 account (`+0`, ` 0`, `000`, short row, `\x0b`, NIS marker, 100000 rows, 4 MiB+1 file) | found, or the section is partial/UNKNOWN; a violation still wins | WP7 |
| 13 | Exfiltrate shadow hashes, key blobs/comments, sudoers commands, container env through the payload | none of them is ever in a payload (grep test) | WP7, WP9 |
| 14 | Make `sudo -l` semantics differ from the parse (aliases, tag inheritance, `#500`, includedir `.`/`~` files, negation) | `unparsed`/`visudo_files_match` make it approximate, never exact | WP7 |
| 15 | Plant a FIFO, device, symlink or 1 MiB+ file as `authorized_keys`; slow-loris or 3 MiB reply from the docker socket | not followed, no hang, timeout and caps, `partial` | WP7, WP9 |
| 16 | Make the agent call a denied syscall (SIGSYS) | no `ctypes` (AST test); `timedatectl`/`chronyc` only | WP7, WP9 |
| 17 | Add a volatile field to churn the store | content digest stable across runs (test) | WP7, WP9, WP8 |
| 18 | Send a new section to an old server or an old agent to a new server | `accepts` negotiation; legacy host UNKNOWN under coverage 1.0, never a pass | WP7, WP8 |
| 19 | Pair two agents to one asset, pair as an analyst, or probe for foreign assets | 409 by the unique index; 403; foreign and random ids answer identically | WP4 |
| 20 | Keep a pairing across a re-key or revoke; make an inert pairing read HOLDS | ended in the same transaction; inert falls back to `agent:` | WP4 |
| 21 | Place a host in a zone by lying about its claimed addresses (paired host) | zone from the asset's addresses only | WP4 |
| 22 | Pre-acknowledge a future scan observation, ack a budget or peer conflict, or let an ack outlive 720 h | 409/422; later observation re-raises; expiry | WP4 |
| 23 | Get HOLDS for a datastore reachable from an unmodelled Lambda/Fargate ENI, with a partial page, AccessDenied or stale inventory | UNKNOWN with the estate witness | WP2 |
| 24 | Make a disabled invariant close its findings, or a release reopen itself | never closed by the machine; `wontfix` is human and sticky | WP3 |
| 25 | Forge an audit ip or evade/poison a limiter with `X-Forwarded-For` | strict address; the static guard test | WP0 |
| 26 | Hide a schema error behind a bad `assert:` or get an `Invariant` from the placeholder | all problems reported; no `Invariant` | WP1 |
| 27 | Declare a /8 sensor scope silently | 422 `scope_too_wide` unless justified and audited | WP3 |
| 28 | Install a package over a script install (or the reverse), enable or start on install, read a token, delete state on `remove`, delete state on `purge` without the marker | each refused or not done | WP14 |
| 29 | Ship a tampered `.deb`/`.rpm`, an unsigned repo as signed, or a secret in the repo | checksums, signatures and `PRIVATE KEY` grep fail the build; no key means no repo | WP14, WP16 |

### 8.5 Not verified here (carried to the status section after the build)

The unit under a real systemd (`ProtectHome=read-only`, `docker.sock` connect, `timedatectl` under the sandbox), any real
host, a real GitHub release (`release.yml` has never run), real GPG keys and `rpmsign`, `lintian` (never run on these
packages), `createrepo_c`, dnf/rpm scriptlet semantics, several orchestrator replicas, the performance of 10,000
distinct manifests in the builder, and any distribution feed shape that changed since the 2026-11-26 probes.

## 9. Non-goals, known limits and what HOLDS will not mean

**What HOLDS will not mean in P2.1** (each is also said in the std text or a `basis:` note):

* `std:kev-patched-within-Nd` HOLDS does **not** mean the host has no exploitable vulnerability. It means: in the signed
  package list, against the distribution's own public advisory data and CISA's catalogue (both unsigned, TLS only: the feed
  vendor is the trust root), no listed vulnerability with a published fix older than N days is unfixed. It says nothing about
  snaps, flatpaks, containers, language ecosystems, third-party repositories (deb origin cannot be proven per package), a
  process still holding an old library until restart, CVEs without a fix (counted, not judged), a host whose agent a root
  attacker controls, or a fix the vendor never published to the advisory feed. A date is the advisory's publication, not the
  moment the host's mirror had the package, and Alma advisories lag Red Hat (we deliberately use the host distro's date).
  A leftover binary of an older source version reads as unpatched (a false-positive direction); RHEL EUS/E4S streams are
  treated as the standard stream (noisy for EUS customers).
* The six host-config invariants say "no counterexample in the files and sockets the collectors read": not a malware or
  intrusion check (the agent is posture, exposure and containment, not an EDR: MVP 6.2), nothing about LDAP/sssd/NIS
  accounts (UNKNOWN), polkit/doas, sudo-rs (UNKNOWN until verified), rootless containers, Kubernetes/containerd/CRI-O nodes
  (UNKNOWN), stopped containers, a TCP-exposed daemon, per-user `LD_PRELOAD`, or an NTP source's trustworthiness. A root
  attacker can sign any of it (E2: facts stay `configured`).
* A pairing HOLDS means the host's facts are attributed to the asset the admin named; it does not prove the admin was right
  for private ports (only public ports are cross-checked by the scan). Acknowledging a conflict restores coverage and nothing
  else.
* The estate fix keeps `std:no-internet-to-datastore` UNKNOWN whenever an unmodelled ENI (Lambda, Fargate, RDS, endpoint,
  NAT, detached) shares a referenced security group, until per-ENI nodes (P2.2); remedies are a separate SG, a time-boxed
  `allow:` exception, or waiting.
* A signed package is not a vendor package; a signed manifest is not an installed system; a signed `ProtectHome=read-only`
  host is not a sandboxed one.

**Non-goals (explicit):** any dashboard screen (P6); Rocky, Amazon Linux, Oracle, SUSE, Alpine, CentOS Stream, Ubuntu Pro/ESM
and Debian ELTS advisory data; language-ecosystem or snap vulnerability data; banner cross-validation of the package list
against an external scan (a cheap, strong follow-up for exposed services; it must withdraw coverage like
`agent_closed_scan_open` and is not in P2.1: the `kev` fact is `configured` and carries no such check); FIM, SUID/SGID,
enabled-unit and cron drift, disk encryption, auditd/journald, the IMDSv2 std invariant, egress baseline, per-ENI nodes
(P2.2); the privilege split (P4); attestation (P3, which must count acknowledged conflicts, pinned runs and the advisory
snapshot ids); Terraform and Ansible roles; CycloneDX; Windows and macOS; a pure-Python rpm writer; a public package repo
the maintainers must host (the tarball is always produced, hosting is opt-in); a four-eyes rule on pairing; and any
change to the v1 inventory route, `CAP_NET_RAW`, tombstone scope or the zone-unknown 65-node behaviour (P2 owner decisions
1, 4, 5, 6 stay as they were).

**Known limits of the build as designed** (each fails safe unless marked **not safe**):

1. **Feed trust root (not safe against a malicious vendor path).** Section 1.4. Mitigated by guards, sha recording and
   the staleness bound; not removable.
2. **Signed is not true** (not safe, by nature): a root-compromised host signs a clean manifest or accounts section.
   Mitigations are the existing scan-conflict flag (for ports) and, for the package list, nothing in P2.1.
3. **Deb origin is not provable per package** (not safe, narrow): a third-party or local build with a higher version string
   than the Debian fix reads patched; carried as a basis note and `host.kev.third_party_sources`.
4. **Dating:** undated fixes are UNKNOWN until old enough; the bootstrap of a fresh intel makes every undated row
   `first_seen` now (UNKNOWN for N days, then a proven violation).
5. **The ENI inventory is point-in-time**; between pulls a new ENI in a referenced SG is invisible (bounded by `max_age`).
6. **Collectors:** `timedatectl` needs systemd and D-Bus; DMI and the IMDS probe are host-reported; the IMDS probe cannot tell
   a disabled endpoint from a firewall; rpm `RSAHEADER` key ids and `apt-cache policy` summaries are only as honest as the
   host; the `accounts` parse agrees with glibc only for the quirks probed (differential CI against real `getent`,
   `sudo -l` and `visudo -c` is required, not optional).
7. **Rollout:** `coverage: 1.0` on every new std invariant means a mixed-version estate reads UNKNOWN until every host
   runs the new agent (intended, E5); `std:server-no-passwordless-sudo` will open findings on stock cloud images, and
   `std:server-container-engine-not-exposed` on hosts whose monitoring agent mounts `docker.sock` on purpose.
8. **Pairing** cannot serve autoscaled or golden-image fleets; a routine disk rebuild needs a re-key and a re-pair; an
   inert pairing is visible only to someone who reads `effective.state` (a P6 badge).
9. **Packages:** the `.rpm` is reproducible only for the same rpm version; apt metadata without `Valid-Until` accepts a stale
   mirror (freeze attack); downgrading across a state-format change is unsupported; the GPG key is a long-lived secret
   outside `release.yml`'s no-long-lived-key model (offline primary, subkey in a protected environment, pinned fingerprint,
   committed public key, revocation certificate and rotation procedure; **the owner must create it**; without it no
   repository is published); the Maintainer address is a placeholder; `release.yml` has never run and the GitHub
   settings (environment reviewers, tag ruleset, branch protection) are still an **owner action** (P2 11 item 19), so a
   tag pusher can still cause a signed release.
10. **Lifecycle:** compaction and purge remove witnesses older than 30 days and rows older than 365 days (P3 pins what it
    needs); the strict client address makes a wrong `TRUSTED_PROXY_HOPS` share one limiter bucket (availability only).

## 10. Status (filled in after the build)

Not yet built. WP17 replaces this section with what shipped, what differs from this contract, the gate results, what no
test exercised, and the outcome of the adversarial review, in the shape of ASSURANCE_P2.md section 13.
