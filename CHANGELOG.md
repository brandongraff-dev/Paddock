# Changelog

What changed in Paddock, and an honest picture of what is solid today and what is not.
The dashboard shows this file under **Settings → About**; it is generated from here
(`python scripts/export_changelog.py`), so edit this file, not the generated one.

Paddock is **early**. No tagged release exists yet, so the version below is the in-tree
version (`0.1.0`) and everything new is listed under *Unreleased*. When the first
`vX.Y.Z` tag is pushed, move the *Unreleased* entries under that version and date.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Detailed status, per area:
[`docs/READINESS.md`](docs/READINESS.md).

## State of the app

States: **working** = built and covered by automated tests, no known blocker.
**beta** = works, with known gaps listed. **unverified** = built and tested in CI, but never run
on the real hardware, cluster or service it is for. **not released** = does not exist for users yet.

| Area | State | Notes |
|---|---|---|
| Detection and finding lifecycle | working | 207 seeded cases gate CI. Thresholds are not yet calibrated on real customer data. |
| Verified exploitability and re-checks | working | 11 safe, scope-pinned checks. A verdict never closes a finding on its own. |
| Tenant isolation | working | Row-level security in the orchestrator and every compute service, with sweep tests. One shared service key remains (per-service keys are the real fix). |
| Integrations (21 connectors) | beta | Tested against protocol-accurate fakes, not real SaaS tenants. |
| Reporting and compliance packs | working | Executive report, PCI DSS, NIST CSF, CIS, ISO 27001, IEC 62443, EU CRA. |
| Install on Linux and macOS | working | `make lite` and `install.sh` run end to end in CI. |
| Install on Windows (Paddock Setup) | unverified | Tested in CI (fake Docker) and compiles for Windows. Never run by a person on a real Windows PC. Not code-signed, so SmartScreen warns. |
| Prebuilt images and release downloads | not released | The workflow is in place and tested without publishing. Until the first release tag, installers build from source (15+ minutes). |
| AI features (optional) | beta | Works without any key. A key saved in Settings is stored encrypted. Not yet exercised against the live Anthropic API in CI. |
| Kubernetes (Helm) and 24 h soak | unverified | Chart validated in CI; never deployed to a real cluster, and no soak test has run. |
| Sensors and Raspberry Pi image | unverified | Built and tested; the image has not been built or run on real hardware. |
| Production use | beta | Early: validated mostly on synthetic data and one live reference host. Run the hardened profile and read the security policy. |

## [Unreleased]

### Added

- **Paddock Setup**, a Windows installer wizard (`Paddock-Setup.exe`): it checks your PC and explains how to fix anything wrong, installs, and hands you the login. Three screens, plain-English messages, a folder picker, an optional Start menu shortcut, and a manage screen (open, update, stop, remove) for an existing install.
- **Prebuilt, signed images** for the lite stack and a release zip with `install.bat`, so an install pulls images in about two minutes instead of building for 15+. Nothing is published until a release tag is pushed.
- **`-Doctor` / `--doctor`** for the installers: checks Docker, WSL, virtualization, memory, disk, ports and network, with a plain-English fix for each problem. The installers run the same checks first.
- **AI features key in Settings → System**: paste an Anthropic key instead of editing `.env`. The lite stack now runs the AI service (`brain`).
- **Settings → System**: version, edition and the health of every component.
- **Settings → About**: this changelog and the state of each area of the app.
- A **Download for Windows** button for the website (on its own branch, for the live design).

### Changed

- The lite compose file has `image:` tags next to `build:`; `make lite` still builds from source.
- In lite mode the orchestrator probes `brain` instead of reporting it as not enabled.

### Fixed

- `install.ps1`: a native command's output no longer leaks into its exit-code check.
- `-Purge` (both installers) now refuses an unsafe folder **before** deleting the database volume, not after.

### Security

- The optional AI key is stored AES-256-GCM encrypted, never returned to a browser, never logged or audited, and released only to the fleet service key. `SECURITY.md` no longer says the key is confined to `brain`: the orchestrator now holds it (encrypted), and a stolen service key can read it. See `docs/trust/TENANCY.md`.

### Known issues

- No release has been published, so the README's download links point at a page with nothing on it yet.
- `schema/039_ai_settings.sql` has the same number as two other unmerged migrations. They have different names, so the migrator is unaffected; whoever merges second may want to renumber.

## Earlier work (before this changelog)

- 2026-11-21: Verify loop, integrations, billing, MSP console and tenancy hardening, with CI and a rewritten README (PR #4).
- 2026-11-21: Universal ingest, the MCP server, installer and CI templates.
- 2026-11-21: Growth features: free exposure check, trust pages, supplier monitoring.
- 2026-11-21: Sentry plug-in kit: enrollment, resilient uploads, Raspberry Pi image, tested to 1M flows/day.
- 2026-11-21: Tenant isolation extended to every compute service and worker.
- 2026-11-21: Dashboard and landing redesign (PRs #2 and #3), then the landing cliff-and-rider footer scene (PR #5).
- 2026-11-21: Contributor licence agreement is now asked only of outside contributors (PR #6).
- 2026-11-21: Launch film in the README, and all links point at the Paddock repository (PR #8).
