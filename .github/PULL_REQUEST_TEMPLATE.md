<!-- Thanks for contributing! Keep PRs focused; link the issue they close. -->

## What & why

<!-- What does this change and why? Link issues: "Closes #123". -->

## Type

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Docs / tests / CI
- [ ] Other:

## Checklist

- [ ] Tests pass locally (`make test`, and the relevant service's `pytest -q`).
- [ ] I added/updated tests for the change.
- [ ] Lint is clean (`ruff check .`).
- [ ] Docs updated if behavior/flags/contracts changed (README, `docs/`, service notes).
- [ ] If I touched a shared schema or an inter-service contract, I updated `docs/CONTRACTS.md` and the dependent services.

## Safety gate (required — see SECURITY.md §6)

palantir-asm is **detection-only**. Confirm this PR does **not** add any of:

- [ ] auto-exploitation / payload delivery / PoC execution
- [ ] credential attacks (brute force, spray, stuffing, submitting default creds)
- [ ] evasion (stealth/fragmented scans, WAF-bypass, decoys, source spoofing)
- [ ] a path to send traffic to a target outside the `scope_entries` allowlist

> PRs that add offensive capability will be rejected on sight. This posture is
> what keeps the tool legal, safe, and employable.

## The "never touch the live DB" rule

- [ ] My tests do **not** connect to a production/live database. DB-backed
      suites use `TEST_DATABASE_URL` (a disposable DB) or skip; the orchestrator
      suite uses `pytest-postgresql`'s throwaway instances. (A real incident is
      why this is a checkbox — see CONTRIBUTING.md.)

## Screenshots (UI changes)

<!-- Before/after for dashboard changes. -->
