// GENERATED from CHANGELOG.md by scripts/export_changelog.py. Do not edit; edit CHANGELOG.md.
// `python scripts/export_changelog.py --check` (and the scripts tests) fail if this is out of date.
import type { Changelog } from "./types";

export const CHANGELOG: Changelog = {
  "state": [
    {
      "area": "Detection and finding lifecycle",
      "state": "working",
      "notes": "207 seeded cases gate CI. Thresholds are not yet calibrated on real customer data."
    },
    {
      "area": "Verified exploitability and re-checks",
      "state": "working",
      "notes": "11 safe, scope-pinned checks. A verdict never closes a finding on its own."
    },
    {
      "area": "Tenant isolation",
      "state": "working",
      "notes": "Row-level security in the orchestrator and every compute service, with sweep tests. One shared service key remains (per-service keys are the real fix)."
    },
    {
      "area": "Integrations (21 connectors)",
      "state": "beta",
      "notes": "Tested against protocol-accurate fakes, not real SaaS tenants."
    },
    {
      "area": "Reporting and compliance packs",
      "state": "working",
      "notes": "Executive report, PCI DSS, NIST CSF, CIS, ISO 27001, IEC 62443, EU CRA."
    },
    {
      "area": "Install on Linux and macOS",
      "state": "working",
      "notes": "make lite and install.sh run end to end in CI."
    },
    {
      "area": "Install on Windows (Paddock Setup)",
      "state": "unverified",
      "notes": "Tested in CI (fake Docker) and compiles for Windows. Never run by a person on a real Windows PC. Not code-signed, so SmartScreen warns."
    },
    {
      "area": "Prebuilt images and release downloads",
      "state": "not released",
      "notes": "The workflow is in place and tested without publishing. Until the first release tag, installers build from source (15+ minutes)."
    },
    {
      "area": "AI features (optional)",
      "state": "beta",
      "notes": "Works without any key. A key saved in Settings is stored encrypted. Not yet exercised against the live Anthropic API in CI."
    },
    {
      "area": "Kubernetes (Helm) and 24 h soak",
      "state": "unverified",
      "notes": "Chart validated in CI; never deployed to a real cluster, and no soak test has run."
    },
    {
      "area": "Sensors and Raspberry Pi image",
      "state": "unverified",
      "notes": "Built and tested; the image has not been built or run on real hardware."
    },
    {
      "area": "Production use",
      "state": "beta",
      "notes": "Early: validated mostly on synthetic data and one live reference host. Run the hardened profile and read the security policy."
    }
  ],
  "releases": [
    {
      "version": "Unreleased",
      "date": null,
      "sections": [
        {
          "kind": "Added",
          "items": [
            "Paddock Setup, a Windows installer wizard (Paddock-Setup.exe): it checks your PC and explains how to fix anything wrong, installs, and hands you the login. Three screens, plain-English messages, a folder picker, an optional Start menu shortcut, and a manage screen (open, update, stop, remove) for an existing install.",
            "Prebuilt, signed images for the lite stack and a release zip with install.bat, so an install pulls images in about two minutes instead of building for 15+. Nothing is published until a release tag is pushed.",
            "-Doctor / --doctor for the installers: checks Docker, WSL, virtualization, memory, disk, ports and network, with a plain-English fix for each problem. The installers run the same checks first.",
            "AI features key in Settings → System: paste an Anthropic key instead of editing .env. The lite stack now runs the AI service (brain).",
            "Settings → System: version, edition and the health of every component.",
            "Settings → About: this changelog and the state of each area of the app.",
            "A Download for Windows button for the website (on its own branch, for the live design)."
          ]
        },
        {
          "kind": "Changed",
          "items": [
            "The lite compose file has image: tags next to build:; make lite still builds from source.",
            "In lite mode the orchestrator probes brain instead of reporting it as not enabled."
          ]
        },
        {
          "kind": "Fixed",
          "items": [
            "install.ps1: a native command's output no longer leaks into its exit-code check.",
            "-Purge (both installers) now refuses an unsafe folder before deleting the database volume, not after."
          ]
        },
        {
          "kind": "Security",
          "items": [
            "The optional AI key is stored AES-256-GCM encrypted, never returned to a browser, never logged or audited, and released only to the fleet service key. SECURITY.md no longer says the key is confined to brain: the orchestrator now holds it (encrypted), and a stolen service key can read it. See docs/trust/TENANCY.md."
          ]
        },
        {
          "kind": "Known issues",
          "items": [
            "No release has been published, so the README's download links point at a page with nothing on it yet.",
            "schema/039_ai_settings.sql has the same number as two other unmerged migrations. They have different names, so the migrator is unaffected; whoever merges second may want to renumber."
          ]
        }
      ]
    }
  ],
  "other": [
    {
      "title": "Earlier work (before this changelog)",
      "items": [
        "2026-11-21: Verify loop, integrations, billing, MSP console and tenancy hardening, with CI and a rewritten README (PR #4).",
        "2026-11-21: Universal ingest, the MCP server, installer and CI templates.",
        "2026-11-21: Growth features: free exposure check, trust pages, supplier monitoring.",
        "2026-11-21: Sentry plug-in kit: enrollment, resilient uploads, Raspberry Pi image, tested to 1M flows/day.",
        "2026-11-21: Tenant isolation extended to every compute service and worker.",
        "2026-11-21: Dashboard and landing redesign (PRs #2 and #3), then the landing cliff-and-rider footer scene (PR #5).",
        "2026-11-21: Contributor licence agreement is now asked only of outside contributors (PR #6).",
        "2026-11-21: Launch film in the README, and all links point at the Paddock repository (PR #8)."
      ]
    }
  ]
};
