# Subprocessors — TEMPLATE

> For an organisation operating Paddock as a service. The open-source project
> has no subprocessors because it operates no service. Rows marked
> *(software dependency)* are third parties **the Paddock software itself
> contacts** when the corresponding feature is enabled — whether they are
> "subprocessors" depends on whether personal data is sent to them (assess per
> row). Keep this list in sync with the DPA Annex III and notify customers
> [30] days before changes.

Last updated: [date]

## Infrastructure (operator to complete)

| Subprocessor | Purpose | Data processed | Location | Transfer mechanism |
|---|---|---|---|---|
| [Cloud provider] | hosting, database, object storage (audit anchors) | all service data | [region] | [SCCs / adequacy] |
| [E-mail provider] | account / alert e-mail | user e-mail addresses, alert content | [region] | [ ] |
| [Support / ticketing] | customer support | support correspondence | [region] | [ ] |
| [Error monitoring / logging] | operations | logs (may include IPs, usernames) | [region] | [ ] |

## Third parties the Paddock software contacts

| Party | Feature / module | What is sent | Personal data? | Can be disabled |
|---|---|---|---|---|
| Anthropic (Claude API) | `brain` LLM triage + Ask; `remediation` LLM drafting — only when an Anthropic key is set, either `ANTHROPIC_API_KEY` in `.env` or one an admin saved under Settings > System > AI features *(software dependency)* | finding titles/descriptions/evidence summaries, asset identifiers, natural-language questions and the DB schema description | possibly (incidental, from asset metadata/evidence) | yes — remove the key (Settings > System > AI features, and `.env`); deterministic fallback is used |
| crt.sh / Certificate Transparency | passive discovery (`ct_logs`) | customer domain names as queries | no (domain names) | yes (module config) |
| Internet Archive (Wayback) | passive discovery | customer domain names | no | yes |
| RIPE stat / BGPView | ASN / IP-range expansion | ASNs, IP ranges | no | yes |
| Shodan InternetDB / Shodan API | passive service enrichment | customer IP addresses | no | yes |
| NIST NVD, FIRST EPSS, CISA KEV | vulnerability intelligence (`intel`) | none (download only) | no | n/a |
| OSV.dev, PyPI, npm registry | SCA vulnerability + typosquat data (`sca`) | package names/versions from customer SBOMs | no | yes |
| GitHub API | code-analysis / repository integration when configured | repository identifiers | no | yes |
| Threat-intel feeds (TAXII/STIX URLs configured by the operator) | `threatintel` | none (download only) | no | yes |
| Integration endpoints (Slack, Jira, webhooks, …) configured by the customer | `integrations` | finding/alert content | possibly | yes — customer-controlled |
| Audit anchor sink (S3-compatible bucket / webhook) | audit anchoring | tenant id, row id, hash, timestamp — no content | no | yes |

Targets inside the customer's scope allowlist are contacted by the workers by
design; they are the customer's own systems, not subprocessors.
