# Data Processing Agreement — TEMPLATE

> **Template, not legal advice.** For an organisation that provides Paddock
> as a managed service to customers (the open-source project itself processes
> no customer data). Have counsel adapt it; it follows the structure of GDPR
> Art. 28 and the EU Standard Contractual Clauses (SCCs). Bracketed fields are
> to be completed. Annex II describes what the Paddock software actually does —
> keep it in sync with [SECURITY_WHITEPAPER.md](SECURITY_WHITEPAPER.md).

**Between** [Customer legal name] ("Controller") **and** [Provider legal name]
("Processor"), forming part of the [Master Services Agreement] dated [date]
(the "Agreement").

## 1. Definitions
Terms such as *personal data*, *processing*, *controller*, *processor*,
*data subject*, *personal data breach* and *supervisory authority* have the
meanings in Regulation (EU) 2016/679 ("GDPR") and, where applicable, the UK
GDPR and other Applicable Data Protection Law.

## 2. Subject matter and duration
The Processor processes personal data only to provide the attack-surface
management service described in the Agreement, for the term of the Agreement
plus the deletion period in §10.

## 3. Controller instructions
3.1 The Processor processes personal data only on documented instructions of
the Controller, including the Agreement, this DPA and configuration the
Controller makes in the service (e.g. scope allowlist, enabled modules,
integrations, optional LLM features).
3.2 The Controller warrants it is **authorised to assess every asset it adds to
the scope allowlist** and that it has a lawful basis for the processing.
3.3 The Processor informs the Controller if an instruction infringes
Applicable Data Protection Law.

## 4. Confidentiality
Persons authorised to process personal data are bound by confidentiality
obligations and receive access on a least-privilege basis.

## 5. Security
The Processor implements the technical and organisational measures in
**Annex II** and keeps them at a level appropriate to the risk (Art. 32).

## 6. Subprocessors
6.1 The Controller gives general authorisation for the subprocessors listed in
**Annex III** (see [SUBPROCESSORS.md](SUBPROCESSORS.md)).
6.2 The Processor notifies the Controller at least [30] days before adding or
replacing a subprocessor; the Controller may object on reasonable data
protection grounds, in which case the parties discuss in good faith and the
Controller may terminate the affected service.
6.3 The Processor imposes data protection obligations on each subprocessor no
less protective than this DPA and remains liable for its subprocessors.

## 7. Data subject rights
Taking into account the nature of processing, the Processor assists the
Controller by appropriate measures to respond to data subject requests
(access, rectification, erasure, restriction, portability, objection) within
[10] business days of a request.

## 8. Personal data breaches
8.1 The Processor notifies the Controller **without undue delay and in any
event within [48] hours** of becoming aware of a personal data breach
affecting Controller data, with the information in Art. 33(3) as it becomes
available (see [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md)).
8.2 The Processor provides the relevant tenant's audit-log extract and the
results of the audit-chain verification (`/v1/audit/verify`) on request.

## 9. Assistance
The Processor assists with DPIAs and prior consultations (Art. 35–36) to the
extent the information is available to it.

## 10. Return and deletion
On termination the Processor, at the Controller's choice, returns the
Controller's data in a machine-readable export and/or deletes it within [30]
days, following the tenant purge procedure in
[DATA_RETENTION.md](DATA_RETENTION.md), and confirms deletion in writing.
Backups are deleted on their normal rotation, no later than [35] days
thereafter. The cryptographically chained audit log and its external anchors
may be retained for [the audit retention period] where required by law or to
evidence the integrity of the service; they contain the minimum personal data
listed in Annex I.

## 11. Audits
The Processor makes available the information necessary to demonstrate
compliance (e.g. [SOC 2 report when available], this DPA's annexes, the
release verification evidence in [VERIFY.md](VERIFY.md)) and allows audits by
the Controller or its mandated auditor on [30] days' notice, no more than once
per year unless required by a supervisory authority or following a breach.

## 12. International transfers
Transfers outside the EEA/UK rely on [the EU SCCs Module 2 / UK IDTA / an
adequacy decision], incorporated by reference. Data residency: tenant data is
stored in [region] (recorded per tenant in `tenants.data_region`).

## 13. Liability and precedence
Liability is governed by the Agreement. In case of conflict on data protection
matters, this DPA prevails.

---

## Annex I — Description of processing

| Item | Description |
|---|---|
| Categories of data subjects | Controller's users of the service (analysts, admins, auditors); individuals whose data appears in Controller's internet-facing assets (e.g. names/e-mails in TLS certificates, WHOIS, web page metadata) |
| Categories of personal data | user account data (username, optional e-mail, display name, role, password hash); client IP addresses, request ids and actions in the audit log; incidental personal data in discovered asset metadata and finding evidence |
| Special categories | none intended |
| Nature and purpose | discovery, scope-gated probing, vulnerability correlation, prioritisation and reporting of the Controller's attack surface; security audit logging |
| Frequency | continuous |
| Retention | per [DATA_RETENTION.md](DATA_RETENTION.md) and Controller configuration |

## Annex II — Technical and organisational measures (what the software does)

* **Access control:** authenticated API (JWT or hashed API keys), RBAC
  (viewer/analyst/auditor/admin) with deny-closed default, classification-based
  ABAC enforced in SQL, scoped and expiring API keys, login throttling.
* **Tenant isolation:** Postgres row-level security on every tenant-scoped table;
  the application connects as a role that cannot bypass RLS
  ([TENANCY.md](TENANCY.md) — including its listed limits).
* **Audit:** fail-closed, HMAC-keyed, per-tenant hash-chained audit log anchored
  to append-only external storage; application role cannot update/delete audit rows.
* **Encryption:** integration credentials AES-256-GCM; passwords bcrypt;
  in transit and at rest per Provider's hosting measures [describe: TLS 1.2+ at
  the edge, mTLS/private network internally, encrypted volumes, KMS].
* **Scope safety:** probing restricted to the Controller's allowlist, enforced
  in three independent layers; every outbound request logged.
* **Supply chain:** signed release images with SBOMs and SLSA provenance.
* **Organisational:** [personnel screening, training, access reviews, incident
  response, vulnerability management, business continuity — describe].

## Annex III — Subprocessors
See [SUBPROCESSORS.md](SUBPROCESSORS.md) (to be completed by the Provider).
