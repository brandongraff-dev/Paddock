# SIEM integrations (OCSF 1.3)

Paddock pushes findings and platform events into your SIEM as
**[OCSF 1.3](https://schema.ocsf.io/1.3.0/)** JSON. Five connectors ship in
`orchestrator/app/integrations/connectors/`, all `Capability.NOTIFY`, category
`siem`:

| kind | Destination | Transport | Batching | Secret(s) |
|---|---|---|---|---|
| `splunk_hec` | Splunk HTTP Event Collector | HTTPS | up to 200 events per request | `token` |
| `sentinel` | Microsoft Sentinel via the Azure Monitor **Logs Ingestion API** | HTTPS | up to 500 records per request, split at the 1 MB body limit | `client_secret` |
| `google_secops` | Google SecOps (Chronicle) Ingestion API | HTTPS | up to 200 events per request, split at 1 MB | `service_account_json` |
| `elastic` | Elasticsearch / Elastic Security `_bulk` | HTTPS | up to 500 docs per request | `api_key` |
| `syslog` | Any RFC 5424 collector (QRadar, ArcSight, Graylog, rsyslog, syslog-ng…) | TLS (default), or TCP/UDP for private targets | one connection per batch | none |

Every connector:

* sends the OCSF mapping described [below](#ocsf-mapping), so the same detections
  look the same in every SIEM;
* checks every destination with `netsafety.validate_outbound_url` right before
  each request: `https` only, never cloud-metadata/reserved ranges, and private
  or LAN addresses only when the integration has **`allow_private`** turned on.
  Redirects are never followed;
* classifies failures for the delivery worker. `DeliveryResult.retryable` is
  `True` for timeouts, connection errors, HTTP 408/425/429/5xx and Splunk
  "server busy" codes. It is `False` for bad credentials (401/403), bad
  requests (400/404/413), refused destinations and TLS verification failures,
  which are configuration problems a retry cannot fix;
* never returns a secret. If a remote error body echoes the token back, it is
  replaced with `********` in `detail`;
* has a real **Test** button (`test()`): it sends one `integration.test` event
  end to end, so a passing test proves the credentials, permissions and
  index/stream are all right;
* is idempotent per event. The Paddock event id goes along as the dedupe key:
  `fields.paddock_event_id` in Splunk, `EventId` in Sentinel, the document `_id`
  in Elastic (a re-sent event gets `409` and counts as delivered), and
  `eventId=` in syslog structured data.

> **Batching contract.** Besides `deliver(event)`, SIEM connectors implement
> `deliver_batch(events) -> DeliveryResult`. This is an additive method on top
> of the shared `Connector` contract. A dispatcher can call it with any number
> of events, and the connector chunks them by `max_batch`. The result is
> all-or-nothing, so retry the whole batch. Splunk and syslog may then
> duplicate events, which is why the event id travels with every record.
>
> **`allow_private`.** Connectors read it from `connector.allow_private`
> (the dispatcher sets it from the `integrations.allow_private` column) or, if
> that isn't set, from `config["allow_private"]`. Anything else means *deny private targets*.

---

## Splunk (HTTP Event Collector)

1. In Splunk, go to **Settings → Data inputs → HTTP Event Collector → New Token**.
   Pick a default index (e.g. `security`) and allow the source type
   `paddock:ocsf`, or leave it as *Automatic*.
2. In Paddock, go to **Integrations → Add → Splunk** and fill in:

| field | value |
|---|---|
| `url` | `https://splunk.example.com:8088`. The `/services/collector/event` path is added for you |
| `index` | optional; leave empty to use the token's default index |
| `sourcetype` | default `paddock:ocsf` |
| `source`, `host` | optional event metadata |
| `channel` | the HEC channel GUID, needed only if *indexer acknowledgement* is on |
| `tls_verify` | default `true`. Only an **`allow_private`** integration (for example a lab Splunk with a self-signed certificate on the LAN) may set it to `false`. For a public host the setting is refused |
| secret `token` | the HEC token |

Events arrive as `{"time": <epoch s>, "sourcetype": ..., "event": <OCSF>,
"fields": {"paddock_event_id", "paddock_event_type", "ocsf_class_uid"}}`. Useful
SPL:

```spl
index=security sourcetype="paddock:ocsf" class_uid=2002 severity_id>=4
| dedup paddock_event_id
| table _time finding_info.title resources{}.name vulnerabilities{}.cve.uid unmapped.paddock.cvss
```

## Microsoft Sentinel (Logs Ingestion API)

Paddock uses the current Logs Ingestion API, not the deprecated HTTP Data
Collector API:

1. **Create an Entra app registration** and a client secret. Note the tenant ID
   and client (application) ID.
2. **Create a custom table** `PaddockOCSF_CL` in your Sentinel workspace, along
   with a **data collection endpoint (DCE)** and a **data collection rule
   (DCR)**. The DCR stream declaration needs at least these columns:

   ```json
   "streamDeclarations": {
     "Custom-PaddockOCSF_CL": {
       "columns": [
         {"name": "TimeGenerated", "type": "datetime"},
         {"name": "EventId", "type": "string"},
         {"name": "class_uid", "type": "int"},
         {"name": "class_name", "type": "string"},
         {"name": "activity_id", "type": "int"},
         {"name": "type_uid", "type": "long"},
         {"name": "severity_id", "type": "int"},
         {"name": "severity", "type": "string"},
         {"name": "status_id", "type": "int"},
         {"name": "status", "type": "string"},
         {"name": "message", "type": "string"},
         {"name": "time", "type": "long"},
         {"name": "finding_info", "type": "dynamic"},
         {"name": "resources", "type": "dynamic"},
         {"name": "vulnerabilities", "type": "dynamic"},
         {"name": "remediation", "type": "dynamic"},
         {"name": "observables", "type": "dynamic"},
         {"name": "metadata", "type": "dynamic"},
         {"name": "unmapped", "type": "dynamic"}
       ]
     }
   }
   ```
   A pass-through `transformKql` of `source` works. Columns the stream doesn't
   declare are dropped.
3. **Grant the app the *Monitoring Metrics Publisher* role on the DCR.**
   Without it, ingestion returns 403. Paddock reports this as a non-retryable
   error that names the role.
4. In Paddock, go to **Integrations → Add → Microsoft Sentinel** and fill in:

| field | value |
|---|---|
| `dce_endpoint` | `https://my-dce-xxxx.eastus-1.ingest.monitor.azure.com` |
| `dcr_immutable_id` | `dcr-0123…` (the DCR's *Immutable ID*) |
| `stream_name` | `Custom-PaddockOCSF_CL` |
| `tenant_id`, `client_id` | from step 1 |
| `authority_host` | default `login.microsoftonline.com`; change it for sovereign clouds |
| secret `client_secret` | from step 1 |

Token handling: Paddock gets a client-credentials token for
`https://monitor.azure.com//.default`. It caches the token per (authority,
tenant, client, secret fingerprint) until 5 minutes before it expires. If
ingestion returns 401, Paddock drops the token, refreshes it once and retries,
so a rotated secret recovers by itself. Each record is the OCSF object plus
`TimeGenerated` (taken from OCSF `time`) and `EventId`.

```kql
PaddockOCSF_CL
| where severity_id >= 4
| extend cve = tostring(vulnerabilities[0].cve.uid), asset = tostring(resources[0].name)
| summarize arg_max(TimeGenerated, *) by EventId
```

## Elasticsearch / Elastic Security

1. Create an API key that can write to the target, e.g. with privileges
   `{"index": [{"names": ["logs-paddock.ocsf-*"], "privileges": ["create_doc", "auto_configure"]}]}`.
2. In Paddock, go to **Integrations → Add → Elastic** and fill in:

| field | value |
|---|---|
| `url` | `https://my-deployment.es.us-east-1.aws.elastic.cloud` |
| `data_stream` | default `logs-paddock.ocsf-default` (matches the built-in `logs-*-*` template, which needs `@timestamp`) |
| `pipeline` | optional ingest pipeline |
| secret `api_key` | the **encoded** key (base64 of `id:api_key`) |

Paddock calls `_bulk` with `create` actions, setting `_id` to the Paddock event
id. A `200` response can still contain item-level errors, so each item is
classified separately. `409` means the event is already indexed and counts as
delivered. `429`/`5xx` items make the batch retryable. Any other item error
(for example a mapping conflict) is permanent, so the batch is not retried
forever. Each document is the OCSF object plus `@timestamp` and
`event.{id,kind,dataset,action}`.

## Syslog (RFC 5424, CEF or OCSF JSON)

| field | default | notes |
|---|---|---|
| `host` | — | collector name or IP |
| `port` | 6514 (tls) / 514 | |
| `transport` | `tls` | `tls` (RFC 5425), `tcp` (RFC 6587 octet counting) or `udp` (RFC 5426) |
| `format` | `ocsf_json` | `ocsf_json` or `cef` |
| `facility` | 13 (log audit) | 0–23 |
| `app_name` / `hostname` | `paddock` | RFC 5424 header fields |
| `sd_id` | `paddock@32473` | 32473 is the RFC 5612 example enterprise number; use your own PEN if you have one |
| `ca_cert` | — | PEM CA bundle to trust for a private PKI (public data, not a secret) |
| `tls_verify` | `true` | `false` only for `allow_private` integrations |

**Paddock never sends plaintext syslog to a public host.** It refuses `tcp`
and `udp` unless the integration has `allow_private` **and** every address the
host resolves to is private or loopback. TLS uses TLS 1.2 or later and
verifies both the certificate and the host name. Paddock resolves the host once,
checks every address, and connects to the checked address (SNI still carries
the configured name), so a DNS rebind can't redirect the stream. Client
certificates (mTLS) are not supported yet.

Message layout:

```
<PRI>1 2026-11-21T10:00:00.123Z paddock paddock - finding.opened [paddock@32473 eventId="…" eventType="finding.opened" classUid="2002" severity="critical" findingUid="…"] MSG
```

`PRI = facility*8 + severity`. Severity is crit for critical, err for high,
warning for medium, notice for low and info for info. `MSG` is the compact
OCSF JSON or a CEF line. UDP datagrams are capped at 8 KiB. An oversized record
is sent without `vulnerabilities`, `remediation` and `observables`.

CEF extension keys:

| CEF key | Paddock / OCSF source |
|---|---|
| header *Signature ID* | rule id (e.g. `CVE-2021-44228`, `sast:python.sqli`), else the event type |
| header *Name* | `finding_info.title` |
| header *Severity* | `severity_id`: 1 becomes 1, 2 → 3, 3 → 5, 4 → 8, 5 → 10 |
| `rt` | OCSF `time` (ms) |
| `externalId` | `finding_info.uid` (the finding id) |
| `cat` | event type (`finding.opened`, …) |
| `msg` | `finding_info.desc` (1023 chars max) |
| `cs1` `ocsfClassUid` | 2002 / 2004 |
| `cs2` `status` | Paddock status |
| `cs3` `cve` | CVE ids, comma-separated |
| `cs4` `cwe` | CWE ids |
| `cs5` `ruleSource` | `cve_match`, `sast`, `sca`, … |
| `cs6` `assetKind` | asset kind |
| `dst` / `dhost` / `dvchost` / `duser` | asset value: `dst` for IPs, `dhost` for domains, `duser` for repositories, `dvchost` otherwise |
| `cn1` `cvss`, `cfp1` `epss` | original scores |
| `request` | deep link into the Paddock dashboard |

---

## Google SecOps (Chronicle)

`google_secops` sends events to the Chronicle **Ingestion API** with
service-account auth (the same JWT-bearer flow as the GCP connector: a signed
RS256 JWT exchanged at `oauth2.googleapis.com`, scope
`https://www.googleapis.com/auth/malachite-ingestion`; no Google SDK). The token
is cached and refreshed once on a 401.

1. In Google SecOps, create a service account with ingestion rights and download
   its JSON key. Note the SecOps **customer ID** (a GUID).
2. Create the integration: `customer_id`, `region` (`us` default, or `europe`,
   `europe-west2`, `asia-southeast1`, ...), and paste the key as the
   `service_account_json` secret. `ingestion_url` overrides the regional host.
3. Pick `format`:
   * `udm` (default): each event is sent as a **UDM** `GENERIC_EVENT` to
     `POST /v2/udmevents:batchCreate` (`{customer_id, events}`). No parser needed.
     The OCSF record from the shared mapping (below) is mapped to
     `security_result` (`summary`, `description`, `severity` INFORMATIONAL..CRITICAL,
     `rule_name`, `rule_id`, `category_details`, `url_back_to_product`), the asset
     becomes `target` (`ip`, `url` or `hostname`), `metadata.product_log_id` is the
     Paddock event id, and the complete OCSF record rides in `additional.ocsf`.
   * `ocsf`: the OCSF JSON is sent as raw log lines to
     `POST /v2/unstructuredlogs:batchCreate` with your `log_type` (default
     `PADDOCK_OCSF`; needs a custom log type with an OCSF-JSON parser).

Bodies are split at 1 MB and 200 events per request. HTTP 200 is success. 429
and 5xx are retryable; 400 (invalid UDM or unknown log type), 401/403 and a
malformed `customer_id` are not. **Test** sends one `integration.test` event
end to end, so a green test proves the key, the customer ID and the region.
Chronicle does not de-duplicate on `product_log_id`; Paddock may resend a batch
after a transient failure, so key detections on it.

---

## OCSF mapping

`app/integrations/ocsf.py` handles the mapping. The same function also backs
`GET /v1/export/findings.ocsf` (see [STANDARDS.md](STANDARDS.md)).

**Class selection.** A finding that refers to a CVE becomes a
**Vulnerability Finding (`class_uid 2002`)**. A finding refers to a CVE when
any of these is true:

* `rule_source = cve_match`;
* the rule id is `CVE-…`;
* the evidence or metadata has `cve`/`cve_ids` (SCA).

Every other finding, and every event that isn't about a finding
(`attack_path.opened`, `change.detected`, `device.behavior`, …), becomes a
**Detection Finding (`class_uid 2004`)**. `category_uid` is always 2
(Findings), and `type_uid = class_uid × 100 + activity_id`.

| OCSF field | Paddock source |
|---|---|
| `activity_id` | finding.opened → 1 Create. finding.updated, reopened and accepted → 2 Update. finding.resolved (or status `fixed`) → 3 Close. Operational events such as scan.* and integration.test → 99 Other |
| `severity_id` / `severity` | info → 1 Informational, low → 2, medium → 3, high → 4, critical → 5 |
| `status_id` / `status` | open → 1 New. triaged → 2 In Progress. accepted_risk, false_positive and wontfix → 3 Suppressed. fixed → 4 Resolved |
| `time` | event `occurred_at`, else finding `last_seen` (ms epoch) |
| `message` | finding title |
| `finding_info.uid` | finding id (or attack-path/change/device id for other events) |
| `finding_info.title` / `.desc` | title / description |
| `finding_info.types[]` | `rule_source` (or event type) |
| `finding_info.analytic` | `{uid: rule_id, name: rule_id, type: "Rule", category: rule_source}` |
| `finding_info.created_time` / `first_seen_time` | `first_seen` |
| `finding_info.modified_time` / `last_seen_time` | `last_seen` |
| `finding_info.src_url` | dashboard deep link (`Event.url`) |
| `resources[0]` | the asset: `uid` = asset id, `name` = value, `type` = asset kind, `labels` = `classification:<label>` |
| `observables[]` | asset value as Hostname (1), IP Address (2) or URL String (6) |
| `remediation.desc` / `.references` | `remediation` / `references` |
| `vulnerabilities[].cve.uid` | each CVE id |
| `vulnerabilities[].cve.cvss[]` | `{version, base_score, vector_string}` from the `cves` row, else the finding's `cvss` |
| `vulnerabilities[].cve.epss` | `{score, percentile}` |
| `vulnerabilities[].is_exploit_available` | CISA KEV flag (finding `metadata.kev` or `cves.known_exploited`) |
| `vulnerabilities[].cwe` | `{uid: "CWE-89", caption, src_url}` from evidence/metadata/`cves.cwe_ids` |
| `vulnerabilities[].affected_packages[]` | SCA `{name, version, package_manager, fixed_in_version}` |
| `vulnerabilities[].affected_code[]` | SAST `{file: {name, path}, start_line, end_line}` |
| `metadata.uid` | the **event id** (the idempotency key). For exports it is the finding id |
| `metadata.correlation_uid` | finding id (groups every event about one finding) |
| `metadata.product` | `{name: "Paddock", vendor_name: "Paddock", version}` |
| `metadata.version` | `1.3.0` |
| `metadata.tenant_uid` | `Event.tenant_id` |
| `unmapped.paddock` | **the original values**: `severity`, `status`, `rule_id`, `rule_source`, `cvss`, `epss`, `blast_score`, `classification`, `assigned_to`, `kev`, `impact`, `cwes`, `event_type` |

The mapping does **not** copy a finding's `evidence` wholesale, because it can
hold response snippets. Only the identifiers listed above leave Paddock. For
events that aren't about a finding, only scalar `data` fields go into
`unmapped.paddock.data`, up to 25 of them.

**Event payload shape.** For `finding.*` events, the mapping reads the finding
from `Event.data["finding"]`, or from top-level `data` when it contains
`rule_id`. It accepts optional `data["asset"]` (`{id, value, kind}`) and
`data["cve"]` (a `cves` row). Emitters that include these get the full mapping.
Emitters that don't still get a valid Detection Finding.
