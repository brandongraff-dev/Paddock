# Two-way ticketing: Jira, ServiceNow, Linear

Findings become tickets in the customer's tracker, and closing the ticket
closes the finding. This page covers how it works, how to set up each tool,
including the webhook or Business Rule you create on their side, and how
statuses map in both directions.

Code: `orchestrator/app/integrations/connectors/{jira,servicenow,linear}.py`
(the connectors), `connectors/_ticketing.py` (their shared base),
`integrations/links.py` (finding to ticket links), `integrations/ticketing.py`
(applying inbound changes), and `routers/integrations_inbound.py` (the
public callback endpoint). Schema: `015_integrations.sql` and
`017_ticketing.sql`.

## How it works

```
 Paddock finding event ──► delivery worker ──► connector.deliver()
   finding.opened          (retries,             create / update issue
   finding.updated          idempotent on         transition to done / back
   finding.resolved         event.id)             comment
   finding.reopened                               └─► integration_links row
   finding.accepted

 Ticket changes ──► POST /v1/integrations/<id>/inbound ──► connector.handle_inbound()
   (webhook / Business Rule)   token and/or signature        verify + translate
                                                             └─► finding status + note
                                                                 audit: integration:<kind>:<name>
                                                                 link.external_status
                                                                 follow-up event, origin = this integration
```

| Paddock event      | What happens in the ticket system                                  |
|--------------------|--------------------------------------------------------------------|
| `finding.opened`   | Create the ticket. If one already exists, refresh it, and reopen it if it is done. |
| `finding.updated`  | Update the title, description and priority. Create the ticket if the finding has none. |
| `finding.resolved` | Move it to done and add a comment. Does nothing if it is already done. |
| `finding.reopened` | Move it back to To Do/New and add a comment. Creates the ticket if missing. |
| `finding.accepted` | Add a comment (`[Paddock] Finding marked accepted …`, with the reason). |

**Idempotency.** Before creating a ticket, the connector looks up
`integration_links` for (integration, finding). If no link row exists, it
searches the tracker for the marker `paddock-<finding-id>`, which every
ticket carries (a Jira label, a ServiceNow `correlation_id`, or a line in the
Linear description). Transitions are skipped when the ticket is already in
the target state, so a retried event changes nothing.

**Loop prevention.** A status change that came from a ticket system emits its
follow-up event with `data.origin = {integration_id, kind, name,
external_id}`, and the finding's `metadata.status_origin` records the same
thing. A ticket connector drops an event whose origin is its own integration
(or, when it is unbound, the same kind and ticket), so Jira closing an issue
does not lead Paddock to "close" it again. Other integrations, such as Slack,
still receive the event. Comments that Paddock posts start with `[Paddock]`
and are never imported back as notes.

## The inbound endpoint

`POST /v1/integrations/<integration-id>/inbound`

* **Public route.** It bypasses session/API-key auth through one explicit
  rule in `app/auth.py` (`POST` on this exact path only). Each request is
  authenticated per integration instead:
  * **Signature** (preferred). Jira `X-Hub-Signature: sha256=…`, Linear
    `Linear-Signature`, or the ServiceNow shared-secret header. **If a
    signing secret is configured, the signature is required**, and an
    inbound token does not excuse a missing or bad one.
  * **Inbound token.** When no signing secret is configured, the request
    must carry the integration's `inbound_token` as `?token=…` or as
    header `X-Paddock-Token`. A token that is present but wrong always
    gets a 401. The token is never accepted in the path, because access
    logs and the audit trail record the path.
  * All comparisons are constant time.
* **Responses.**

  | Code | When |
  |------|------|
  | 404 | Unknown, disabled or non-ticketing integration (also returned for a malformed id) |
  | 401 | Bad token or signature |
  | 400 | Malformed JSON |
  | 413 | Body over 1 MiB |
  | 429 | More than `PADDOCK_INBOUND_RATE_PER_MIN` (default 120) requests per minute for that integration (in-process window) |
  | 503 | The integration's secrets cannot be decrypted (key rotated away) |
  | 200 | `{received, applied, ignored, results[]}` |

* **Replay protection.** The delivery id is stored in
  `integration_inbound_deliveries` (017) and a repeat is answered with
  `{"duplicate": true}`. The id comes from Jira's
  `X-Atlassian-Webhook-Identifier`, Linear's `Linear-Delivery`, or the
  Business Rule's `X-Paddock-Delivery`. Linear deliveries must also be
  within 60 s of `webhookTimestamp`.
* **What gets applied.** Each update is resolved to a finding through
  `integration_links`. A ticket with no link but carrying a valid
  `paddock-<id>` marker is adopted, unless that finding is already linked
  to another ticket on the same integration (a relabelled issue cannot
  hijack a finding). For each update the endpoint:
  * sets the finding status;
  * appends a note to `findings.metadata.integration_notes` (the last 50
    are kept);
  * stores the remote status in `integration_links.external_status`;
  * writes an audit record with actor `integration:<kind>:<name>` and role
    `integration`.

  Set `"sync_inbound_status": false` in an integration's config to import
  comments only.

### Status mapping and degradation

Paddock statuses: `open`, `triaged`, `fixed`, `accepted`, `false_positive`.
If the `findings.status` CHECK constraint does not allow a status yet, the
endpoint falls back:

* `accepted` becomes `accepted_risk`, then `wontfix`.
* `false_positive` becomes `accepted`, then `accepted_risk`.
* If nothing fits, the status is left unchanged and a note says so.

The response reports `degraded_from` whenever a fallback was used.

Every connector also accepts `status_map` in its config: a map from the
remote status name (or ServiceNow value, or Linear state type) to a Paddock
status. It wins over the defaults below.

## Jira

**Paddock config.**

| Setting | Value |
|---------|-------|
| `base_url` | `https://acme.atlassian.net` (Cloud) or your Data Center URL |
| `deployment` | `cloud` (REST v3, ADF descriptions) or `datacenter` (REST v2, wiki markup) |
| `project_key` | Project to file issues in |
| `issue_type` | Default `Bug` |
| `priority_map` | Severity to Jira priority name. Default: critical=Highest, high=High, medium=Medium, low=Low, info=Lowest. Set `set_priority: false` if priority is not on your create screen. |
| `component`, `labels` | Optional |
| `done_transition`, `reopen_transition` | Transition or status names. By default the first transition into a Done-category (or To Do-category) status is used. |
| `done_resolution` | Optional. Data Center close screens often require a resolution. |
| `email` | Cloud only |

**Secrets.** Cloud: `api_token` (from id.atlassian.com → Security → API
tokens). Data Center: `pat` (a personal access token). Optional for both:
`webhook_secret`.

The issue description (ADF on Cloud) contains:

* severity, asset, rule, CVSS/EPSS/KEV;
* *Why it matters*;
* *Remediation*;
* an *Open in Paddock* deep link (from the event URL, or
  `PADDOCK_PUBLIC_URL`/findings/<id>);
* the `paddock-<id>` marker (also added as a label: do not remove it).

The account needs Browse, Create, Edit, Transition and Add Comments on the
project.

**Inbound webhook (Jira Cloud).** In *Settings → System → WebHooks →
Create a WebHook*:

1. URL: `https://<paddock>/v1/integrations/<id>/inbound`
2. Secret: generate a random value and also save it as the integration's
   `webhook_secret`. Jira then signs every request with `X-Hub-Signature`.
3. Events: *Issue → updated*, *Comment → created*. JQL filter:
   `labels = paddock`.

**Data Center** (no signing), or **Jira Automation** (*Send web request*):
use `https://<paddock>/v1/integrations/<id>/inbound?token=<inbound_token>`
and leave `webhook_secret` empty. For Automation, send the issue as the
"Issue data (Jira format)" body.

**Mapping.** Only changes whose changelog touches `status` or `resolution`
change the finding; other edits are ignored.

| Jira status category | Resolution | Paddock status |
|---|---|---|
| To Do (`new`) | | `open` |
| In Progress (`indeterminate`) | | `triaged` |
| Done | Won't Do / Won't Fix / Risk Accepted | `accepted` |
| Done | Not a Bug / Invalid / Cannot Reproduce / False Positive | `false_positive` |
| Done | Duplicate | (ignored) |
| Done | anything else | `fixed` |

## ServiceNow

**Paddock config.**

| Setting | Value |
|---------|-------|
| `instance_url` | `https://acme.service-now.com` |
| `table` | `incident` (default) or `sn_vul_vulnerable_item` (Vulnerability Response) |
| `auth_method` | `basic` (`username` plus secret `password`) or `oauth` (secrets `client_id` and `client_secret`; enable the client-credentials grant on the OAuth application registry entry) |
| `assignment_group`, `category`, `caller_id`, `extra_fields` | Optional, merged into created records |
| `severity_map` | Default: critical 1/1, high 1/2, medium 2/2, low 2/3, info 3/3 (impact/urgency) |
| `resolved_state` / `reopen_state` | Defaults: incident 6/2, vulnerable item 3/1 |
| `close_code` | Default `Solution provided` |
| `comment_field` | `work_notes` (default) or `comments` |
| `inbound_secret_header` | Default `X-Paddock-Secret` |

**Secrets.** `password` or `client_id`/`client_secret`, plus
`inbound_secret`.

The integration user needs the `itil` role (or `sn_vul.remediation_owner`
for Vulnerability Response), plus read/write on the table. Records are keyed
by `correlation_id = paddock-<finding-id>`.

**Inbound Business Rule.** Create it under *System Definition → Business
Rules → New*:

* Table: your table
* Advanced: ✓
* When: **after**
* Update: ✓
* Condition: `current.correlation_id.startsWith('paddock-') && (current.state.changes() || current.comments.changes() || current.work_notes.changes())`

Store the shared secret in a private system property, for example
`x_paddock.inbound_secret`, readable by admin only. Then use this script:

```javascript
(function executeRule(current, previous) {
    var r = new sn_ws.RESTMessageV2();
    r.setEndpoint('https://<paddock>/v1/integrations/<integration-id>/inbound');
    r.setHttpMethod('post');
    r.setRequestHeader('Content-Type', 'application/json');
    r.setRequestHeader('X-Paddock-Secret', gs.getProperty('x_paddock.inbound_secret'));
    r.setRequestHeader('X-Paddock-Delivery', gs.generateGUID());
    var note = '';
    if (current.comments.changes()) note = current.comments.getJournalEntry(1);
    r.setRequestBody(JSON.stringify({
        sys_id: current.getUniqueValue(),
        number: current.getValue('number'),
        table: current.getTableName(),
        state: current.getValue('state'),
        state_label: current.getDisplayValue('state'),
        close_code: current.getValue('close_code'),
        substate: current.getDisplayValue('substate'),
        correlation_id: current.getValue('correlation_id'),
        updated_by: current.getValue('sys_updated_by'),
        comment: note
    }));
    r.executeAsync();   // never block the user's save on Paddock
})(current, previous);
```

The body can also be a JSON array of such objects (at most 100 are
processed). If you cannot store a secret, leave `inbound_secret` empty and
append `?token=<inbound_token>` to the endpoint instead.

**Mapping.** For `fixed`/`accepted` states, a `close_code` or `substate`
mentioning *false positive* gives `false_positive`, and one mentioning
*risk accepted*, *deferred* or *exception* gives `accepted`.

| Table | State values → Paddock status |
|-------|-------------------------------|
| incident | 1 New → `open`; 2 In Progress / 3 On Hold → `triaged`; 6 Resolved / 7 Closed → `fixed`; 8 Canceled → `accepted` |
| sn_vul_vulnerable_item | 1 Open → `open`; 2 / 10 / 11 → `triaged`; 3 Closed → `fixed`; 13 Deferred → `accepted` |

Check these values against your instance's choice list. Use `status_map`
(keyed by value or label) for anything custom.

## Linear

**Paddock config.**

| Setting | Value |
|---------|-------|
| `team_id` | Team UUID (Cmd/Ctrl-K → "Copy model UUID") |
| `project_id` | Optional |
| `label_ids` | Labels always applied |
| `label_map` | Severity to label id |
| `priority_map` | Default: critical=1 Urgent, high=2, medium=3, low=4, info=0 |
| `done_state_id` / `reopen_state_id` | Default: the team's first `completed` / `unstarted` state |
| `canceled_status` | `accepted` (default), `false_positive` or `fixed` |

**Secrets.**

* `api_key`: a personal API key `lin_api_…` (sent as-is), or an OAuth access
  token (sent as Bearer).
* `webhook_secret`: the webhook's signing secret.

**Inbound webhook.** In *Settings → API → Webhooks → New webhook*:

* URL: `https://<paddock>/v1/integrations/<id>/inbound`
* Team: the same team as `team_id`
* Resource types: **Issues** and **Comments**
* Copy the **signing secret** into the integration's `webhook_secret`.

Linear signs every delivery (`Linear-Signature`, HMAC-SHA256 of the raw
body). Paddock also rejects deliveries whose `webhookTimestamp` is more than
60 s old.

**Mapping.** Only updates that change `stateId` change the finding.

| Linear state type | Paddock status |
|---|---|
| triage / backlog / unstarted | `open` |
| started | `triaged` |
| completed | `fixed` |
| canceled | `canceled_status` (default `accepted`) |

## For the delivery worker

Ticket connectors work with the plain `Connector(config, secrets, http)`
contract. In that mode they deduplicate through the remote marker. For link
persistence and exact loop prevention, call

```python
from app.integrations.ticketing import deliver_ticket
result = await deliver_ticket(pool, integration_row, event, http=client)
```

Alternatively, call `connector.bind(integration_id=row["id"], pool=pool,
allow_private=row["allow_private"])` before `deliver()`. Every outbound URL
passes `netsafety.validate_outbound_url(url, allow_private=…)` and redirects
are refused. A self-hosted Jira or ServiceNow on the LAN therefore needs
`allow_private` on that integration. Error details never contain secret
values: they are scrubbed before they reach `DeliveryResult.detail`.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `PADDOCK_INBOUND_RATE_PER_MIN` | 120 | Inbound requests per integration per minute (per orchestrator process) |
| `PADDOCK_PUBLIC_URL` | (unset) | Base URL for "Open in Paddock" links when an event has no `url` |
| `PADDOCK_SECRET_KEY` | (shared) | Decrypts integration secrets (see `integrations/secrets.py`) |

## Troubleshooting

| Symptom | Fix |
|---|---|
| 401 on every webhook | A `webhook_secret` / `inbound_secret` is configured but the sender is not signing. Configure the secret on the sender, or clear it and use `?token=`. |
| `result: "unlinked"` | The ticket was not created by this integration and carries no `paddock-<id>` marker (or that finding is already linked to another ticket). |
| `degraded_from` in responses | Your database has not been migrated to the newer finding statuses yet. This is expected and harmless. |
| `no Jira transition … is available` | The workflow has no direct transition to Done (or back). Set `done_transition` / `reopen_transition`. |
