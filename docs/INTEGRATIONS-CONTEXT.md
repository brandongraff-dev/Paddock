# Context connectors and network quarantine

Paddock's attack-path engine is only as good as the graph behind it. These
connectors pull **context** from systems you already run, and let a human
**quarantine** a misbehaving device from the Sentry sensor.

| Kind | Capability | What it adds | Writes to the customer system? |
|---|---|---|---|
| `aws` | SOURCE | EC2, ELB/ALB/NLB, security groups, RDS, IAM instance roles to S3, S3 exposure, Route53 | **never** |
| `microsoft_defender` | SOURCE | Defender for Endpoint devices (OS/build, exposure, risk, sensor health) + Intune (managed, compliant, primary user) | **never** |
| `crowdstrike` | SOURCE | Falcon hosts + prevention-policy status | **never** |
| `servicenow_cmdb` | SOURCE | CIs, owner, support group, business service, criticality (crown jewels) | **never** |
| `unifi` | ACTION | block a client / move it to a quarantine network, and release it | only after a human approves |
| `meraki` | ACTION | apply a quarantine group policy (or `Blocked`) to a client, and restore it | only after a human approves |

Code: `orchestrator/app/integrations/connectors/` (one module each),
`orchestrator/app/integrations/{ingest,runtime}.py`,
`orchestrator/app/routers/{integration_sync,network_actions}.py`,
`schema/025_context_connectors.sql`.

All connectors follow the shared contract (`app/integrations/base.py`):
secrets are stored AES-GCM encrypted and never logged or returned; every
customer-configurable URL passes `netsafety.validate_outbound_url` (HTTPS,
no cloud-metadata or reserved ranges, private/LAN only with the integration's
`allow_private` opt-in); redirects are not followed (Meraki shard hosts under
`*.meraki.com` excepted, each hop re-validated); error text is written by
Paddock (status code + what was being done), never copied from a response.

---

## 1. How SOURCE syncs run

1. Create the integration (kind, config, secrets) through the Integrations API.
2. The orchestrator scheduler (`app/scheduler.py`) starts one background
   sweep per tick. Every **enabled** SOURCE integration whose last run is older
   than `config.sync_interval_minutes` (default 360, floor 15; CMDB 720) is
   pulled. A slow cloud never delays scan schedules.
3. The batch is written through the orchestrator's **own** bulk handlers
   (`/v1/assets/bulk`, `/v1/edges/bulk`, `/v1/findings/bulk`), so canonical
   forms, upserts and `asset_added` / `finding_opened` events are identical to
   every other producer. Owner rules go into `asset_owners`.
4. Every run is a row in `integration_sync_runs` (status, counts, a scrubbed
   detail), `integrations.last_ok_at` / `last_error` are updated, and an
   `integration_sync` row is appended to the audit log. One run at a time per
   integration (a partial unique index makes the claim multi-replica safe;
   runs stuck for 2 h are marked `abandoned`).

Endpoints:

```
GET  /v1/integration-sync                 latest run per SOURCE integration
GET  /v1/integration-sync/{id}/runs       history
POST /v1/integration-sync/{id}            sync now (admin)
```

`PADDOCK_SOURCE_SYNC=0` pauses scheduled pulls. Per-integration options:
`sync_interval_minutes`, `sync_timeout_sec` (default 900).

### Merging onto assets Paddock already knows

EDR/MDM/CMDB records carry a merge hint (`merge_on: {ips, hostnames, macs}`).
Ingest attaches the record's metadata to every **existing** asset that matches
(at most 20): `ipv4`/`ipv6` by address, IoT/OT devices by IP or MAC, EC2
instances by private IP, `domain`/`subdomain` by FQDN, any asset by
`metadata.hostname` or `metadata.mac`. `tags` are unioned. Only when nothing
matches is a new asset created (the private IP, else the FQDN); a record with
neither (e.g. a phone known only by name) is dropped unless something matches.
Findings on such records land on every matched asset.

Deliberately **not** used for merging: EDR "external IP" (a whole office
shares one NAT address) and secondary NICs (Docker/Hyper-V bridges share
addresses across thousands of machines).

Metadata written: `hostname`, `os`, `os_version`, `owner`, `owner_team`,
`managed`, `compliant`, `exposure_level`, `edr`, `mac`, plus one namespaced
block per source (`mde`, `intune`, `crowdstrike`, `servicenow`). Crown jewels
get `crown_jewel: true`, data stores `sensitive: true`; internet-reachable
things get `public: true`. These are exactly the flags the attack-path engine
uses for targets and sources.

All findings use `rule_source = policy` and `metadata.source = integration:<kind>`.

---

## 2. AWS

**Pulls** (per region in `regions`, or `["all"]`): EC2 instances, security
groups, ELBv2 + classic ELB (listeners, registered targets), RDS instances;
globally: IAM instance profiles → roles → S3 grants, S3 buckets (account +
bucket Public Access Block, ACL, policy status), Route53 public zones (private
zones with `include_private_zones`).

**Graph**

```
subdomain --routes_to--> load balancer --routes_to--> EC2 instance --has_role--> IAM role --can_access--> S3 bucket
subdomain --resolves_to--> ipv4 --attached_to--> EC2 instance --can_reach--> RDS instance
```

* `public: true` on internet-facing LBs, on instances with a public IP behind
  a security group that admits 0.0.0.0/0 or ::/0, and on records resolving to
  either. S3 buckets and RDS instances get `sensitive: true`
  (`data_stores_are_crown_jewels`, default on); anything tagged with one of
  `crown_jewel_tags` (`"Key"` or `"Key=Value"`) gets `crown_jewel: true`.
* `role --can_access--> bucket` comes from the role's inline and attached
  policies (customer-managed are read; AWS-managed `AdministratorAccess`,
  `PowerUserAccess`, `AmazonS3FullAccess`, `AmazonS3ReadOnlyAccess`,
  `ReadOnlyAccess` are known). It is a conservative over-approximation:
  conditions and Deny statements are not evaluated.
* `instance --can_reach--> RDS` only when the database's security group admits
  the instance's security group or private IP.
* There are **no** edges to the account or to security groups: the engine
  walks edges undirected, and such hubs would invent lateral paths.

**Findings**: `aws.rds.publicly_accessible` (high; critical when a security
group also admits the internet on the DB port), `aws.s3.bucket_public` (high),
`aws.ec2.admin_port_open_to_internet` (high, on the instance),
`aws.ec2.sg_admin_port_open_to_world` (medium, on the group). Admin ports
default to SSH/RDP/SMB/Telnet/Docker/etcd and common databases; override with
`admin_ports`.

**Credentials** (recommended: a role in each account, assumed with an
external id):

* config `role_arn`, secret `external_id`;
* the orchestrator's own credentials come from secrets `access_key_id` /
  `secret_access_key` (/ `session_token`), or, if empty, the default AWS
  chain (instance profile / IRSA of the host running Paddock).

Install the optional dependency: `pip install 'paddock-orchestrator[aws]'`
(boto3).

**Trust policy** on the role in the customer account:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::<PADDOCK_ACCOUNT_ID>:role/<paddock-orchestrator>"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:ExternalId": "<EXTERNAL_ID>"}}
  }]
}
```

**Permissions policy** (exactly what the connector calls; read-only):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PaddockInventory",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "rds:DescribeDBInstances",
        "route53:ListHostedZones",
        "route53:ListResourceRecordSets"
      ],
      "Resource": "*"
    },
    {
      "Sid": "PaddockIamPaths",
      "Effect": "Allow",
      "Action": [
        "iam:GetInstanceProfile",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion"
      ],
      "Resource": "*"
    },
    {
      "Sid": "PaddockS3Exposure",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketTagging"
      ],
      "Resource": "*"
    }
  ]
}
```

No `s3:GetObject`, no `Put*`/`Create*`/`Delete*`, no `iam:Pass*`. (The AWS
managed `SecurityAudit` policy also covers this but is much broader.)
Missing permissions do not fail the sync: each failed call becomes a warning
in the run's `detail` ("partial: s3:GetBucketPolicyStatus: AccessDenied").

---

## 3. Microsoft Defender for Endpoint + Intune

**Setup**: Entra ID → App registrations → New registration (single tenant) →
Certificates & secrets → client secret. API permissions (type
**Application**), then **Grant admin consent**:

| API | Permission | Why |
|---|---|---|
| WindowsDefenderATP | `Machine.Read.All` | devices, OS build, exposure level, risk score, sensor health, IP/MAC |
| Microsoft Graph | `DeviceManagementManagedDevices.Read.All` | Intune managed/compliant, primary user |

Config: `tenant_id`, `client_id`; secret: `client_secret`. Toggle either half
with `include_defender` / `include_intune`. Sovereign clouds: override
`login_url`, `graph_url`, `defender_url` (they must still pass netsafety).

Records are joined on the Entra device id (falling back to the host name);
the Intune primary user becomes `metadata.owner`. With `emit_owner_rules`
an `owner:<upn>` tag and an owner rule are created per user (off by default).

**Findings**: `msdefender.device_noncompliant` (medium),
`msdefender.high_exposure` (medium), `msdefender.high_risk` (high),
`msdefender.sensor_not_reporting` (low).

## 4. CrowdStrike Falcon

**Setup**: Falcon console → Support and resources → API clients and keys →
Add new API client with **only** these scopes:

* `Hosts`: **Read**
* `Prevention policies`: **Read**

(Never `Hosts: Write`: that scope can network-contain hosts.)

Config: `client_id`, `cloud` (`us-1`, `us-2`, `eu-1`, `us-gov-1`) or
`base_url`, optional `member_cid` (Flight Control), optional FQL `filter`;
secret: `client_secret`.

**Findings**: `crowdstrike.prevention_policy_not_applied` (medium),
`crowdstrike.prevention_policy_disabled` (high),
`crowdstrike.reduced_functionality_mode` (medium). Containment status is
recorded as `metadata.contained`.

## 5. ServiceNow CMDB

**Setup**: create an integration user (`Web service access only`) with a
custom role that has **read** ACLs on exactly:

* the CI tables you sync (default `cmdb_ci_computer`, which includes servers),
* `cmdb_ci_service` and `cmdb_rel_ci` (business-service mapping),
* `sys_user` / `sys_user_group` `email` fields (owner contacts),

plus `snc_platform_rest_api_access` if your instance enforces REST API
access. `cmdb_read` works too on recent releases; `itil` is broader than
needed.

Config: `instance_url`, `tables`, optional encoded `query` (e.g.
`operational_status=1`), `crown_jewel_criticalities` (default
`["1 - most critical"]`, matched against the business service's
`busines_criticality`). Secrets: `username` + `password`, or `oauth_token`.
An on-prem instance on a private address needs `allow_private`.

**Mapping**: support group → `owner_team` + an `asset_owners` rule matching the
tag `owner:<group>` (contact = the group's email), so findings on those assets
route to that team; `owned_by` → `owner`; business service →
`business_service(s)`; critical service → `crown_jewel: true` (an attack-path
target).

---

## 6. Network quarantine (UniFi, Meraki) through the approve gate

ACTION connectors are **never** called by the scheduler or by a detector. The
only caller is `POST /v1/fleet/network-actions/{id}/execute`, and only for an
action a human approved through the **existing fleet gate**
(`agent_actions`, `app/routers/fleet.py`): four-eyes approval, `dry_run` by
default, audit on every transition, first-class revert.

```
Sentry finding device_lateral_scan
   │  POST /v1/fleet/network-actions/from-finding {finding_id, integration_id}
   ▼
proposed (dry_run=true, no agent, integration_id set)
   │  POST /v1/fleet/actions/{id}/approve {"apply_for_real": true}   admin, approver ≠ requester
   ▼
approved ──POST /v1/fleet/network-actions/{id}/execute──▶ applied (revert plan stored) │ failed
   │
   │  POST /v1/fleet/actions/{id}/revert          (mints the release, auto-approved: de-escalation)
   ▼
revert row ──POST /v1/fleet/network-actions/{revert_id}/execute──▶ original becomes `reverted`
```

* Approving **without** `apply_for_real` authorises a **dry run** only:
  execute performs read calls (it confirms the client exists) and stores the
  calls a real run would make under `result.dry_run_preview`; the action stays
  `approved`. A real quarantine needs a new proposal approved for real.
* Manual proposals: `POST /v1/fleet/network-actions {integration_id, mac,
  action_type: quarantine_device|release_device, reason, finding_id?}`.
  Only `device_lateral_scan` findings convert automatically; the device's MAC
  comes from the Sentry asset.
* Guards: valid unicast MAC only; never a MAC in the integration's
  `protected_macs` (put your gateway, core switches and the Sentry sensor
  there); the integration must be enabled and declare ACTION; one open
  proposal per device; one execution at a time; a *release* cannot be
  "reverted" back into a quarantine (that would skip approval); unknown
  request fields are rejected.
* Audit: `propose`, `approve`/`deny`, `execute_dry_run`, `apply`/`fail`,
  `revert`, `reverted` under `resource_type = fleet_action`, with integration,
  MAC and outcome, never credentials. `GET /v1/fleet/network-actions` lists
  them; they also appear in `GET /v1/fleet/actions` (with `agent_id = null`).
  Host agents never receive them.

### UniFi Network

Config: `base_url` (e.g. `https://192.168.1.1`), `controller_type`
(`unifi_os` for UDM/UCG/Cloud Key Gen2+/UniFi OS Server, `classic` for the
self-hosted application on :8443), `site` (the short site *name* from the
URL), `quarantine_mode`:

* `block` (default): `cmd/stamgr block-sta` / `unblock-sta`. Wired and wireless.
* `network`: per-client virtual network override to `quarantine_network_id`,
  then `kick-sta` so wireless clients re-associate into it (wired clients move
  on their next link/DHCP cycle). Release restores the previous override.

Credentials, least privilege: an **API key** (UniFi Network 9+: Settings →
Control Plane → Integrations), created by a **local** admin whose role is
limited to the Network application with *Site Admin* on the target site only;
or that admin's `username` / `password` (cookie + CSRF login, logged out after
every call). `test()` only reads the site list.

The controller is on your LAN, so enable the integration's `allow_private`
(a deliberate, audited opt-in). Prefer a valid certificate; `verify_tls:
false` is honoured **only** together with `allow_private`.

### Cisco Meraki

Config: `network_id`, `quarantine_policy` = `group_policy` (with
`group_policy_id`) or `blocked`; optional `base_url` for the China / Canada /
government dashboards. Create a *Quarantine* group policy in Dashboard
(Network-wide → Group policies) that denies everything except what remediation
needs (DHCP, DNS, your portal).

Credentials, least privilege: a Dashboard API key of an admin with **network**
access (full) on the target network(s) only, **not** an organization admin.
Quarantine reads the client's current policy first and stores it as the revert
plan; release restores it (or `Normal`). `test()` only reads the network.

---

## 7. Not done yet (honest list)

* GCP and Azure connectors; AWS Lambda, EKS, API Gateway, CloudFront, NAT and
  peering paths; S3 bucket policies that grant other principals; SG-to-SG
  reachability beyond instance → RDS.
* Resources that disappear are not deleted; they simply stop refreshing
  `last_seen`.
* Entra certificate credentials (client secret only); ServiceNow mutual TLS.
* Aruba, Fortinet, Palo Alto, pfSense/OPNsense quarantine; switch-port
  shutdown for wired UniFi clients in `network` mode.
* Auto-approval policies ("quarantine IoT scanners at night"): every network
  action needs a human today.
* The orchestrator container image does not install `boto3` yet; build it
  with the `aws` extra to use the AWS connector.
