# Single sign-on (OIDC + SAML) and SCIM provisioning

Paddock can delegate sign-in to your identity provider (IdP), map IdP groups
to Paddock roles and clearances, and let the IdP create, update and
deactivate Paddock users over SCIM 2.0.

| | Supported |
|---|---|
| **OIDC** | Okta, Microsoft Entra ID, Google Workspace, Auth0, Keycloak, any provider with discovery |
| **SAML 2.0** | Any IdP that signs assertions (Okta, Entra ID, ADFS, Ping, JumpCloud, Keycloak, …) |
| **SCIM 2.0** | Okta, Microsoft Entra ID (and any RFC 7644 client) |

Everything below is configured in the dashboard under **Settings → Identity**
(admins only) or through the API listed at the end. Every change and every SSO
sign-in, successful or not, is written to the hash-chained audit log.

---

## 0. Before you start

Set these in `.env` (see `.env.example`) and restart the orchestrator:

| Variable | Example | Why |
|---|---|---|
| `SSO_BASE_URL` | `https://paddock.example.com` | Public URL of the orchestrator. Redirect URIs, the SAML ACS + entity ID and the SCIM base URL are built from it. Use `https://` in production. |
| `SSO_DASHBOARD_URL` | `https://paddock.example.com` | Where the dashboard is served. Sign-in finishes at `<this>/sso/callback`. |
| `PADDOCK_SECRET_KEY` | 32 random bytes, urlsafe-base64 | Encrypts OIDC client secrets at rest. **Required** in `AUTH_MODE=enforce` before a client secret can be saved. |

```bash
python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

If the dashboard and the API share an origin behind a reverse proxy, both
`/v1/*` and `/scim/*` must reach the orchestrator (the bundled
`dashboard/nginx.conf` proxies both); then `SSO_BASE_URL` and
`SSO_DASHBOARD_URL` are the same URL.

In the snippets below, replace `paddock.example.com` with your host and
`<slug>` with the slug you give the provider in Paddock (e.g. `okta`).

| Value the IdP asks for | Paddock value |
|---|---|
| OIDC redirect / callback URI | `https://paddock.example.com/v1/auth/sso/<slug>/callback` |
| SAML ACS (Reply URL, Single sign-on URL) | `https://paddock.example.com/v1/auth/sso/<slug>/acs` |
| SAML SP entity ID (Audience URI, Identifier) | `https://paddock.example.com/v1/auth/sso/<slug>/metadata` |
| SAML SP metadata | `https://paddock.example.com/v1/auth/sso/<slug>/metadata` |
| SCIM base URL (Tenant URL) | `https://paddock.example.com/scim/v2` |

The provider editor shows the exact values (with copy buttons) once a
provider is saved.

---

## 1. How roles are decided

Each provider has an ordered list of **mappings**: `IdP group → role (+ optional clearance)`.

* Mappings are checked **top to bottom; the first group the user belongs to wins.**
  Put your most privileged mapping first.
* Group names match case-insensitively.
* No match → the provider's **default role / clearance** (`viewer` / `internal`
  out of the box), or a denied sign-in if **Deny users with no matching group**
  is on.
* With **Sync role on every sign-in** (default), the IdP stays the source of
  truth: a user removed from `paddock-admins` is demoted on their next sign-in.
  Roles are read live on every request, so an SCIM group change takes effect
  immediately, without waiting for a new sign-in.
* Where the groups come from is the provider's **groups claim**: `groups` by
  default; a dotted path for nested claims (Keycloak `realm_access.roles`); an
  exact key for namespaced claims (Auth0 `https://paddock/groups`); for SAML the
  **groups attribute**.

**Account linking.** On first sign-in Paddock looks for an existing account in
this order:

1. an identity already linked to this provider + subject (`sub` / NameID);
2. a SCIM-provisioned user whose `externalId` equals the token's `sub` (Okta)
   or `oid` (Entra ID);
3. a user with the same email, **only if the IdP asserts the email is
   verified** (`email_verified: true`; SAML assertions count as verified).
   Entra ID emails are never trusted for linking (see the *nOAuth* class of
   bugs); Entra links via `oid` instead;
4. otherwise, with **Just-in-time provisioning** on, a new account is created
   (`username` = email), with no password.

**Break-glass accounts** (Settings → Identity → Sign-in policy, `admin` by
default) can never be claimed or created by an IdP identity, are never touched
by role sync or SCIM, and are the only accounts that keep password sign-in
when SSO is required.

**Allowed email domains** (per provider): when set, the user's email domain
must be on the list (Google Workspace: the `hd` hosted-domain claim must be too).

---

## 2. OIDC: Okta

1. Okta Admin Console → **Applications → Create App Integration** →
   **OIDC – OpenID Connect** → **Web Application**.
2. **Sign-in redirect URIs:** `https://paddock.example.com/v1/auth/sso/okta/callback`.
   Grant type: **Authorization Code** only. Remove the sign-out redirect.
3. **Assignments:** the people or groups allowed into Paddock. Save, then copy
   the **Client ID** and **Client secret**.
4. Emit a groups claim in the ID token:
   * *Org authorization server* (issuer `https://your-org.okta.com`): app →
     **Sign On** tab → **OpenID Connect ID Token** → Groups claim type
     **Filter**, name `groups`, *Starts with* `paddock-` (or *Matches regex* `.*`).
   * *Custom authorization server* (issuer `https://your-org.okta.com/oauth2/default`):
     **Security → API → Authorization Servers → default → Claims → Add Claim**:
     name `groups`, include in **ID Token / Always**, value type **Groups**,
     filter as above.
5. Paddock → Settings → Identity → **Add provider** → *Okta*:
   * Issuer URL: as above (exactly what Okta shows as *Issuer*).
   * Client ID / secret from step 3; slug `okta`.
   * Mappings, e.g. `paddock-admins → admin / restricted`,
     `paddock-analysts → analyst / confidential`, `paddock-auditors → auditor`.
6. Use **Test** on the provider row (runs discovery + fetches the JWKS), then
   sign out and use **Continue with Okta**.

## 3. OIDC: Microsoft Entra ID

1. Entra admin center → **App registrations → New registration**.
   * Supported account types: **Accounts in this organizational directory only**.
   * Redirect URI: **Web** → `https://paddock.example.com/v1/auth/sso/entra/callback`.
2. **Certificates & secrets → New client secret**: copy the *Value*.
3. Roles — recommended: **App roles → Create app role** for each Paddock role
   (e.g. value `Paddock.Admin`, `Paddock.Analyst`; allowed member types
   *Users/Groups*). Then **Enterprise applications → (your app) → Users and
   groups → Add user/group** to assign them. They arrive in the ID token's
   `roles` claim.
   *Alternative:* **Token configuration → Add groups claim → Security groups**
   emits group **object IDs** in `groups` (map on the GUIDs). Users in more than
   200 groups get an "overage" pointer instead of the list; Paddock resolves
   it through Microsoft Graph (see *Group overage* below), or use app roles,
   which never overflow.
4. Optional: **Token configuration → Add optional claim → ID → email, upn**.
5. Paddock → **Add provider** → *Microsoft Entra ID*:
   * Issuer: `https://login.microsoftonline.com/<tenant-id>/v2.0`
   * Client ID = *Application (client) ID*, secret from step 2, slug `entra`.
   * Groups claim: `roles` (app roles) or `groups` (object IDs).
   * Mappings, e.g. `Paddock.Admin → admin`, `Paddock.Analyst → analyst`.

Entra users are linked by their immutable object ID (`oid`), never by email.
If you also use SCIM (§7), set the SCIM `externalId` mapping to `objectId` so
SSO and SCIM resolve to the same Paddock account.

### Group overage (Entra, OIDC and SAML)

When a user is in too many groups (200 in a JWT, 150 in a SAML assertion) Entra
leaves the groups out and says so: `hasgroups: true` or `_claim_names.groups`
in the ID token, or the attribute
`http://schemas.microsoft.com/claims/groups.link` in the assertion. Paddock then
asks Microsoft Graph (`transitiveMemberOf`, so nested groups count; paged,
up to 50 pages) for the user's groups. Two ways, per provider:

| Mode | How | Needs |
|---|---|---|
| `delegated` (OIDC default) | `GET /v1.0/me/transitiveMemberOf` with the user's own access token | Add a Graph scope such as `User.Read` to **scopes**; the app needs delegated permission to read the user's group memberships (`GroupMember.Read.All`) with admin consent |
| `app` (OIDC option, **always** for SAML) | client-credentials token for an app registration, `GET /v1.0/users/{oid}/transitiveMemberOf` | **Application** permission `GroupMember.Read.All` with admin consent. OIDC reuses the provider's client ID/secret and the tenant from the issuer; SAML takes `graph_tenant_id`, `graph_client_id` and the write-only `graph_client_secret` |

Set `oidc.graph_mode: "app"`, or for SAML the `saml.graph_*` fields. Setting
`graph_overage: "off"` ignores the markers. The Graph base/login URLs default to
the public cloud and can be changed for sovereign clouds (https only).

* Only group **object IDs** are used (`$select=id`). Display names are not
  unique in Entra and by default any user may create a group named
  "Paddock Admins", so never map roles on display names for overage users.
* The `endpoint` in `_claim_sources` / the `groups.link` URL is **never
  followed** (it is token data and legacy `graph.windows.net`); Paddock calls the
  configured Graph host only, and refuses a `@odata.nextLink` that leaves it.
* Results are cached per user for `PADDOCK_GRAPH_GROUP_CACHE_SEC` (default 300,
  `0` = off). Failures are never cached and a stale list is never served.
* **Failure mode: deny, never grant.** If Graph cannot be used (no credentials,
  403 consent missing, throttled, timeout, bad payload, internal address) the
  user's groups are *unresolved*: no role mapping is applied (a partial `groups`
  claim next to an overage marker is discarded too). A provider with *Deny
  users with no matching group* refuses the sign-in with `groups_unavailable`;
  otherwise a new user gets the provider's default role and an existing user keeps
  the role they already have (it is neither raised nor reset, and their stored
  groups are not blanked). The audit record carries `groups_unresolved` and the
  `groups_error` code (`graph_forbidden`, `graph_throttled`, `graph_unreachable`,
  `graph_not_configured`, `graph_no_user`, `graph_bad_response`, ...).
* All Graph and token requests use the DNS-pinned transport
  ([outbound safety](INTEGRATIONS.md#outbound-safety)).

## 4. OIDC: Google Workspace

1. Google Cloud console (a project owned by your Workspace org) →
   **APIs & Services → OAuth consent screen** → User type **Internal**.
2. **Credentials → Create credentials → OAuth client ID → Web application**.
   Authorized redirect URI: `https://paddock.example.com/v1/auth/sso/google/callback`.
3. Paddock → **Add provider** → *Google Workspace*:
   * Issuer `https://accounts.google.com` (pre-filled), client ID + secret, slug `google`.
   * **Allowed email domains:** your Workspace domain(s), e.g. `corp.example`.
     Paddock checks both the email domain and Google's `hd` claim, so personal
     Gmail accounts can't sign in.
   * Google ID tokens carry **no group information**: everyone gets the default
     role. Pick a conservative default (`viewer`) and promote people in Paddock,
     or provision roles with SCIM from another IdP.
   * Optional: add `hd=corp.example` to *extra auth params* (via the API) to
     pre-select the domain on Google's account chooser. This is cosmetic;
     enforcement is the allow-list.

## 5. OIDC: Auth0 and Keycloak

* **Auth0:** Applications → *Regular Web Application*; Allowed Callback URL
  as above. Issuer is `https://<tenant>.<region>.auth0.com/` (trailing slash is
  fine). Auth0 does not put roles in ID tokens by default; add a post-login
  Action that sets a namespaced claim, e.g.
  `api.idToken.setCustomClaim("https://paddock/groups", event.authorization.roles)`,
  and set the groups claim to `https://paddock/groups`.
* **Keycloak:** Clients → *Create* (OpenID Connect, Client authentication **on**,
  Standard flow only); Valid redirect URI as above. Issuer is
  `https://<host>/realms/<realm>`. Add a **Group Membership** mapper (*Full group
  path* off, add to ID token) with token claim name `groups`, or map realm roles
  with groups claim `realm_access.roles`. If Keycloak is on your LAN, enable
  **IdP is on a private network** (outbound requests to private addresses are
  otherwise refused; cloud-metadata addresses always are).

---

## 6. SAML 2.0

Paddock is a SAML service provider (SP-initiated, HTTP-Redirect for the
request, HTTP-POST for the response). It requires the **assertion to be
signed** (SHA-256 or better) by the certificate you configure, and checks the
audience, destination/recipient, issuer, validity window and `InResponseTo`.
Assertion IDs are remembered until they expire (replay protection).

1. Pick a slug (e.g. `corp-saml`). The SP values follow from it (table in §0):
   ACS `https://paddock.example.com/v1/auth/sso/corp-saml/acs`, entity ID
   `https://paddock.example.com/v1/auth/sso/corp-saml/metadata`, so you can
   configure the IdP first.
2. Configure the IdP (below) and download its **metadata XML**.
3. Paddock → **Add provider** → **SAML 2.0**, same slug, paste the metadata
   (fills entity ID, SSO URL and signing certificate) or enter them by hand.
   Set the **groups attribute** (and **email attribute** if the NameID isn't
   the email) and your mappings. The SP metadata is then served at
   `/v1/auth/sso/<slug>/metadata` for IdPs that import it.

**Okta (SAML):** Applications → Create App Integration → **SAML 2.0**.
*Single sign-on URL* = ACS URL (check *Use this for Recipient URL and
Destination URL*); *Audience URI* = SP entity ID; *Name ID format*
EmailAddress; *Application username* Email. **Group Attribute Statements:**
name `groups`, filter *Starts with* `paddock-`. Leave *Assertion Signature*
= Signed. Copy the **Metadata URL**'s XML into Paddock.

**Entra ID (SAML):** Enterprise applications → **New application → Create
your own application** (non-gallery) → **Single sign-on → SAML**.
*Basic SAML Configuration:* Identifier = SP entity ID, Reply URL = ACS URL.
*Attributes & Claims:* **Add a group claim** → Security groups (emits object
IDs under `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`) —
set that as the groups attribute; or emit app roles
(`http://schemas.microsoft.com/ws/2008/06/identity/claims/role`). Email is in
`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`; set it as
the email attribute because the default NameID is the UPN.
*SAML Signing Certificate:* signing option **Sign SAML assertion** (default)
→ download **Federation Metadata XML** and paste it into Paddock.

### SP key pair: signed requests and encrypted assertions

Generate a key pair for the provider (Paddock keeps the private key encrypted
with `PADDOCK_SECRET_KEY`, never returns it, and puts the certificate in the SP
metadata and the provider config):

```
POST /v1/auth/sso/admin/providers/{id}/saml-sp-keypair   -> {"sp_x509_cert": "-----BEGIN CERTIFICATE-----..."}
```

or supply your own: `saml.sp_x509_cert` (PEM) plus the write-only
`sp_private_key` (PEM). Paddock checks that they match. Then, per provider:

* `saml.sign_authn_requests: true`: AuthnRequests and LogoutRequests are signed
  (RSA-SHA256, Redirect binding); give the IdP the certificate (it is in the SP
  metadata as `AuthnRequestsSigned="true"`).
* **Encrypted assertions** are decrypted with the same key whenever the IdP
  sends them. `saml.require_encrypted_assertions: true` also refuses plaintext
  assertions. An assertion encrypted for another key, or when no key is
  configured, is rejected (`invalid_assertion`). Rotate by calling the keypair
  endpoint again and uploading the new certificate to the IdP.
* `idp_metadata_url` (instead of pasting XML) makes Paddock download the IdP
  metadata: https only, public addresses only, no redirects, 512 KiB cap,
  through the DNS-pinned transport.

### Single logout

Set the IdP's single-logout URL (`saml.idp_slo_url`, picked up from metadata)
and give the IdP the SP's SLS endpoint, `https://paddock.example.com/v1/auth/sso/<slug>/sls`
(HTTP-Redirect binding; also in the SP metadata).

* **SP-initiated:** the dashboard calls `POST /v1/auth/sso/logout` with the
  user's token. Every Paddock session of that user is revoked at once (JWT
  watermark + pending exchange codes), and the response is
  `{"revoked": true, "idp_logout_url": "<IdP SLO URL with a LogoutRequest>"}`;
  navigate the browser there to end the IdP session too. The IdP's
  LogoutResponse returns to `/sls` with the single-use `RelayState` and must
  answer our request (`InResponseTo`). Without an SLO URL (or for non-SAML
  logins) `idp_logout_url` is `null` (OIDC: the IdP's `end_session_endpoint`
  when it advertises one).
* **IdP-initiated:** a `LogoutRequest` at `/sls` revokes the matching user's
  sessions (matched by NameID, and by SessionIndex when the request names one:
  a different IdP session leaves ours alone) and is answered with a
  LogoutResponse redirect. **Logout messages must be signed by the pinned IdP
  certificate** (otherwise anyone could end any user's session); unsigned or
  wrongly signed ones get `400` and change nothing. An unknown NameID is
  answered like a known one (no user oracle).

Every logout is audited (`action=logout`, `details.initiator` = `user` / `idp`).
`logout` is a reserved provider slug.

Not supported: IdP-initiated *sign-on* (unsolicited responses are refused by
design), POST-binding logout, artifact binding.

The SAML stack is OneLogin's `python3-saml` on `xmlsec`. Their wheels bundle
libxml2, so `xmlsec` and `lxml` are pinned as a pair in
`orchestrator/pyproject.toml`; if SAML ever fails to import, the SAML
endpoints answer **501** and OIDC keeps working.

---

## 7. SCIM 2.0 provisioning

1. Paddock → Settings → Identity → **SCIM provisioning → Create token**. The
   token (`pscim_…`) is shown **once**; Paddock stores only its hash. It works
   only on `/scim/v2` and nowhere else; revoke it from the same table.
2. Under **Group → role mapping**, map SCIM group names (the `displayName` the
   IdP pushes) to roles. Users in no mapped group get the "no match" role. With
   no mappings at all, SCIM never changes anyone's role.

### Okta

1. Open the Paddock app integration (the OIDC or SAML one) → **General → App
   Settings → Edit → Provisioning: SCIM** → Save.
2. **Provisioning → Integration → Edit**:
   * SCIM connector base URL: `https://paddock.example.com/scim/v2`
   * Unique identifier field for users: `userName`
   * Supported provisioning actions: **Push New Users, Push Profile Updates, Push Groups**
   * Authentication Mode: **HTTP Header**, Authorization: `Bearer pscim_…`
   * **Test Connector Configuration**, then Save.
3. **Provisioning → To App → Edit:** enable *Create Users*, *Update User
   Attributes*, *Deactivate Users*.
4. **Push Groups:** push the groups you mapped (e.g. `paddock-admins`).

Okta's SCIM `externalId` is the Okta user ID, which is also the OIDC `sub`,
so SSO sign-ins land on the provisioned account automatically.

### Microsoft Entra ID

1. Enterprise applications → (your Paddock app) → **Provisioning → Get started**
   → Provisioning Mode **Automatic**.
2. **Admin Credentials:** Tenant URL `https://paddock.example.com/scim/v2`,
   Secret Token `pscim_…` → **Test Connection**.
3. **Mappings → Provision Microsoft Entra ID Users:** keep `userName ←
   userPrincipalName`; change `externalId` to **`objectId`** (so OIDC sign-ins
   link by `oid`). Keep **Provision Microsoft Entra ID Groups** enabled.
4. **Settings → Scope:** *Sync only assigned users and groups*; set
   **Provisioning Status: On** and save.

### Behaviour

| IdP action | Paddock effect |
|---|---|
| Create user | Account with no password (SSO only), role from group mappings |
| Update user / `PUT` | Profile fields updated; userName changes are uniqueness-checked |
| `active: false` (Okta deactivate, Entra soft-delete) | Account disabled; **every session token issued so far and every API key of that user is revoked immediately** |
| `active: true` | Account re-enabled; old tokens and API keys stay dead — the user signs in again |
| `DELETE /Users/{id}` | Deactivated as above, unlinked from SSO and hidden from SCIM (404). The row is kept for the audit trail; re-creating the same userName revives it |
| Group membership / rename / delete | Roles of affected members recomputed instantly |

Guard rails: SCIM can only see users it provisioned or that were created by
SSO just-in-time (which it adopts on first write). Local password accounts
and break-glass accounts are invisible to SCIM, so a leaked SCIM token cannot
disable your break-glass admin.

Implemented (RFC 7644): Users and Groups with `GET` (list, one),
`POST`, `PUT`, `PATCH`, `DELETE`, `POST /Users/.search` and `/Groups/.search`,
`ServiceProviderConfig`, `ResourceTypes`, `Schemas`.

* **Filters:** `eq ne co sw ew gt ge lt le pr`, `and` / `or` / `not (…)`,
  parentheses and value paths (`emails[type eq "work" and value sw "a"]`,
  `groups[value eq "<id>"]`, `members[value eq "<id>"]`). Attributes: users
  `userName`, `externalId`, `displayName`, `name.givenName`, `name.familyName`,
  `emails`, `emails.value`, `active`, `id`, `roles.value`, `groups.value`,
  `meta.created`, `meta.lastModified`; groups `displayName`, `externalId`, `id`,
  `members.value`, `meta.*`. Strings compare case-insensitively (not
  `externalId` / `id`); dates take ISO 8601. Values are bound parameters; the
  parser is bounded (1 KiB, depth 8, 20 terms). Anything else is
  `400 invalidFilter`.
* **Paging:** `startIndex` (< 1 → 1) and `count` (negative → 0, capped at 200),
  true `totalResults` past the end. `attributes` / `excludedAttributes`
  project responses (`id` and `schemas` always stay).
* **ETags:** every resource carries `meta.version` and an `ETag` (weak). `GET`
  honours `If-None-Match` (304); `PUT`/`PATCH`/`DELETE` honour `If-Match`
  (`412` when stale; `*` and no header always work, which is what Okta and
  Entra send). Group membership changes bump the version of both the group and
  the affected users.
* **PATCH** accepts Okta (`replace` with a value object and no path, e.g.
  `{"active": false}`; `members[value eq "…"]` removal, with or without a
  trailing `.value`) and Entra (capitalised ops, explicit paths, `"True"` /
  `"False"` strings, `emails[type eq "work"].value`, `Remove` of `name.*`,
  `members` add / replace / remove with a value array or no value, upper-cased
  GUIDs, enterprise-extension attributes, which are accepted and ignored). Unknown
  member ids are ignored; malformed operations are `400` and change nothing.

Not implemented: bulk, sort (`sort.supported=false`), password changes.

---

## 8. Require SSO

Settings → Identity → **Sign-in policy → Require SSO**. Password sign-in is
then refused (HTTP 403, same answer whether or not the account exists) for
everyone except the listed **break-glass accounts**. API keys keep working
(they are separate, admin-issued credentials). Paddock refuses to turn this
on unless at least one provider is enabled and at least one break-glass
account is listed. Keep a break-glass password in your vault and test it.

---

## 9. Troubleshooting

Failed sign-ins land on `/sso/callback?error=<code>`; the full reason is in
the orchestrator log (`sso_login_failed`) and the audit log
(`action=login`, `resource_type=sso`, `details.reason/detail`).

| Code | Usual cause |
|---|---|
| `state_mismatch` | Sign-in took longer than `SSO_STATE_TTL_SEC`, was finished in another browser, or the callback was replayed |
| `invalid_token` | ID token failed validation: wrong client ID (audience), issuer URL not exactly the IdP's, clock skew > `SSO_CLOCK_SKEW_SEC`, unsupported algorithm |
| `invalid_assertion` | SAML: unsigned or wrongly signed assertion (check the certificate), wrong ACS/entity ID in the IdP, expired assertion |
| `replay` | The same ID token nonce / SAML assertion was presented twice |
| `idp_error` | The IdP returned an error (user not assigned to the app, consent denied) or rejected the code exchange (wrong client secret) |
| `provider_unavailable` | Discovery/JWKS unreachable, or the issuer resolves to a private/blocked address (enable *IdP is on a private network* for LAN IdPs) |
| `domain_not_allowed` | Email (or Google `hd`) not in the provider's allowed domains |
| `no_mapping` | *Deny users with no matching group* is on and none matched — check the groups claim name |
| `provisioning_disabled` | JIT is off and no account is linked or provisioned |
| `account_conflict` | An account with that email exists but the IdP didn't assert a verified email, or the account is a break-glass account |
| `user_disabled` | The Paddock account is deactivated (e.g. by SCIM) |
| `groups_unavailable` | Entra group overage and Graph could not be used while *Deny users with no matching group* is on — see *Group overage* (consent, credentials, throttling) |

Use the **Test** button on a provider to check discovery and the JWKS.

---

## 9a. Multi-tenant deployments (hosted / MSP)

Providers, users, login state, SCIM tokens and the sign-in policy
(`identity_settings`, including **Require SSO** and the break-glass list) all
belong to one tenant; every tenant has its own, so tenant B can run SSO exactly
like a single-tenant install. How the unauthenticated flow finds the right
tenant:

* **Provider slugs are globally unique** (they are part of the public
  callback / ACS URL), so the slug identifies the tenant. The flow reads the
  slug's owning tenant in `auth_lookup` mode (schema/038, a narrow SELECT-only
  policy on `identity_providers`, selecting only `tenant_id`), then does
  *everything else* (state / nonce / PKCE, JIT provisioning, role mapping,
  identity links, exchange code, audit entries) inside that tenant under
  normal RLS. A disabled provider, or one of a suspended tenant, is
  "unknown".
* **State is bound to its provider and tenant.** A callback / ACS /
  logout `state` minted for another tenant's provider and presented to your
  slug is refused (`state_mismatch`) and is not consumed.
* **Exchange codes name their tenant** (`<tenant uuid hex>.<random>`), so the
  SPA's `POST /v1/auth/sso/exchange` needs no tenant parameter; the issued JWT
  carries the provider's `tid`.
* **No cross-tenant takeover.** Linking by verified email, SCIM `externalId`
  or existing identity only looks inside the provider's tenant. Usernames stay
  globally unique, so JIT provisioning of a username that exists in another
  tenant is refused with `account_conflict` ("already exists in another
  organization"); nothing is created or linked. Use a different IdP username
  or email for that user.
* **Require SSO is per tenant.** Password sign-in is gated by the policy of
  the tenant the username belongs to (an unknown username gets the default
  tenant's policy). `GET /v1/auth/sso/providers?tenant=<slug|id>` returns that
  tenant's providers and `sso_required` for its sign-in page; an unknown tenant
  gets an empty answer.
* Creating a provider with a slug another tenant already uses returns 409.
* SCIM tokens already resolve their tenant (schema/036); SCIM users, groups
  and role mappings in tenant B use tenant B's `identity_settings`.

---

## 10. API reference

Public (no credentials):

| Method | Path | |
|---|---|---|
| GET | `/v1/auth/sso/providers[?tenant=<slug>]` | Enabled providers for the sign-in page + `sso_required` (of the default tenant, or of `tenant`) |
| GET | `/v1/auth/sso/{slug}/start?spa_challenge=…&return_to=/path` | 302 to the IdP. `spa_challenge` = base64url(SHA-256(verifier)), required |
| GET | `/v1/auth/sso/{slug}/callback` | OIDC redirect URI |
| POST | `/v1/auth/sso/{slug}/acs` | SAML ACS |
| GET | `/v1/auth/sso/{slug}/metadata` | SAML SP metadata |
| GET | `/v1/auth/sso/{slug}/sls` | SAML single logout (signed LogoutRequest / LogoutResponse, Redirect binding) |
| POST | `/v1/auth/sso/exchange` `{code, verifier}` | One-time code → Paddock JWT (`LoginOut` + `username`) |

Signed in (any role): `POST /v1/auth/sso/logout` → `{"revoked": true, "idp_logout_url": …}`.

Admin (capability `admin`):

| Method | Path |
|---|---|
| GET, POST | `/v1/auth/sso/admin/providers` |
| GET, PATCH, DELETE | `/v1/auth/sso/admin/providers/{id}` (secrets `client_secret`, `sp_private_key`, `graph_client_secret`: omit = keep, `""` = clear; `saml` PATCH merges onto the stored config; `idp_metadata_url` fetches IdP metadata) |
| POST | `/v1/auth/sso/admin/providers/{id}/test` |
| POST | `/v1/auth/sso/admin/providers/{id}/saml-sp-keypair` (generate / rotate the SAML SP key pair) |
| GET, PUT | `/v1/auth/sso/admin/settings` |
| GET, POST | `/v1/auth/sso/admin/scim-tokens` |
| DELETE | `/v1/auth/sso/admin/scim-tokens/{id}` |

SCIM (SCIM token only): `/scim/v2/Users`, `/scim/v2/Groups`,
`/scim/v2/ServiceProviderConfig`, `/scim/v2/ResourceTypes`, `/scim/v2/Schemas`.

Schema: `schema/020_identity.sql`, `schema/030_identity_hardening.sql`
(`user_identities.idp_session`, the SAML NameID / SessionIndex used for logout).
Code: `orchestrator/app/identity/` (`graph.py` = Entra overage, `scim_filter.py` =
SCIM filters),
`orchestrator/app/routers/sso.py`, `orchestrator/app/routers/scim.py`.
Tests: `orchestrator/tests/test_identity_{oidc,saml,saml_hardening,scim,scim_rfc,graph,sessions}.py`
(a fake OIDC provider, a self-signed SAML IdP, a fake Microsoft Graph),
`dashboard/tests/identity.test.tsx`.
