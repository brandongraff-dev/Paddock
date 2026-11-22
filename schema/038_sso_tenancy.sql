-- 038: SSO browser login for non-default tenants.
--
-- The unauthenticated SSO flow (/v1/auth/sso/{slug}/start|callback|acs|sls)
-- only knows a provider SLUG. Providers are tenant rows under RLS, so a
-- provider owned by any tenant other than the default one was invisible and
-- the flow failed closed. Like api_keys / sensors / scim_tokens (034, 036) the
-- tenant is not known until the credential row is read, so identity_providers
-- gets ONE narrow SELECT-only policy that is open inside
-- `tenancy.auth_lookup()` and nowhere else. The code selects only
-- (id, tenant_id, kind) in that mode, then re-reads the full row (config,
-- encrypted secrets) and runs EVERYTHING else -- login state, JIT
-- provisioning, exchange codes, audit -- inside the provider's tenant.
--
-- slug stays globally unique (it is part of the public ACS / callback URL).
-- sso_login_states / sso_exchange_codes need no lookup policy: the state is
-- consumed under the provider's tenant and filtered by provider_id, and the
-- exchange code carries its tenant id as a prefix.
--
-- Idempotent.

ALTER TABLE identity_providers ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS identity_provider_auth_lookup ON identity_providers;
CREATE POLICY identity_provider_auth_lookup ON identity_providers FOR SELECT
  USING (current_setting('app.auth_lookup', true) = 'on');
