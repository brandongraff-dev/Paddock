-- 030: identity hardening (SAML single logout).
--
-- The IdP session a user logged in with, so SP-initiated logout can send a
-- LogoutRequest with the right NameID / SessionIndex, and an IdP-initiated
-- LogoutRequest can be matched to a user. Overwritten on every SAML login.
-- (The SP private key and the Entra Graph secret live in identity_providers.secrets,
-- encrypted with the existing secrets module; nothing else is needed for them.)
ALTER TABLE user_identities ADD COLUMN IF NOT EXISTS idp_session JSONB;
COMMENT ON COLUMN user_identities.idp_session IS
  'SAML: {name_id, format, nq, spnq, session_index} of the last login; NULL for OIDC';
