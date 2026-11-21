/**
 * Settings → Identity (admin). Three sections:
 *   1. Policy — require SSO for everyone except named break-glass accounts.
 *   2. Identity providers — OIDC (Okta, Entra ID, Google, Auth0, Keycloak)
 *      and SAML 2.0, with group → role/clearance mappings (first match wins).
 *   3. SCIM provisioning — bearer tokens (shown exactly once) and the SCIM
 *      group → role mapping.
 * Every change here is written to the audit log server-side.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import {
  createProvider,
  createScimToken,
  deleteProvider,
  getIdentitySettings,
  listProviders,
  listScimTokens,
  putIdentitySettings,
  revokeScimToken,
  testProvider,
  updateProvider,
  type Preset,
  type Provider,
  type ProviderInput,
  type ProviderKind,
  type ProviderTestResult,
  type RoleMapping,
  type ScimTokenCreated,
} from "../api/sso";
import { ApiError } from "../api/client";
import type { Classification, Role } from "../api/types";
import EmptyState from "../components/EmptyState";
import Gate from "../components/Gate";
import "../styles/identity.css";

const ROLES: Role[] = ["viewer", "analyst", "auditor", "admin"];
const CLEARANCES: Classification[] = ["public", "internal", "confidential", "restricted"];

interface PresetInfo {
  label: string;
  kind: ProviderKind;
  issuer: string;
  issuerHint: string;
  groupsClaim: string;
  note: string;
}

const PRESETS: Record<Preset, PresetInfo> = {
  okta: {
    label: "Okta", kind: "oidc", issuer: "", issuerHint: "https://your-org.okta.com/oauth2/default",
    groupsClaim: "groups", note: "Add a “groups” claim to the authorization server (filter: Matches regex .*).",
  },
  entra: {
    label: "Microsoft Entra ID", kind: "oidc", issuer: "",
    issuerHint: "https://login.microsoftonline.com/<tenant-id>/v2.0",
    groupsClaim: "roles", note: "Use App roles (the “roles” claim) or emit group object IDs in “groups”.",
  },
  google: {
    label: "Google Workspace", kind: "oidc", issuer: "https://accounts.google.com",
    issuerHint: "https://accounts.google.com", groupsClaim: "groups",
    note: "Google ID tokens carry no groups — restrict with allowed domains (checked against “hd”).",
  },
  auth0: {
    label: "Auth0", kind: "oidc", issuer: "", issuerHint: "https://your-tenant.us.auth0.com/",
    groupsClaim: "https://paddock/groups", note: "Add groups via an Action as a namespaced claim.",
  },
  keycloak: {
    label: "Keycloak", kind: "oidc", issuer: "", issuerHint: "https://sso.example.com/realms/corp",
    groupsClaim: "groups", note: "Add a Group Membership mapper (full path off), or use realm_access.roles.",
  },
  generic: {
    label: "Generic", kind: "oidc", issuer: "", issuerHint: "https://idp.example.com",
    groupsClaim: "groups", note: "Any OpenID Connect provider with discovery.",
  },
};

function errText(e: unknown): string {
  if (e instanceof ApiError) {
    const b = e.body as { detail?: unknown } | undefined;
    if (b && typeof b.detail === "string") return b.detail;
    if (b && Array.isArray(b.detail)) return "Some fields are invalid.";
    return e.message;
  }
  return e instanceof Error ? e.message : "Request failed.";
}

function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="idp-copy">
      <span className="idp-copy-label">{label}</span>
      <code className="mono">{value}</code>
      <button
        type="button"
        className="ghost"
        onClick={() => {
          navigator.clipboard?.writeText(value).then(() => setCopied(true), () => undefined);
          setTimeout(() => setCopied(false), 1500);
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

function Toggle({
  id, checked, onChange, label, hint,
}: { id: string; checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string }) {
  return (
    <label className="idp-toggle" htmlFor={id}>
      <input id={id} type="checkbox" role="switch" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span className="idp-switch" aria-hidden="true" />
      <span className="idp-toggle-text">
        <span>{label}</span>
        {hint && <span className="idp-hint">{hint}</span>}
      </span>
    </label>
  );
}

/* ------------------------------ mappings ------------------------------- */

export function MappingEditor({
  value, onChange, groupLabel = "IdP group / claim value",
}: { value: RoleMapping[]; onChange: (v: RoleMapping[]) => void; groupLabel?: string }) {
  const set = (i: number, patch: Partial<RoleMapping>) =>
    onChange(value.map((m, j) => (j === i ? { ...m, ...patch } : m)));
  return (
    <div className="idp-mappings">
      {value.length > 0 && (
        <div className="idp-mappings-head">
          <span>{groupLabel}</span><span>Role</span><span>Clearance</span><span />
        </div>
      )}
      {value.length === 0 && <div className="idp-hint idp-mappings-empty">No mappings — everyone gets the default role.</div>}
      {value.map((m, i) => (
        <div className="idp-mapping-row" key={i}>
          <input
            aria-label={`Mapping ${i + 1} group`}
            value={m.group}
            placeholder="paddock-admins"
            onChange={(e) => set(i, { group: e.target.value })}
          />
          <select aria-label={`Mapping ${i + 1} role`} value={m.role} onChange={(e) => set(i, { role: e.target.value as Role })}>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <select
            aria-label={`Mapping ${i + 1} clearance`}
            value={m.clearance ?? ""}
            onChange={(e) => set(i, { clearance: (e.target.value || null) as Classification | null })}
          >
            <option value="">default</option>
            {CLEARANCES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <button type="button" className="ghost" aria-label={`Remove mapping ${i + 1}`}
            onClick={() => onChange(value.filter((_, j) => j !== i))}>✕</button>
        </div>
      ))}
      <div className="idp-mappings-foot">
        <button type="button" onClick={() => onChange([...value, { group: "", role: "viewer", clearance: null }])}>
          Add mapping
        </button>
        <span className="idp-hint">Evaluated top to bottom — the first matching group wins.</span>
      </div>
    </div>
  );
}

/* ------------------------------- policy -------------------------------- */

function PolicyPanel() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["identity-settings"], queryFn: getIdentitySettings });
  const [required, setRequired] = useState(false);
  const [breakGlass, setBreakGlass] = useState("");
  useEffect(() => {
    if (q.data) {
      setRequired(q.data.sso_required);
      setBreakGlass(q.data.break_glass_users.join(", "));
    }
  }, [q.data]);
  const save = useMutation({
    mutationFn: () => putIdentitySettings({
      sso_required: required,
      break_glass_users: breakGlass.split(",").map((s) => s.trim()).filter(Boolean),
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["identity-settings"] }),
  });
  return (
    <section className="panel idp-section">
      <div className="idp-section-intro">
        <h2>Sign-in policy</h2>
        <p>Require single sign-on for everyone. Break-glass accounts keep password access for when the IdP is down.</p>
      </div>
      <form className="idp-section-body" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        <Gate need="admin">
          <Toggle id="sso-required" checked={required} onChange={setRequired}
            label="Require SSO" hint="Disables password sign-in for all non-break-glass users." />
          <div className="field">
            <label htmlFor="break-glass">Break-glass accounts</label>
            <input id="break-glass" className="mono" value={breakGlass} onChange={(e) => setBreakGlass(e.target.value)}
              placeholder="admin" />
          </div>
          {save.isError && <div className="login-error" role="alert">{errText(save.error)}</div>}
          <div className="idp-actions">
            <button type="submit" className="primary" disabled={save.isPending}>Save policy</button>
            {save.isSuccess && <span className="idp-saved">Saved</span>}
          </div>
        </Gate>
      </form>
    </section>
  );
}

/* --------------------------- provider editor --------------------------- */

interface Draft {
  kind: ProviderKind;
  preset: Preset;
  display_name: string;
  slug: string;
  enabled: boolean;
  issuer: string;
  client_id: string;
  client_secret: string;
  scopes: string;
  token_auth_method: "client_secret_basic" | "client_secret_post" | "none";
  allow_private: boolean;
  use_userinfo: boolean;
  metadata_xml: string;
  idp_entity_id: string;
  idp_sso_url: string;
  idp_x509_cert: string;
  email_attribute: string;
  groups_attribute: string;
  allowed_domains: string;
  jit_provisioning: boolean;
  sync_roles: boolean;
  require_mapping: boolean;
  default_role: Role;
  default_clearance: Classification;
  groups_claim: string;
  role_mappings: RoleMapping[];
}

function draftFrom(p?: Provider): Draft {
  const c = (p?.config ?? {}) as Record<string, any>;
  return {
    kind: p?.kind ?? "oidc",
    preset: p?.preset ?? "okta",
    display_name: p?.display_name ?? "",
    slug: p?.slug ?? "",
    enabled: p?.enabled ?? true,
    issuer: c.issuer ?? "",
    client_id: c.client_id ?? "",
    client_secret: "",
    scopes: (c.scopes ?? ["openid", "email", "profile"]).join(" "),
    token_auth_method: c.token_auth_method ?? "client_secret_basic",
    allow_private: !!c.allow_private,
    use_userinfo: !!c.use_userinfo,
    metadata_xml: "",
    idp_entity_id: c.idp_entity_id ?? "",
    idp_sso_url: c.idp_sso_url ?? "",
    idp_x509_cert: c.idp_x509_cert ?? "",
    email_attribute: c.email_attribute ?? "",
    groups_attribute: c.groups_attribute ?? "",
    allowed_domains: (p?.allowed_domains ?? []).join(", "),
    jit_provisioning: p?.jit_provisioning ?? true,
    sync_roles: p?.sync_roles ?? true,
    require_mapping: p?.require_mapping ?? false,
    default_role: p?.default_role ?? "viewer",
    default_clearance: p?.default_clearance ?? "internal",
    groups_claim: p?.groups_claim ?? "groups",
    role_mappings: p?.role_mappings ?? [],
  };
}

function toInput(d: Draft, isNew: boolean): ProviderInput {
  const body: ProviderInput = {
    display_name: d.display_name.trim(),
    preset: d.preset,
    enabled: d.enabled,
    allowed_domains: d.allowed_domains.split(/[\s,]+/).filter(Boolean),
    jit_provisioning: d.jit_provisioning,
    sync_roles: d.sync_roles,
    require_mapping: d.require_mapping,
    default_role: d.default_role,
    default_clearance: d.default_clearance,
    groups_claim: d.groups_claim.trim() || "groups",
    role_mappings: d.role_mappings.filter((m) => m.group.trim()).map((m) => ({ ...m, group: m.group.trim() })),
  };
  if (isNew) {
    body.slug = d.slug.trim();
    body.kind = d.kind;
  }
  if (d.kind === "oidc") {
    body.oidc = {
      issuer: d.issuer.trim(),
      client_id: d.client_id.trim(),
      scopes: d.scopes.split(/\s+/).filter(Boolean),
      token_auth_method: d.token_auth_method,
      allow_private: d.allow_private,
      use_userinfo: d.use_userinfo,
    };
    if (d.client_secret) body.client_secret = d.client_secret;
  } else {
    if (d.metadata_xml.trim()) body.saml_metadata_xml = d.metadata_xml.trim();
    if (d.idp_entity_id && d.idp_sso_url && d.idp_x509_cert) {
      body.saml = {
        idp_entity_id: d.idp_entity_id.trim(),
        idp_sso_url: d.idp_sso_url.trim(),
        idp_x509_cert: d.idp_x509_cert.trim(),
        email_attribute: d.email_attribute.trim() || null,
        groups_attribute: d.groups_attribute.trim() || null,
      };
    }
  }
  return body;
}

function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
}

function ProviderEditor({ provider, onClose }: { provider?: Provider; onClose: () => void }) {
  const qc = useQueryClient();
  const isNew = !provider;
  const [d, setD] = useState<Draft>(() => draftFrom(provider));
  const set = (patch: Partial<Draft>) => setD((cur) => ({ ...cur, ...patch }));
  const preset = PRESETS[d.preset];

  const save = useMutation({
    mutationFn: () => (isNew ? createProvider(toInput(d, true)) : updateProvider(provider!.id, toInput(d, false))),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["identity-providers"] });
      onClose();
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate();
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <form className="modal idp-modal" onClick={(e) => e.stopPropagation()} onSubmit={submit} aria-label="Identity provider">
        <header>{isNew ? "Add identity provider" : `Edit ${provider!.display_name}`}</header>
        <div className="body">
          {isNew && (
            <div className="idp-seg" role="radiogroup" aria-label="Protocol">
              {(["oidc", "saml"] as ProviderKind[]).map((k) => (
                <button key={k} type="button" role="radio" aria-checked={d.kind === k}
                  className={`login-tab ${d.kind === k ? "on" : ""}`}
                  onClick={() => set({ kind: k, preset: k === "saml" ? "generic" : d.preset })}>
                  {k === "oidc" ? "OpenID Connect" : "SAML 2.0"}
                </button>
              ))}
            </div>
          )}

          <div className="idp-grid">
            {d.kind === "oidc" && (
              <div className="field">
                <label htmlFor="idp-preset">Provider</label>
                <select id="idp-preset" value={d.preset} onChange={(e) => {
                  const p = e.target.value as Preset;
                  set({
                    preset: p,
                    issuer: PRESETS[p].issuer || d.issuer,
                    groups_claim: PRESETS[p].groupsClaim,
                    display_name: d.display_name || PRESETS[p].label,
                    slug: isNew && !d.slug ? p : d.slug,
                  });
                }}>
                  {(Object.keys(PRESETS) as Preset[]).map((p) => <option key={p} value={p}>{PRESETS[p].label}</option>)}
                </select>
              </div>
            )}
            <div className="field">
              <label htmlFor="idp-name">Button label</label>
              <input id="idp-name" required value={d.display_name} placeholder={preset.label}
                onChange={(e) => set({ display_name: e.target.value, slug: isNew && !d.slug ? slugify(e.target.value) : d.slug })} />
            </div>
            <div className="field">
              <label htmlFor="idp-slug">Slug</label>
              <input id="idp-slug" className="mono" required disabled={!isNew} value={d.slug}
                pattern="[a-z0-9][a-z0-9\-]{0,62}" onChange={(e) => set({ slug: e.target.value })} />
            </div>
          </div>

          {d.kind === "oidc" ? (
            <>
              <div className="idp-hint idp-note">{preset.note}</div>
              <div className="field">
                <label htmlFor="idp-issuer">Issuer URL</label>
                <input id="idp-issuer" className="mono" required value={d.issuer} placeholder={preset.issuerHint}
                  onChange={(e) => set({ issuer: e.target.value })} />
              </div>
              <div className="idp-grid">
                <div className="field">
                  <label htmlFor="idp-client-id">Client ID</label>
                  <input id="idp-client-id" className="mono" required value={d.client_id}
                    onChange={(e) => set({ client_id: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor="idp-client-secret">Client secret</label>
                  <input id="idp-client-secret" type="password" autoComplete="new-password" className="mono"
                    value={d.client_secret}
                    placeholder={provider?.has_client_secret ? "•••••••• (stored — leave blank to keep)" : ""}
                    onChange={(e) => set({ client_secret: e.target.value })} />
                </div>
              </div>
              <div className="idp-grid">
                <div className="field">
                  <label htmlFor="idp-scopes">Scopes</label>
                  <input id="idp-scopes" className="mono" value={d.scopes} onChange={(e) => set({ scopes: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor="idp-auth-method">Token auth</label>
                  <select id="idp-auth-method" value={d.token_auth_method}
                    onChange={(e) => set({ token_auth_method: e.target.value as Draft["token_auth_method"] })}>
                    <option value="client_secret_basic">client_secret_basic</option>
                    <option value="client_secret_post">client_secret_post</option>
                    <option value="none">none (public client + PKCE)</option>
                  </select>
                </div>
              </div>
              <div className="idp-toggles">
                <Toggle id="idp-userinfo" checked={d.use_userinfo} onChange={(v) => set({ use_userinfo: v })}
                  label="Merge userinfo claims" hint="For IdPs that only send groups from /userinfo." />
                <Toggle id="idp-private" checked={d.allow_private} onChange={(v) => set({ allow_private: v })}
                  label="IdP is on a private network" hint="e.g. self-hosted Keycloak on the LAN." />
              </div>
            </>
          ) : (
            <>
              <div className="field">
                <label htmlFor="idp-metadata">IdP metadata XML</label>
                <textarea id="idp-metadata" className="mono" rows={5} value={d.metadata_xml}
                  placeholder="Paste the IdP's metadata to fill entity ID, SSO URL and signing certificate"
                  onChange={(e) => set({ metadata_xml: e.target.value })} />
              </div>
              <details className="idp-details" open={!isNew}>
                <summary>…or enter the IdP settings manually</summary>
                <div className="field">
                  <label htmlFor="idp-entity">IdP entity ID</label>
                  <input id="idp-entity" className="mono" value={d.idp_entity_id} onChange={(e) => set({ idp_entity_id: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor="idp-sso-url">IdP SSO URL (HTTP-Redirect)</label>
                  <input id="idp-sso-url" className="mono" value={d.idp_sso_url} onChange={(e) => set({ idp_sso_url: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor="idp-cert">IdP signing certificate (PEM)</label>
                  <textarea id="idp-cert" className="mono" rows={3} value={d.idp_x509_cert} onChange={(e) => set({ idp_x509_cert: e.target.value })} />
                </div>
              </details>
              <div className="idp-grid">
                <div className="field">
                  <label htmlFor="idp-email-attr">Email attribute</label>
                  <input id="idp-email-attr" className="mono" value={d.email_attribute} placeholder="(NameID)"
                    onChange={(e) => set({ email_attribute: e.target.value })} />
                </div>
                <div className="field">
                  <label htmlFor="idp-groups-attr">Groups attribute</label>
                  <input id="idp-groups-attr" className="mono" value={d.groups_attribute} placeholder="groups"
                    onChange={(e) => set({ groups_attribute: e.target.value })} />
                </div>
              </div>
            </>
          )}

          <h3 className="idp-sub">Access</h3>
          <div className="idp-grid">
            <div className="field">
              <label htmlFor="idp-domains">Allowed email domains</label>
              <input id="idp-domains" className="mono" value={d.allowed_domains} placeholder="corp.example (empty = any)"
                onChange={(e) => set({ allowed_domains: e.target.value })} />
            </div>
            {d.kind === "oidc" && (
              <div className="field">
                <label htmlFor="idp-groups-claim">Groups claim</label>
                <input id="idp-groups-claim" className="mono" value={d.groups_claim}
                  onChange={(e) => set({ groups_claim: e.target.value })} />
              </div>
            )}
          </div>
          <div className="idp-grid">
            <div className="field">
              <label htmlFor="idp-default-role">Default role</label>
              <select id="idp-default-role" value={d.default_role} onChange={(e) => set({ default_role: e.target.value as Role })}>
                {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
            </div>
            <div className="field">
              <label htmlFor="idp-default-clearance">Default clearance</label>
              <select id="idp-default-clearance" value={d.default_clearance}
                onChange={(e) => set({ default_clearance: e.target.value as Classification })}>
                {CLEARANCES.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
          </div>
          <MappingEditor value={d.role_mappings} onChange={(v) => set({ role_mappings: v })} />
          <div className="idp-toggles">
            <Toggle id="idp-jit" checked={d.jit_provisioning} onChange={(v) => set({ jit_provisioning: v })}
              label="Just-in-time provisioning" hint="Create a Paddock account on first sign-in." />
            <Toggle id="idp-sync" checked={d.sync_roles} onChange={(v) => set({ sync_roles: v })}
              label="Sync role on every sign-in" hint="The IdP stays the source of truth." />
            <Toggle id="idp-require-mapping" checked={d.require_mapping} onChange={(v) => set({ require_mapping: v })}
              label="Deny users with no matching group" />
            <Toggle id="idp-enabled" checked={d.enabled} onChange={(v) => set({ enabled: v })} label="Enabled" />
          </div>

          {provider && (
            <div className="idp-copies">
              <h3 className="idp-sub">Values for your IdP</h3>
              {provider.redirect_uri && <CopyField label="Redirect URI" value={provider.redirect_uri} />}
              {provider.saml_acs_url && <CopyField label="ACS URL" value={provider.saml_acs_url} />}
              {provider.saml_entity_id && <CopyField label="SP entity ID" value={provider.saml_entity_id} />}
              {provider.saml_metadata_url && <CopyField label="SP metadata" value={provider.saml_metadata_url} />}
            </div>
          )}
          {save.isError && <div className="login-error" role="alert">{errText(save.error)}</div>}
        </div>
        <div className="foot">
          <button type="button" onClick={onClose}>Cancel</button>
          <button type="submit" className="primary" disabled={save.isPending}>
            {isNew ? "Add provider" : "Save changes"}
          </button>
        </div>
      </form>
    </div>
  );
}

/* ------------------------------ providers ------------------------------ */

function ProvidersPanel() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["identity-providers"], queryFn: listProviders });
  const [editing, setEditing] = useState<Provider | "new" | null>(null);
  const [tests, setTests] = useState<Record<string, ProviderTestResult>>({});
  const del = useMutation({
    mutationFn: (id: string) => deleteProvider(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["identity-providers"] }),
  });
  const runTest = useMutation({
    mutationFn: (id: string) => testProvider(id),
    onSuccess: (res, id) => setTests((t) => ({ ...t, [id]: res })),
    onError: (e, id) => setTests((t) => ({ ...t, [id]: { ok: false, detail: errText(e) } })),
  });
  const providers = Array.isArray(q.data) ? q.data : [];

  return (
    <section className="panel idp-section">
      <div className="idp-section-intro">
        <h2>Identity providers</h2>
        <p>OpenID Connect and SAML 2.0. Users appear on the sign-in page as “Continue with …”.</p>
        <Gate need="admin">
          <button type="button" className="primary" onClick={() => setEditing("new")}>Add provider</button>
        </Gate>
      </div>
      <div className="idp-section-body">
        {providers.length === 0 ? (
          <EmptyState title="No identity providers yet." hint="Add Okta, Entra ID, Google Workspace, Auth0, Keycloak or any SAML IdP." />
        ) : (
          <ul className="idp-list">
            {providers.map((p) => {
              const t = tests[p.id];
              return (
                <li key={p.id} className="idp-row">
                  <div className="idp-row-main">
                    <span className="idp-row-name">{p.display_name}</span>
                    <span className="idp-row-meta mono">
                      {p.slug} · {p.kind.toUpperCase()} · {p.role_mappings.length} mapping{p.role_mappings.length === 1 ? "" : "s"}
                      {p.allowed_domains.length > 0 && ` · ${p.allowed_domains.join(", ")}`}
                    </span>
                    {t && (
                      <span className={`idp-test ${t.ok ? "ok" : "bad"}`}>
                        {t.ok ? "Connection OK" : `Failed: ${t.detail ?? t.error ?? "error"}`}
                      </span>
                    )}
                  </div>
                  <span className={`chip ${p.enabled ? "idp-on" : "idp-off"}`}>{p.enabled ? "enabled" : "disabled"}</span>
                  <Gate need="admin">
                    <div className="idp-row-actions">
                      <button type="button" className="ghost" onClick={() => runTest.mutate(p.id)}>Test</button>
                      <button type="button" onClick={() => setEditing(p)}>Edit</button>
                      <button type="button" className="danger" onClick={() => {
                        if (confirm(`Delete ${p.display_name}? Users linked to it can no longer sign in with it.`)) del.mutate(p.id);
                      }}>Delete</button>
                    </div>
                  </Gate>
                </li>
              );
            })}
          </ul>
        )}
      </div>
      {editing && <ProviderEditor provider={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />}
    </section>
  );
}

/* -------------------------------- SCIM --------------------------------- */

function ScimPanel() {
  const qc = useQueryClient();
  const settings = useQuery({ queryKey: ["identity-settings"], queryFn: getIdentitySettings });
  const tokens = useQuery({ queryKey: ["scim-tokens"], queryFn: listScimTokens });
  const [name, setName] = useState("");
  const [fresh, setFresh] = useState<ScimTokenCreated | null>(null);
  const [mappings, setMappings] = useState<RoleMapping[]>([]);
  const [defRole, setDefRole] = useState<Role>("viewer");
  const [defClr, setDefClr] = useState<Classification>("internal");
  useEffect(() => {
    if (settings.data) {
      setMappings(settings.data.scim_role_mappings ?? []);
      setDefRole(settings.data.scim_default_role);
      setDefClr(settings.data.scim_default_clearance);
    }
  }, [settings.data]);

  const create = useMutation({
    mutationFn: () => createScimToken(name.trim()),
    onSuccess: (t) => {
      setFresh(t);
      setName("");
      qc.invalidateQueries({ queryKey: ["scim-tokens"] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => revokeScimToken(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scim-tokens"] }),
  });
  const saveMap = useMutation({
    mutationFn: () => putIdentitySettings({
      scim_role_mappings: mappings.filter((m) => m.group.trim()),
      scim_default_role: defRole,
      scim_default_clearance: defClr,
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["identity-settings"] }),
  });
  const list = useMemo(() => (Array.isArray(tokens.data) ? tokens.data : []), [tokens.data]);

  return (
    <section className="panel idp-section">
      <div className="idp-section-intro">
        <h2>SCIM provisioning</h2>
        <p>Let Okta or Entra ID create, update and deactivate Paddock users. Deactivation ends sessions and revokes API keys immediately.</p>
      </div>
      <div className="idp-section-body">
        {settings.data && <CopyField label="SCIM base URL" value={settings.data.scim_base_url} />}
        <Gate need="admin">
          <form className="idp-inline" onSubmit={(e) => { e.preventDefault(); if (name.trim()) create.mutate(); }}>
            <div className="field" style={{ flex: 1 }}>
              <label htmlFor="scim-token-name">New token name</label>
              <input id="scim-token-name" value={name} placeholder="okta-provisioning" onChange={(e) => setName(e.target.value)} />
            </div>
            <button type="submit" className="primary" disabled={!name.trim() || create.isPending}>Create token</button>
          </form>
        </Gate>
        {create.isError && <div className="login-error" role="alert">{errText(create.error)}</div>}
        {fresh && (
          <div className="idp-secret" role="status">
            <div className="idp-secret-head">
              <strong>Copy this token now.</strong> It won't be shown again — Paddock only keeps a hash.
              <button type="button" className="ghost" onClick={() => setFresh(null)} aria-label="Dismiss token">✕</button>
            </div>
            <CopyField label={fresh.name} value={fresh.token} />
          </div>
        )}
        {list.length > 0 && (
          <table className="table idp-table">
            <thead><tr><th>name</th><th>prefix</th><th>created</th><th>last used</th><th>status</th><th /></tr></thead>
            <tbody>
              {list.map((t) => (
                <tr key={t.id} style={{ cursor: "default" }}>
                  <td>{t.name}</td>
                  <td className="mono">pscim_{t.prefix}…</td>
                  <td className="mono">{t.created_at.slice(0, 16).replace("T", " ")}</td>
                  <td className="mono">{t.last_used ? t.last_used.slice(0, 16).replace("T", " ") : "never"}</td>
                  <td><span className={`chip ${t.revoked ? "idp-off" : "idp-on"}`}>{t.revoked ? "revoked" : "active"}</span></td>
                  <td style={{ textAlign: "right" }}>
                    <Gate need="admin">
                      <button type="button" className="danger" disabled={t.revoked}
                        onClick={() => { if (confirm(`Revoke SCIM token ${t.name}?`)) revoke.mutate(t.id); }}>
                        Revoke
                      </button>
                    </Gate>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        <h3 className="idp-sub">Group → role mapping</h3>
        <form className="idp-stack" onSubmit={(e) => { e.preventDefault(); saveMap.mutate(); }}>
          <Gate need="admin">
            <MappingEditor value={mappings} onChange={setMappings} groupLabel="SCIM group (displayName)" />
            <div className="idp-grid">
              <div className="field">
                <label htmlFor="scim-default-role">Role when no group matches</label>
                <select id="scim-default-role" value={defRole} onChange={(e) => setDefRole(e.target.value as Role)}>
                  {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
              <div className="field">
                <label htmlFor="scim-default-clearance">Clearance when no group matches</label>
                <select id="scim-default-clearance" value={defClr} onChange={(e) => setDefClr(e.target.value as Classification)}>
                  {CLEARANCES.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
            </div>
            {saveMap.isError && <div className="login-error" role="alert">{errText(saveMap.error)}</div>}
            <div className="idp-actions">
              <button type="submit" className="primary" disabled={saveMap.isPending}>Save mapping</button>
              {saveMap.isSuccess && <span className="idp-saved">Saved · roles recomputed</span>}
            </div>
          </Gate>
        </form>
      </div>
    </section>
  );
}

export default function IdentitySettingsPage() {
  return (
    <div className="page identity-page">
      <div className="page-header">
        <div>
          <h1>Identity</h1>
          <div className="subtitle">
            Single sign-on, role mapping and user provisioning. Every change is recorded in the audit log.
          </div>
        </div>
      </div>
      <PolicyPanel />
      <ProvidersPanel />
      <ScimPanel />
    </div>
  );
}
