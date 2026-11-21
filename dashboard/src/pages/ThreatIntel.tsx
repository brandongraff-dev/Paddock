import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import StatTile from "../components/StatTile";
import SeverityChip from "../components/Severity";
import EmptyState from "../components/EmptyState";
import {
  createTiFeed,
  deleteTiFeed,
  getTiSummary,
  ingestStix,
  listTiFeeds,
  listTiIndicators,
  listTiMatches,
  pollTiFeed,
  type TiFeedKind,
  type TiIndicatorType,
  type TiMatch,
} from "../api/ti";
import { SEV_COLOR } from "../lib/color";
import { useStore } from "../state/store";
import "../styles/threatintel.css";

/* ------------------------------ constants ------------------------------ */

const IOC_TYPES: TiIndicatorType[] = [
  "ipv4",
  "ipv6",
  "cidr",
  "domain",
  "url",
  "file_sha256",
  "file_md5",
  "email",
];

const TYPE_COLOR: Record<string, string> = {
  ipv4: "#4ea3ff",
  ipv6: "#4ea3ff",
  cidr: "#7aa2ff",
  domain: "#58d68d",
  url: "#f0b429",
  file_sha256: "#c678dd",
  file_md5: "#c678dd",
  email: "#e06c75",
};

const PAGE = 100;

/* ------------------------------- helpers ------------------------------- */

function relTime(iso: string | null): string {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 60) return `${Math.max(s, 0)}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

function typeChip(t: string) {
  const c = TYPE_COLOR[t] ?? "var(--text-2)";
  return (
    <span className="ti-type-chip mono" style={{ color: c, borderColor: c }}>
      {t}
    </span>
  );
}

/* ------------------------------- matches ------------------------------- */

function MatchRow({ m }: { m: TiMatch }) {
  const openDrawer = useStore((s) => s.openDrawer);
  const label =
    m.indicator.malware[0] ??
    m.indicator.labels[0] ??
    m.indicator.threat_actor ??
    "malicious indicator";
  const assetId = m.subject.asset_id;
  return (
    <div className="ti-match-row">
      <SeverityChip severity={m.severity} compact />
      <div className="ti-match-body">
        <div className="ti-match-headline">
          {assetId ? (
            <button
              type="button"
              className="ti-asset mono"
              title={m.subject.asset_value ?? ""}
              onClick={() => openDrawer({ kind: "asset", id: assetId })}
            >
              {m.subject.asset_value ?? m.matched_value}
            </button>
          ) : (
            <span className="ti-asset mono static">{m.matched_value}</span>
          )}
          <span className="ti-match-arrow">matches</span>
          {typeChip(m.indicator.type)}
          <span className="ti-ind-value mono" title={m.indicator.value}>
            {m.indicator.value}
          </span>
        </div>
        <div className="ti-match-meta">
          <span className="ti-label">{label}</span>
          {m.indicator.malware.length > 0 && (
            <span className="ti-tag malware">{m.indicator.malware.join(", ")}</span>
          )}
          {m.indicator.threat_actor && (
            <span className="ti-tag actor">{m.indicator.threat_actor}</span>
          )}
          {m.indicator.labels.map((l) => (
            <span key={l} className="ti-tag">
              {l}
            </span>
          ))}
          <span className="ti-subject-kind">
            {m.subject_type === "finding" ? "via finding evidence" : "surface asset"}
          </span>
        </div>
        {m.subject.finding_title && (
          <div className="ti-match-finding">
            finding:{" "}
            {m.finding_id ? (
              <button
                type="button"
                className="ti-flink mono"
                onClick={() => openDrawer({ kind: "finding", id: m.finding_id! })}
              >
                {m.subject.finding_title}
              </button>
            ) : (
              <span className="mono">{m.subject.finding_title}</span>
            )}
          </div>
        )}
      </div>
      <span className="ti-match-time mono" title={m.matched_at}>
        {relTime(m.matched_at)}
      </span>
    </div>
  );
}

function MatchesPanel() {
  const q = useQuery({
    queryKey: ["ti-matches"],
    queryFn: () => listTiMatches({ limit: PAGE }),
    staleTime: 10_000,
  });
  const items = q.data?.items ?? [];
  return (
    <div className="panel ti-matches">
      <div className="panel-h">
        <h2>Matches</h2>
        <span className="panel-sub">
          {q.data?.total ?? 0} · your surface on a threat feed · worst first
        </span>
      </div>
      <div className="ti-match-list">
        {q.isLoading && <div className="ti-loading">Loading matches…</div>}
        {q.isError && <div className="ti-error">Failed to load matches.</div>}
        {!q.isLoading && items.length === 0 && (
          <EmptyState
            title="No threat-intel matches."
            hint="None of your assets or findings touch a known-bad indicator yet. Register a feed and poll it."
          />
        )}
        {items.map((m) => (
          <MatchRow key={m.id} m={m} />
        ))}
      </div>
    </div>
  );
}

/* ----------------------------- indicators ------------------------------ */

function IndicatorsPanel() {
  const [type, setType] = useState<TiIndicatorType | "">("");
  const [q, setQ] = useState("");
  const [label, setLabel] = useState("");

  const filter = useMemo(
    () => ({
      type: type || undefined,
      q: q.trim() || undefined,
      label: label.trim() || undefined,
      limit: PAGE,
    }),
    [type, q, label],
  );

  const query = useQuery({
    queryKey: ["ti-indicators", filter],
    queryFn: () => listTiIndicators(filter),
    staleTime: 10_000,
  });
  const items = query.data?.items ?? [];

  return (
    <div className="panel ti-indicators">
      <div className="panel-h">
        <h2>Indicators</h2>
        <span className="panel-sub">{query.data?.total ?? 0} IOCs ingested</span>
      </div>

      <div className="ti-filterbar">
        <select value={type} onChange={(e) => setType(e.target.value as TiIndicatorType | "")}>
          <option value="">all types</option>
          {IOC_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <input
          placeholder="label (c2, phishing…)"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
        <input placeholder="value contains…" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>

      <div className="ti-table-wrap">
        {query.isLoading && <div className="ti-loading">Loading indicators…</div>}
        {!query.isLoading && items.length === 0 && (
          <EmptyState title="No indicators match." />
        )}
        {items.length > 0 && (
          <table className="ti-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Labels</th>
                <th>Conf</th>
                <th>Feed</th>
              </tr>
            </thead>
            <tbody>
              {items.map((i) => (
                <tr key={i.id}>
                  <td>{typeChip(i.type)}</td>
                  <td className="ti-ind-value mono" title={i.pattern ?? i.value}>
                    {i.value}
                  </td>
                  <td>
                    <div className="ti-labels">
                      {i.malware.map((mw) => (
                        <span key={mw} className="ti-tag malware">
                          {mw}
                        </span>
                      ))}
                      {i.threat_actor && <span className="ti-tag actor">{i.threat_actor}</span>}
                      {i.labels.map((l) => (
                        <span key={l} className="ti-tag">
                          {l}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="mono">{i.confidence}</td>
                  <td className="ti-feed-name">{i.feed_name ?? i.source ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

/* -------------------------------- feeds -------------------------------- */

function FeedsPanel() {
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);
  const feeds = useQuery({ queryKey: ["ti-feeds"], queryFn: listTiFeeds, staleTime: 15_000 });

  const [name, setName] = useState("");
  const [kind, setKind] = useState<TiFeedKind>("taxii");
  const [url, setUrl] = useState("");
  const [collection, setCollection] = useState("");
  const [bundle, setBundle] = useState("");

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["ti-feeds"] });
    qc.invalidateQueries({ queryKey: ["ti-summary"] });
  };

  const create = useMutation({
    mutationFn: () =>
      createTiFeed({
        name: name.trim(),
        kind,
        url: kind === "manual" ? null : url.trim() || null,
        collection: kind === "taxii" ? collection.trim() || null : null,
        enabled: true,
      }),
    onSuccess: () => {
      pushToast({ text: "Feed registered." });
      setName("");
      setUrl("");
      setCollection("");
      invalidate();
    },
    onError: () => pushToast({ text: "Could not register feed.", severity: "high" }),
  });

  const remove = useMutation({
    mutationFn: (id: string) => deleteTiFeed(id),
    onSuccess: invalidate,
  });

  const poll = useMutation({
    mutationFn: (id: string) => pollTiFeed(id),
    onSuccess: (res) => {
      if (res.ok === false) {
        pushToast({ text: res.note ?? "Service unreachable.", severity: "high" });
      } else {
        pushToast({ text: "Poll triggered." });
      }
      invalidate();
      qc.invalidateQueries({ queryKey: ["ti-indicators"] });
      qc.invalidateQueries({ queryKey: ["ti-matches"] });
    },
    onError: () => pushToast({ text: "Poll failed.", severity: "high" }),
  });

  const ingest = useMutation({
    mutationFn: () => {
      const trimmed = bundle.trim();
      // Allow pasting either a STIX bundle JSON, or a bare feed URL.
      if (/^https?:\/\//i.test(trimmed)) return ingestStix({ url: trimmed });
      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        return Promise.reject(new Error("invalid JSON"));
      }
      return ingestStix(parsed);
    },
    onSuccess: (res) => {
      if (res.ok === false) {
        pushToast({ text: res.note ?? "Service unreachable.", severity: "high" });
      } else {
        const n = (res.inserted as number) ?? (res.parsed as number) ?? 0;
        pushToast({ text: `Ingested (${n} new).` });
        setBundle("");
      }
      qc.invalidateQueries({ queryKey: ["ti-indicators"] });
      qc.invalidateQueries({ queryKey: ["ti-matches"] });
      qc.invalidateQueries({ queryKey: ["ti-summary"] });
    },
    onError: () => pushToast({ text: "Ingest failed — check the JSON.", severity: "high" }),
  });

  const canCreate = name.trim().length > 0 && (kind === "manual" || url.trim().length > 0);

  return (
    <div className="panel ti-feeds">
      <div className="panel-h">
        <h2>Feeds</h2>
        <span className="panel-sub">{feeds.data?.length ?? 0} configured</span>
      </div>

      <div className="ti-feed-list">
        {(feeds.data ?? []).length === 0 && !feeds.isLoading && (
          <div className="ti-muted">No feeds yet. Register a TAXII server or STIX URL below.</div>
        )}
        {(feeds.data ?? []).map((f) => (
          <div key={f.id} className={`ti-feed-row${f.enabled ? "" : " disabled"}`}>
            <div className="ti-feed-main">
              <div className="ti-feed-name-line">
                <span className="ti-feed-name">{f.name}</span>
                <span className="ti-feed-kind mono">{f.kind}</span>
                <span className="ti-feed-count mono">{f.indicator_count} IOCs</span>
              </div>
              {f.url && (
                <div className="ti-feed-url mono" title={f.url}>
                  {f.url}
                  {f.collection ? ` · ${f.collection}` : ""}
                </div>
              )}
              <div className="ti-feed-status">
                <span
                  className={`ti-status-dot ${
                    f.last_status?.startsWith("ok") ? "ok" : f.last_status ? "err" : ""
                  }`}
                />
                <span className="mono">{f.last_status ?? "not polled"}</span>
                <span className="ti-muted">· {relTime(f.last_poll)}</span>
              </div>
            </div>
            <div className="ti-feed-actions">
              <button
                className="ghost"
                disabled={poll.isPending || f.kind === "manual"}
                onClick={() => poll.mutate(f.id)}
                title={f.kind === "manual" ? "manual feeds are not polled" : "poll now"}
              >
                poll now
              </button>
              <button
                className="ghost danger"
                onClick={() => remove.mutate(f.id)}
                title="remove feed"
              >
                ✕
              </button>
            </div>
          </div>
        ))}
      </div>

      <form
        className="ti-feed-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (canCreate) create.mutate();
        }}
      >
        <div className="ti-form-head">Register feed</div>
        <div className="field">
          <label>Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. AlienVault OTX" />
        </div>
        <div className="ti-form-grid">
          <div className="field">
            <label>Kind</label>
            <select value={kind} onChange={(e) => setKind(e.target.value as TiFeedKind)}>
              <option value="taxii">taxii</option>
              <option value="stix_url">stix_url</option>
              <option value="manual">manual</option>
            </select>
          </div>
          {kind === "taxii" && (
            <div className="field">
              <label>Collection</label>
              <input value={collection} onChange={(e) => setCollection(e.target.value)} placeholder="collection id" />
            </div>
          )}
        </div>
        {kind !== "manual" && (
          <div className="field">
            <label>{kind === "taxii" ? "TAXII server / API root URL" : "STIX bundle URL"}</label>
            <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://…" />
            <span className="field-note">user-configured · stored server-side</span>
          </div>
        )}
        <div className="ti-form-foot">
          <button type="submit" className="primary" disabled={!canCreate || create.isPending}>
            {create.isPending ? "Registering…" : "Register feed"}
          </button>
        </div>
      </form>

      <div className="ti-ingest">
        <div className="ti-form-head">Paste a STIX bundle to ingest</div>
        <textarea
          value={bundle}
          onChange={(e) => setBundle(e.target.value)}
          placeholder='{"type":"bundle","objects":[…]}  — or a https:// bundle URL'
          spellCheck={false}
        />
        <div className="ti-form-foot">
          <button
            className="primary"
            disabled={bundle.trim().length === 0 || ingest.isPending}
            onClick={() => ingest.mutate()}
          >
            {ingest.isPending ? "Ingesting…" : "Ingest bundle"}
          </button>
        </div>
      </div>
    </div>
  );
}

/* -------------------------------- page --------------------------------- */

export default function ThreatIntelPage() {
  const summary = useQuery({
    queryKey: ["ti-summary"],
    queryFn: getTiSummary,
    staleTime: 30_000,
  });
  const s = summary.data;

  return (
    <div className="page ti-page">
      <div className="page-header">
        <div>
          <h1>Threat Intel</h1>
          <div className="subtitle">
            STIX / TAXII IOC fusion — defensive: is any of your surface a known-bad indicator, or
            does it touch known threat infrastructure?
          </div>
        </div>
      </div>

      <div className="stat-row">
        <StatTile label="Indicators" value={s?.indicators ?? 0} accent="#4ea3ff" />
        <StatTile label="Matches" value={s?.matches ?? 0} accent={SEV_COLOR.critical} />
        <StatTile label="Feeds" value={s?.feeds ?? 0} accent="#58d68d" />
      </div>

      <MatchesPanel />

      <div className="ti-grid">
        <IndicatorsPanel />
        <FeedsPanel />
      </div>
    </div>
  );
}
