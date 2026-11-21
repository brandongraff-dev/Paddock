/**
 * CommandPalette — Palantir-style cmd-K / ctrl-K launcher.
 *
 * Mounted once, globally, from Shell. Opens on cmd/ctrl-K or the top-bar
 * affordance; closes on Esc or backdrop click. A single input drives four
 * sections: Navigate (static, the 7 pages), Assets / Findings / Scans (live,
 * debounced ~150ms). Up/Down move, Enter activates, hover selects. Selecting an
 * asset / finding / scan navigates to its page and opens the DetailDrawer via
 * the shared store. It's a tool, not a toy: one fast fade/scale, no chrome.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useStore } from "../state/store";
import { listAssets } from "../api/assets";
import { listFindings } from "../api/findings";
import { listScans } from "../api/scans";
import { kindColor, severityColor } from "../lib/color";

const DEBOUNCE_MS = 150;

const NAV: { to: string; label: string }[] = [
  { to: "/", label: "Overview" },
  { to: "/graph", label: "Graph" },
  { to: "/findings", label: "Findings" },
  { to: "/chains", label: "Chains" },
  { to: "/timeline", label: "Timeline" },
  { to: "/scope", label: "Scope" },
  { to: "/scans", label: "Scans" },
];

interface CmdItem {
  key: string;
  label: string;
  kind?: string;
  meta?: string;
  dot?: string;
  mono?: boolean;
  run: () => void;
}
interface CmdGroup {
  label: string;
  loading?: boolean;
  items: CmdItem[];
}

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export default function CommandPalette() {
  const open = useStore((s) => s.cmdkOpen);
  const closeCmdk = useStore((s) => s.closeCmdk);
  const toggleCmdk = useStore((s) => s.toggleCmdk);
  const openDrawer = useStore((s) => s.openDrawer);
  const navigate = useNavigate();

  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const dq = useDebounced(q.trim(), DEBOUNCE_MS);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const resultsRef = useRef<HTMLDivElement | null>(null);

  // Global shortcut — cmd/ctrl-K toggles from anywhere, including inputs.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        toggleCmdk();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggleCmdk]);

  // Reset query + focus when opening.
  useEffect(() => {
    if (open) {
      setQ("");
      setActive(0);
      // focus after paint so the autofocus actually lands
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const hasQuery = dq.length >= 1;

  const assets = useQuery({
    queryKey: ["cmdk-assets", dq],
    queryFn: () => listAssets({ value: dq, limit: 8 }),
    enabled: open && hasQuery,
    retry: false,
    staleTime: 10_000,
  });
  const findings = useQuery({
    queryKey: ["cmdk-findings", dq],
    queryFn: () => listFindings({ q: dq, limit: 8 }),
    enabled: open && hasQuery,
    retry: false,
    staleTime: 10_000,
  });
  const scans = useQuery({
    queryKey: ["cmdk-scans", dq],
    queryFn: () => listScans({ limit: 50 }),
    enabled: open && hasQuery,
    retry: false,
    staleTime: 10_000,
  });

  const go = (fn: () => void) => () => {
    fn();
    closeCmdk();
  };

  const groups = useMemo<CmdGroup[]>(() => {
    const needle = dq.toLowerCase();
    // Navigate filters on the raw (un-debounced) input — it's local and cheap;
    // only the live API sections wait for the debounced value.
    const typed = q.trim().toLowerCase();

    const navItems: CmdItem[] = NAV.filter(
      (n) => !typed || n.label.toLowerCase().includes(typed),
    ).map((n) => ({
      key: `nav:${n.to}`,
      label: n.label,
      kind: "page",
      run: go(() => navigate(n.to)),
    }));

    const assetItems: CmdItem[] = hasQuery
      ? (assets.data ?? []).map((a) => ({
          key: `asset:${a.id}`,
          label: a.value,
          kind: a.kind,
          dot: kindColor(a.kind),
          mono: true,
          meta: a.blast_score != null ? `blast ${Math.round(a.blast_score)}` : undefined,
          run: go(() => {
            navigate("/graph");
            openDrawer({ kind: "asset", id: a.id });
          }),
        }))
      : [];

    const findingItems: CmdItem[] = hasQuery
      ? (findings.data ?? []).map((f) => ({
          key: `finding:${f.id}`,
          label: f.title,
          kind: f.severity,
          dot: severityColor(f.severity),
          meta: f.asset_value ?? undefined,
          run: go(() => {
            navigate("/findings");
            openDrawer({ kind: "finding", id: f.id });
          }),
        }))
      : [];

    const scanItems: CmdItem[] = hasQuery
      ? (scans.data ?? [])
          .filter((s) =>
            [s.target, s.kind, s.status, s.id].some((v) =>
              String(v ?? "").toLowerCase().includes(needle),
            ),
          )
          .slice(0, 8)
          .map((s) => ({
            key: `scan:${s.id}`,
            label: s.target,
            kind: s.kind,
            mono: true,
            meta: s.status,
            run: go(() => {
              navigate("/scans");
              openDrawer({ kind: "scan", id: s.id });
            }),
          }))
      : [];

    const out: CmdGroup[] = [];
    if (navItems.length) out.push({ label: "Navigate", items: navItems });
    out.push({ label: "Assets", loading: hasQuery && assets.isFetching, items: assetItems });
    out.push({ label: "Findings", loading: hasQuery && findings.isFetching, items: findingItems });
    out.push({ label: "Scans", loading: hasQuery && scans.isFetching, items: scanItems });
    return out.filter((g) => g.items.length > 0 || g.loading);
  }, [q, dq, hasQuery, assets.data, assets.isFetching, findings.data, findings.isFetching, scans.data, scans.isFetching, navigate, openDrawer]);

  const flat = useMemo(() => groups.flatMap((g) => g.items), [groups]);

  // Keep the active index in range whenever results change.
  useEffect(() => {
    setActive((a) => (flat.length === 0 ? 0 : Math.min(a, flat.length - 1)));
  }, [flat.length]);

  // Scroll the active option into view.
  useEffect(() => {
    if (!open) return;
    const el = resultsRef.current?.querySelector(`#cmdk-opt-${active}`);
    if (el && typeof el.scrollIntoView === "function") el.scrollIntoView({ block: "nearest" });
  }, [active, open]);

  if (!open) return null;

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      closeCmdk();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => (flat.length === 0 ? 0 : (a + 1) % flat.length));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => (flat.length === 0 ? 0 : (a - 1 + flat.length) % flat.length));
    } else if (e.key === "Enter") {
      e.preventDefault();
      flat[active]?.run();
    } else if (e.key === "Tab") {
      // Focus trap: the input is the only tab stop.
      e.preventDefault();
    }
  };

  let idx = -1; // running global index across groups for keyboard mapping

  return (
    <div
      className="cmdk-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) closeCmdk();
      }}
    >
      <div
        className="cmdk"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onKeyDown={onKeyDown}
      >
        <div className="cmdk-input-wrap">
          <span className="glyph mono" aria-hidden>
            {">"}
          </span>
          <input
            ref={inputRef}
            className="cmdk-input"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setActive(0);
            }}
            placeholder="Search assets, findings, scans — or jump to a page…"
            role="combobox"
            aria-expanded
            aria-controls="cmdk-listbox"
            aria-activedescendant={flat.length ? `cmdk-opt-${active}` : undefined}
            autoComplete="off"
            autoCorrect="off"
            spellCheck={false}
          />
          <button className="cmdk-trigger" onClick={closeCmdk} aria-label="close">
            esc
          </button>
        </div>

        <div className="cmdk-results" id="cmdk-listbox" role="listbox" ref={resultsRef}>
          {flat.length === 0 && !groups.some((g) => g.loading) && (
            <div className="cmdk-empty">No matches for “{dq}”.</div>
          )}
          {groups.map((g) => (
            <div key={g.label} role="group" aria-label={g.label}>
              <div className="cmdk-group-label">
                {g.label}
                {g.loading && <span style={{ marginLeft: 8, opacity: 0.7 }}>searching…</span>}
              </div>
              {g.items.map((it) => {
                idx += 1;
                const i = idx;
                return (
                  <div
                    key={it.key}
                    id={`cmdk-opt-${i}`}
                    role="option"
                    aria-selected={i === active}
                    className={`cmdk-item${it.mono ? " mono" : ""}${i === active ? " active" : ""}`}
                    onMouseMove={() => setActive(i)}
                    onClick={it.run}
                  >
                    {it.dot && <span className="dot" style={{ background: it.dot }} />}
                    <span className="ci-label">{it.label}</span>
                    {it.meta && <span className="ci-meta">{it.meta}</span>}
                    {it.kind && <span className="ci-kind">{it.kind}</span>}
                  </div>
                );
              })}
            </div>
          ))}
        </div>

        <div className="cmdk-foot">
          <span><span className="kbd">↑</span> <span className="kbd">↓</span> move</span>
          <span><span className="kbd">↵</span> open</span>
          <span><span className="kbd">esc</span> close</span>
          <span className="sp" />
          <span className="mono">palantir-asm</span>
        </div>
      </div>
    </div>
  );
}
