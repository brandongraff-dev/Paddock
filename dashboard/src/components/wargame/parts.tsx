/**
 * Wargame building blocks: an accessible tooltip, evidence and verdict chips,
 * and the entry → … → crown-jewel route strip.
 *
 * The route strip is plain HTML (not react-flow like AttackPathStrip) so it
 * wraps on narrow screens, reads as an ordered list to a screen reader, and
 * can draw weak evidence as a dashed / dotted line: a conditional or inferred
 * hop must never look like proof.
 */

import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import type { WargameHop, WargameRoute } from "../../api/types";
import {
  MAX_STRENGTH,
  evidenceMeta,
  hopLabels,
  hopWeakest,
  verdictMeta,
  type EvidenceMeta,
  type VerdictTone,
} from "../../lib/wargame";

/* ------------------------------------------------------------------ */
/* Tip: hover / focus tooltip, rendered in a portal so glass panels    */
/* (overflow: clip, backdrop-filter) can't crop it.                    */
/* ------------------------------------------------------------------ */

export function Tip({
  tip,
  children,
  className = "",
  as = "span",
}: {
  tip: ReactNode;
  children: ReactNode;
  className?: string;
  as?: "span" | "div";
}) {
  const id = useId();
  const ref = useRef<HTMLElement | null>(null);
  const bubble = useRef<HTMLDivElement | null>(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ left: number; top: number; above: boolean } | null>(null);

  const place = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const bw = bubble.current?.offsetWidth ?? 260;
    const bh = bubble.current?.offsetHeight ?? 60;
    const vw = window.innerWidth;
    const left = Math.max(8, Math.min(vw - bw - 8, r.left + r.width / 2 - bw / 2));
    const above = r.bottom + bh + 10 > window.innerHeight && r.top - bh - 10 > 0;
    setPos({ left, top: above ? r.top - bh - 8 : r.bottom + 8, above });
  }, []);

  useLayoutEffect(() => {
    if (open) place();
  }, [open, place]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    const onMove = () => place();
    window.addEventListener("keydown", onKey);
    window.addEventListener("scroll", onMove, true);
    window.addEventListener("resize", onMove);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", onMove, true);
      window.removeEventListener("resize", onMove);
    };
  }, [open, place]);

  const Tag = as;
  return (
    <Tag
      ref={ref as never}
      className={`wg-tip ${className}`}
      tabIndex={0}
      aria-describedby={id}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      {children}
      {/* Always in the DOM (hidden) so aria-describedby resolves for screen readers. */}
      {typeof document !== "undefined" ? (
        createPortal(
          <div
            ref={bubble}
            id={id}
            role="tooltip"
            className={`wg-tip-bubble ${open && pos ? "is-open" : ""}`}
            style={pos ? { left: pos.left, top: pos.top } : undefined}
          >
            {tip}
          </div>,
          document.body,
        )
      ) : (
        <span id={id} hidden>
          {tip}
        </span>
      )}
    </Tag>
  );
}

/* ------------------------------------------------------------------ */
/* Evidence                                                            */
/* ------------------------------------------------------------------ */

/** 8 pixel pips, filled to the label's strength. Decorative. */
export function StrengthPips({ strength }: { strength: number }) {
  return (
    <span className="wg-pips" aria-hidden="true">
      {Array.from({ length: MAX_STRENGTH }, (_, i) => (
        <i key={i} className={i < strength ? "on" : ""} />
      ))}
    </span>
  );
}

function evidenceTipBody(m: EvidenceMeta) {
  return (
    <>
      <b>{m.label}</b>
      <span className="wg-tip-meta">
        evidence strength {m.strength} of {MAX_STRENGTH}
        {m.tier === "weak" ? " · not proof" : ""}
      </span>
      <span>{m.tip}</span>
    </>
  );
}

export function EvidenceChip({
  label,
  meta,
  prefix,
  quiet = false,
}: {
  label?: string;
  meta?: EvidenceMeta;
  prefix?: string;
  quiet?: boolean;
}) {
  const m = meta ?? evidenceMeta(label);
  return (
    <Tip tip={evidenceTipBody(m)} className={`wg-ev wg-ev-${m.tier} wg-ev-${m.key} ${quiet ? "is-quiet" : ""}`}>
      {prefix && <span className="wg-ev-prefix">{prefix}</span>}
      {!quiet && <StrengthPips strength={m.strength} />}
      <span className="wg-ev-text">{m.label}</span>
    </Tip>
  );
}

/* ------------------------------------------------------------------ */
/* Verdicts                                                            */
/* ------------------------------------------------------------------ */

export function VerdictChip({ verdict }: { verdict: string }) {
  const m = verdictMeta(verdict);
  return (
    <Tip tip={<><b>{m.label}</b><span>{m.tip}</span></>} className={`wg-verdict tone-${m.tone}`}>
      <span className="wg-verdict-glyph" aria-hidden="true">{m.glyph}</span>
      {m.label}
    </Tip>
  );
}

export function ToneChip({ tone, children, tip }: { tone: VerdictTone; children: ReactNode; tip?: ReactNode }) {
  if (!tip) return <span className={`wg-verdict tone-${tone}`}>{children}</span>;
  return (
    <Tip tip={tip} className={`wg-verdict tone-${tone}`}>
      {children}
    </Tip>
  );
}

/* ------------------------------------------------------------------ */
/* Route strip                                                         */
/* ------------------------------------------------------------------ */

function hopAria(hop: WargameHop, i: number): string {
  const labels = hopLabels(hop).map((m) => m.label.toLowerCase());
  const port = hop.port ? ` on ${hop.port}` : "";
  return `Hop ${i + 1}: ${hop.src} to ${hop.dst}${port}. Evidence: ${labels.join(", ")}.`;
}

function Hop({ hop, i }: { hop: WargameHop; i: number }) {
  const weakest = hopWeakest(hop);
  const others = hopLabels(hop).filter((m) => m.key !== weakest.key);
  return (
    <li className={`wg-hop wg-tier-${weakest.tier} wg-hop-${weakest.key}`} aria-label={hopAria(hop, i)}>
      <span className="wg-hop-line" aria-hidden="true" />
      <span className="wg-hop-body">
        <span className="wg-hop-top">
          <span className="wg-hop-n">hop {i + 1}</span>
          {hop.port && <span className="wg-hop-port mono">{hop.port}</span>}
        </span>
        <EvidenceChip meta={weakest} />
        {others.length > 0 && (
          <span className="wg-hop-also">
            also{" "}
            {others.map((m, k) => (
              <span key={m.key}>
                {k > 0 && ", "}
                <EvidenceChip meta={m} quiet />
              </span>
            ))}
          </span>
        )}
      </span>
    </li>
  );
}

function RouteNode({ id, role }: { id: string; role?: "entry" | "jewel" }) {
  return (
    <li className={`wg-node ${role ? `wg-node-${role}` : ""}`}>
      {role && <span className="wg-node-role">{role === "entry" ? "Entry" : "Crown jewel"}</span>}
      <span className="wg-node-name mono" title={id}>
        {id}
      </span>
    </li>
  );
}

export function RouteStrip({ route }: { route: WargameRoute }) {
  const hops = route.hops ?? [];
  if (!hops.length) {
    return (
      <ol className="wg-route" aria-label={`Route from ${route.entry} to ${route.jewel}`}>
        <RouteNode id={route.entry} role="entry" />
        <li className="wg-hop wg-tier-weak" aria-label="Hops not recorded">
          <span className="wg-hop-line" aria-hidden="true" />
          <span className="wg-hop-body">
            <span className="wg-hop-n">hops not recorded</span>
          </span>
        </li>
        <RouteNode id={route.jewel} role="jewel" />
      </ol>
    );
  }
  return (
    <ol className="wg-route" aria-label={`Route from ${route.entry} to ${route.jewel}, ${hops.length} hops`}>
      <RouteNode id={hops[0].src} role={hops[0].src === route.entry ? "entry" : undefined} />
      {hops.map((h, i) => {
        const last = i === hops.length - 1;
        return [
          <Hop key={`h${i}`} hop={h} i={i} />,
          <RouteNode key={`n${i}`} id={h.dst} role={last && h.dst === route.jewel ? "jewel" : undefined} />,
        ];
      })}
    </ol>
  );
}

/** The evidence ladder as a compact legend (strongest first). */
export function EvidenceLegend({ metas }: { metas: readonly EvidenceMeta[] }) {
  return (
    <ul className="wg-legend" aria-label="Evidence ladder, strongest first">
      {metas.map((m) => (
        <li key={m.key} className={`wg-legend-item wg-tier-${m.tier} wg-hop-${m.key}`}>
          <span className="wg-legend-line" aria-hidden="true" />
          <EvidenceChip meta={m} quiet />
        </li>
      ))}
    </ul>
  );
}
