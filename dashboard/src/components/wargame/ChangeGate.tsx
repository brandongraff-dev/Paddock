/**
 * ChangeGate: "what would this change open or break, before it ships?"
 *
 * Paste or upload a `terraform show -json` plan (and optionally an observed
 * flow log), POST /v1/wargame/change-impact, and read the verdict big and
 * plain. Advisory only: nothing is applied anywhere.
 *
 * In sample mode the gate answers only for the bundled sample plans, so a
 * real plan pasted into the sample never gets an invented answer.
 */

import { useId, useRef, useState, type ChangeEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { ApiError } from "../../api/client";
import { checkWargameChangeImpact } from "../../api/wargame";
import type { WargameChangeImpact, WargameFlow, WargamePair } from "../../api/types";
import { FLOW_FORMATS, impactHeadline } from "../../lib/wargame";
import { SAMPLE_PLANS, sampleImpactFor } from "../../lib/wargameSample";

function errorText(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 404) return "The change gate isn't enabled on this server yet. Ask your admin to update Paddock.";
    if (e.status === 0) return "Couldn't reach the Paddock API. Check your connection and try again.";
    const body = e.body as { detail?: unknown } | undefined;
    const d = body && typeof body === "object" ? body.detail : undefined;
    if (typeof d === "string") return d;
    if (Array.isArray(d) && d.length) {
      return d
        .map((x) => (x && typeof x === "object" && "msg" in x ? String((x as { msg: unknown }).msg) : String(x)))
        .join("; ");
    }
    return `The server couldn't check this change (${e.status}).`;
  }
  return e instanceof Error ? e.message : String(e);
}

function PairList({ pairs, empty }: { pairs: WargamePair[]; empty: string }) {
  if (!pairs.length) return <p className="wg-muted">{empty}</p>;
  return (
    <ul className="wg-pairs">
      {pairs.map((p, i) => (
        <li key={`${p.entry}>${p.jewel}:${i}`} className="mono">
          {p.entry} <span aria-hidden="true">→</span>
          <span className="wg-sr-only"> to </span> {p.jewel}
        </li>
      ))}
    </ul>
  );
}

function FlowTable({ flows, caption }: { flows: WargameFlow[]; caption: string }) {
  return (
    <div className="wg-table-wrap">
      <table className="table wg-flow-table">
        <caption className="wg-sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">From</th>
            <th scope="col">To</th>
            <th scope="col">Port</th>
          </tr>
        </thead>
        <tbody>
          {flows.map((f, i) => (
            <tr key={i}>
              <td className="mono">{f.src_ip}</td>
              <td className="mono">{f.dst_ip}</td>
              <td className="mono">
                {String(f.proto || "").toLowerCase()}/{String(f.dst_port)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ImpactResult({ result, sample, flowsGiven }: { result: WargameChangeImpact; sample: boolean; flowsGiven: boolean }) {
  const h = impactHeadline(result);
  const denied = result.newly_denied_flows ?? [];
  const allowed = result.newly_allowed_flows ?? [];
  const opened = result.routes_opened ?? [];
  const closed = result.routes_closed ?? [];
  const warnings = [...(result.warnings ?? [])];
  if (!flowsGiven && !warnings.some((w) => /flow/i.test(w))) {
    warnings.push("No flow log was supplied, so live flows this change would break were not checked.");
  }
  return (
    <div className={`wg-impact tone-${h.tone}`}>
      <div className="wg-impact-head">
        <span className="wg-impact-glyph" aria-hidden="true">
          {h.tone === "safe" ? "✓" : h.tone === "unknown" ? "?" : "!"}
        </span>
        <div>
          {sample && <span className="wg-sample-tag">Sample result</span>}
          <p className="wg-impact-headline">{h.headline}</p>
          {h.sub && <p className="wg-impact-sub">{h.sub}</p>}
        </div>
      </div>
      {result.change_title && <p className="wg-impact-title mono">{result.change_title}</p>}
      {result.summary && <p className="wg-impact-summary">{result.summary}</p>}
      {(!!result.affected_boundaries?.length || (flowsGiven && result.flows_parsed != null)) && (
        <dl className="wg-facts wg-impact-facts">
          {!!result.affected_boundaries?.length && (
            <div>
              <dt>Boundaries it touches</dt>
              <dd className="mono">{result.affected_boundaries.join(", ")}</dd>
            </div>
          )}
          {flowsGiven && result.flows_parsed != null && (
            <div>
              <dt>Flows checked</dt>
              <dd>
                {result.flows_parsed} read
                {result.flows_skipped ? `, ${result.flows_skipped} skipped (unreadable rows)` : ""}
              </dd>
            </div>
          )}
        </dl>
      )}
      {warnings.length > 0 && (
        <ul className="wg-warnings" aria-label="Warnings">
          {warnings.map((w, i) => (
            <li key={i}>{w}</li>
          ))}
        </ul>
      )}
      <div className="wg-impact-grid">
        <section aria-labelledby="wg-ro">
          <h4 id="wg-ro">Routes opened to a crown jewel ({opened.length})</h4>
          <PairList pairs={opened} empty="None." />
        </section>
        <section aria-labelledby="wg-rc">
          <h4 id="wg-rc">Routes closed ({closed.length})</h4>
          <PairList pairs={closed} empty="None." />
        </section>
        <section aria-labelledby="wg-fd">
          <h4 id="wg-fd">Live flows it would block ({denied.length})</h4>
          {denied.length ? <FlowTable flows={denied} caption="Flows the change would block" /> : <p className="wg-muted">{flowsGiven ? "None of the flows supplied." : "Not checked."}</p>}
        </section>
        <section aria-labelledby="wg-fa">
          <h4 id="wg-fa">Flows it would newly allow ({allowed.length})</h4>
          {allowed.length ? <FlowTable flows={allowed} caption="Flows the change would newly allow" /> : <p className="wg-muted">{flowsGiven ? "None of the flows supplied." : "Not checked."}</p>}
        </section>
      </div>
    </div>
  );
}

async function readFile(e: ChangeEvent<HTMLInputElement>): Promise<string | null> {
  const f = e.target.files?.[0];
  e.target.value = "";
  if (!f) return null;
  return f.text();
}

export default function ChangeGate({ sample }: { sample: boolean }) {
  const ids = { plan: useId(), flows: useId(), fmt: useId(), err: useId() };
  const [plan, setPlan] = useState("");
  const [flows, setFlows] = useState("");
  const [fmt, setFmt] = useState("auto");
  const [localError, setLocalError] = useState<string | null>(null);
  const [sampleResult, setSampleResult] = useState<WargameChangeImpact | null>(null);
  const [flowsOpen, setFlowsOpen] = useState(false);
  const planFile = useRef<HTMLInputElement>(null);
  const flowFile = useRef<HTMLInputElement>(null);
  const flowsAtSubmit = useRef(false);

  const check = useMutation({ mutationFn: checkWargameChangeImpact });

  const submit = () => {
    setLocalError(null);
    setSampleResult(null);
    check.reset();
    const text = plan.trim();
    if (!text) {
      setLocalError("Paste or upload a plan first.");
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      setLocalError("That isn't valid JSON. Export the plan with: terraform show -json plan.out > plan.json");
      return;
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      setLocalError("Expected the JSON object that `terraform show -json` prints.");
      return;
    }
    flowsAtSubmit.current = flows.trim().length > 0;
    if (sample) {
      const r = sampleImpactFor(text);
      if (!r) {
        setLocalError("Sample mode only checks the sample plans. Leave sample mode to check a real plan against your network.");
        return;
      }
      setSampleResult(r);
      return;
    }
    check.mutate({
      plan: parsed,
      ...(flowsAtSubmit.current ? { flows: flows, ...(fmt ? { flows_format: fmt } : {}) } : {}),
    });
  };

  const result = sample ? sampleResult : check.data ?? null;
  const error = localError ?? (check.isError ? errorText(check.error) : null);

  return (
    <div className="wg-gate">
      <p className="wg-lede">
        Before a firewall or Terraform change ships, see whether it opens a route to a crown jewel or breaks traffic
        you rely on. Nothing is applied; Paddock reads the plan and answers.
      </p>

      {sample && (
        <div className="wg-gate-samples" role="group" aria-label="Sample plans">
          <span className="wg-muted">Try a sample plan:</span>
          {SAMPLE_PLANS.map((p) => (
            <button
              key={p.id}
              type="button"
              onClick={() => {
                setPlan(p.plan);
                setFlows(p.flows);
                setFlowsOpen(!!p.flows);
                setLocalError(null);
                setSampleResult(null);
              }}
            >
              {p.title}
            </button>
          ))}
        </div>
      )}

      <div className="wg-field">
        <div className="wg-field-h">
          <label htmlFor={ids.plan}>Terraform plan (JSON)</label>
          <button type="button" className="ghost" onClick={() => planFile.current?.click()}>
            Upload plan.json
          </button>
          <input
            ref={planFile}
            type="file"
            accept=".json,application/json"
            className="wg-sr-only"
            tabIndex={-1}
            aria-hidden="true"
            onChange={async (e) => {
              const t = await readFile(e);
              if (t != null) setPlan(t);
            }}
          />
        </div>
        <textarea
          id={ids.plan}
          className="mono wg-textarea"
          rows={7}
          spellCheck={false}
          placeholder={'terraform plan -out plan.out\nterraform show -json plan.out > plan.json\n\nThen paste plan.json here, or upload it.'}
          value={plan}
          onChange={(e) => setPlan(e.target.value)}
          aria-describedby={error ? ids.err : undefined}
          aria-invalid={!!localError}
        />
      </div>

      <details className="wg-flows" open={flowsOpen} onToggle={(e) => setFlowsOpen((e.target as HTMLDetailsElement).open)}>
        <summary>Add observed flows (optional), to see which live traffic the change would break</summary>
        <div className="wg-field">
          <div className="wg-field-h">
            <label htmlFor={ids.flows}>Flow log</label>
            <label htmlFor={ids.fmt} className="wg-sr-only">
              Flow log format
            </label>
            <select id={ids.fmt} value={fmt} onChange={(e) => setFmt(e.target.value)}>
              {FLOW_FORMATS.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>
            <button type="button" className="ghost" onClick={() => flowFile.current?.click()}>
              Upload log
            </button>
            <input
              ref={flowFile}
              type="file"
              accept=".json,.jsonl,.log,.txt,.csv"
              className="wg-sr-only"
              tabIndex={-1}
              aria-hidden="true"
              onChange={async (e) => {
                const t = await readFile(e);
                if (t != null) setFlows(t);
              }}
            />
          </div>
          <textarea
            id={ids.flows}
            className="mono wg-textarea"
            rows={4}
            spellCheck={false}
            placeholder="Zeek conn.log, firewall allow/deny logs, or JSON lines with src, dst, proto, dport"
            value={flows}
            onChange={(e) => setFlows(e.target.value)}
          />
        </div>
      </details>

      <div className="wg-gate-actions">
        <button type="button" className="primary" onClick={submit} disabled={check.isPending}>
          {check.isPending ? "Checking…" : "Check this change"}
        </button>
        {(plan || flows) && (
          <button
            type="button"
            className="ghost"
            onClick={() => {
              setPlan("");
              setFlows("");
              setLocalError(null);
              setSampleResult(null);
              check.reset();
            }}
          >
            Clear
          </button>
        )}
      </div>

      <div aria-live="polite" className="wg-gate-out">
        {error && (
          <p id={ids.err} className="wg-error" role="alert">
            {error}
          </p>
        )}
        {result && <ImpactResult result={result} sample={sample} flowsGiven={flowsAtSubmit.current} />}
      </div>
    </div>
  );
}
