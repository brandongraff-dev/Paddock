/**
 * TwinSetup: the empty state for a tenant with no Wargame assessment yet.
 * Three steps: load a config (read-only), describe the topology, recompute,
 * plus an optional fourth: add evidence (flow logs, probe results) so a
 * closed pair can be tested, not just shut on paper. Steps 1 and 4 can be
 * done right here; step 2 is an API call (shown verbatim).
 */

import { useId, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import EmptyState from "../EmptyState";
import { ingestWargameConfig, ingestWargameFlows, ingestWargameProbes } from "../../api/wargame";
import type { WargameTwinSummary } from "../../api/types";
import { CONFIG_VENDORS, FLOW_FORMATS, parseProbeResults } from "../../lib/wargame";
import { useStore } from "../../state/store";

const TOPOLOGY_EXAMPLE = `POST /v1/wargame/twin/topology
{
  "segments": [
    { "id": "guest_wifi",  "cidrs": ["10.9.0.0/24"], "role": "entry" },
    { "id": "pos",         "cidrs": ["10.5.0.0/24"] },
    { "id": "payments_db", "cidrs": ["10.1.0.0/24"], "role": "crown_jewel",
      "reason": "cardholder data" }
  ],
  "edges": [
    { "src": "guest_wifi", "dst": "pos", "rule_set_id": "<from step 1>" },
    { "src": "pos", "dst": "payments_db", "rule_set_id": "<from step 1>" }
  ]
}`;

const PROBE_EXAMPLE = `[{ "src": "guest_wifi", "dst": "payments_db", "port": 5432,
   "result": "blocked", "observed_at": "2026-11-22T09:00:00Z",
   "source": "scanner-01" }]`;

function withWarnings(text: string, warnings: string[] | undefined): string {
  const w = warnings ?? [];
  return w.length ? `${text} (${w.length} warning${w.length === 1 ? "" : "s"}: ${w[0]})` : text;
}

function StepState({ done }: { done: boolean }) {
  return (
    <span className={`wg-step-state ${done ? "is-done" : ""}`}>
      {done ? "Done" : "To do"}
    </span>
  );
}

export default function TwinSetup({
  twin,
  twinError,
  onRecompute,
  recomputing,
  onSample,
}: {
  twin: WargameTwinSummary | undefined;
  twinError: boolean;
  onRecompute: () => void;
  recomputing: boolean;
  onSample: () => void;
}) {
  const ids = {
    vendor: useId(),
    raw: useId(),
    source: useId(),
    flowFormat: useId(),
    flowRaw: useId(),
    flowSource: useId(),
    probeRaw: useId(),
  };
  const [vendor, setVendor] = useState(CONFIG_VENDORS[0].value);
  const [raw, setRaw] = useState("");
  const [source, setSource] = useState("");
  const file = useRef<HTMLInputElement>(null);
  const [flowFormat, setFlowFormat] = useState(FLOW_FORMATS[0].value);
  const [flowRaw, setFlowRaw] = useState("");
  const [flowSource, setFlowSource] = useState("");
  const flowFile = useRef<HTMLInputElement>(null);
  const [probeRaw, setProbeRaw] = useState("");
  const probeFile = useRef<HTMLInputElement>(null);
  const qc = useQueryClient();
  const pushToast = useStore((s) => s.pushToast);

  const ingest = useMutation({
    mutationFn: ingestWargameConfig,
    onSuccess: (r) => {
      if (r.status === "unavailable") {
        pushToast({ text: r.detail || "The analysis service is unreachable; the config was not loaded.", severity: "high" });
        return;
      }
      pushToast({ text: r.detail || (r.status === "queued" ? "Config queued for loading." : "Config loaded.") });
      setRaw("");
      qc.invalidateQueries({ queryKey: ["wargame"] });
    },
    onError: () => pushToast({ text: "Couldn't load that config.", severity: "high" }),
  });

  const flows = useMutation({
    mutationFn: ingestWargameFlows,
    onSuccess: (r) => {
      if (r.status === "unavailable") {
        pushToast({ text: r.detail || "The analysis service is unreachable; the flows were not loaded.", severity: "high" });
        return;
      }
      const text = r.status === "queued" ? "Flow logs queued for loading." : r.detail || "Flow logs loaded.";
      pushToast({ text: withWarnings(text, r.warnings), severity: r.flows_stored === 0 ? "medium" : undefined });
      setFlowRaw("");
      qc.invalidateQueries({ queryKey: ["wargame"] });
    },
    onError: () => pushToast({ text: "Couldn't load those flow logs.", severity: "high" }),
  });

  const probes = useMutation({
    mutationFn: ingestWargameProbes,
    onSuccess: (r) => {
      if (r.status === "unavailable") {
        pushToast({ text: r.detail || "The analysis service is unreachable; the results were not recorded.", severity: "high" });
        return;
      }
      const text = r.status === "queued" ? "Probe results queued." : r.detail || "Probe results recorded.";
      pushToast({ text: withWarnings(text, r.warnings), severity: r.rejected ? "medium" : undefined });
      setProbeRaw("");
      qc.invalidateQueries({ queryKey: ["wargame"] });
    },
    onError: () => pushToast({ text: "Couldn't record those probe results.", severity: "high" }),
  });

  const hasRules = (twin?.ruleset_count ?? 0) > 0;
  const flowCount = twin?.flow_count ?? 0;
  const probeCount = twin?.probe_count ?? 0;
  const hasEvidence = flowCount > 0 || probeCount > 0;
  const hasTopo = (twin?.segment_count ?? 0) > 0;

  return (
    <section className="panel wg-setup" aria-labelledby="wg-setup-h">
      <div className="panel-h">
        <h2 id="wg-setup-h">Set up Wargame</h2>
        <button type="button" className="ghost" onClick={onSample}>
          Preview with sample data
        </button>
      </div>

      <EmptyState
        icon="◇"
        title={twin?.has_twin ? "Your network model is loaded, but nothing has been assessed yet." : "No network model yet, so there's nothing to assess."}
        hint={
          <>
            Wargame works backward from your crown jewels over your own firewall and cloud config, and shows who can
            reach them. It reads config only. It never sends exploits.
            {twinError && " (Couldn't read the current model's status.)"}
          </>
        }
      />

      <ol className="wg-steps">
        <li className="wg-step">
          <div className="wg-step-h">
            <span className="wg-step-n" aria-hidden="true">1</span>
            <h3>Load a firewall or cloud config</h3>
            <StepState done={hasRules} />
          </div>
          <p>
            Export the running config (read-only) and load it. It is parsed into rules, never pushed back to the
            device.{" "}
            {hasRules && (
              <span className="wg-muted">
                Loaded so far: {twin!.ruleset_count} rule sets, {twin!.rule_count} rules, {twin!.snapshot_count} snapshots.
              </span>
            )}
          </p>
          <code className="wg-code-inline">POST /v1/wargame/twin/config {"{ vendor, raw, source }"}</code>
          <form
            className="wg-ingest"
            onSubmit={(e) => {
              e.preventDefault();
              if (!raw.trim()) return;
              ingest.mutate({ vendor, raw, source: source.trim() });
            }}
          >
            <div className="wg-ingest-row">
              <label htmlFor={ids.vendor}>Vendor</label>
              <select id={ids.vendor} value={vendor} onChange={(e) => setVendor(e.target.value)}>
                {CONFIG_VENDORS.map((v) => (
                  <option key={v.value} value={v.value}>
                    {v.label}
                  </option>
                ))}
              </select>
              <label htmlFor={ids.source}>Name</label>
              <input
                id={ids.source}
                placeholder="e.g. fw-core-01"
                value={source}
                onChange={(e) => setSource(e.target.value)}
              />
              <button type="button" className="ghost" onClick={() => file.current?.click()}>
                Upload file
              </button>
              <input
                ref={file}
                type="file"
                className="wg-sr-only"
                tabIndex={-1}
                aria-hidden="true"
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  e.target.value = "";
                  if (!f) return;
                  setRaw(await f.text());
                  if (!source) setSource(f.name);
                }}
              />
            </div>
            <label htmlFor={ids.raw} className="wg-sr-only">
              Config text
            </label>
            <textarea
              id={ids.raw}
              className="mono wg-textarea"
              rows={4}
              spellCheck={false}
              placeholder="Paste the exported config here"
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
            />
            <div>
              <button type="submit" disabled={!raw.trim() || ingest.isPending}>
                {ingest.isPending ? "Loading…" : "Load config"}
              </button>
            </div>
          </form>
        </li>

        <li className="wg-step">
          <div className="wg-step-h">
            <span className="wg-step-n" aria-hidden="true">2</span>
            <h3>Say where things sit, and name your crown jewels</h3>
            <StepState done={hasTopo} />
          </div>
          <p>
            Describe your segments (with their address ranges), mark entry points and up to 10 crown jewels, and say
            which rule set guards each link.{" "}
            {hasTopo && (
              <span className="wg-muted">
                Loaded so far: {twin!.segment_count} segments, {twin!.edge_count} links.
              </span>
            )}
          </p>
          <pre className="wg-code" tabIndex={0} aria-label="Example topology request">
            {TOPOLOGY_EXAMPLE}
          </pre>
        </li>

        <li className="wg-step">
          <div className="wg-step-h">
            <span className="wg-step-n" aria-hidden="true">3</span>
            <h3>Run the assessment</h3>
          </div>
          <p>
            Paddock searches backward from each crown jewel, labels every hop with how well it's proved, and works out
            the cheapest set of changes that cuts every route.
          </p>
          <div>
            <button type="button" className="primary" onClick={onRecompute} disabled={recomputing}>
              {recomputing ? "Recomputing…" : "Recompute"}
            </button>
          </div>
        </li>

        <li className="wg-step">
          <div className="wg-step-h">
            <span className="wg-step-n" aria-hidden="true">4</span>
            <h3>Add evidence (optional): upload flow logs / probe results</h3>
            <StepState done={hasEvidence} />
          </div>
          <p>
            Without evidence a closed boundary is shut on paper only. A blocked probe from an entry point to a crown
            jewel makes it shut, proved and tested; real traffic across it, or a probe that got through, flags it open.
            Recompute afterwards to fold the evidence in.{" "}
            {hasEvidence && (
              <span className="wg-muted">
                Stored so far: {flowCount} flows, {probeCount} probe results ({twin?.probe_fresh_count ?? 0} recent
                enough to count).
              </span>
            )}
          </p>

          <form
            className="wg-ingest"
            aria-label="Flow logs"
            onSubmit={(e) => {
              e.preventDefault();
              if (!flowRaw.trim()) return;
              flows.mutate({ raw: flowRaw, format: flowFormat, source: flowSource.trim() });
            }}
          >
            <h4 className="wg-ingest-h">Flow logs</h4>
            <code className="wg-code-inline">POST /v1/wargame/twin/flows {"{ raw, format, source }"}</code>
            <div className="wg-ingest-row">
              <label htmlFor={ids.flowFormat}>Format</label>
              <select id={ids.flowFormat} value={flowFormat} onChange={(e) => setFlowFormat(e.target.value)}>
                {FLOW_FORMATS.map((f) => (
                  <option key={f.value} value={f.value}>
                    {f.label}
                  </option>
                ))}
              </select>
              <label htmlFor={ids.flowSource}>Name</label>
              <input
                id={ids.flowSource}
                placeholder="e.g. zeek-dmz"
                value={flowSource}
                onChange={(e) => setFlowSource(e.target.value)}
              />
              <button type="button" className="ghost" onClick={() => flowFile.current?.click()}>
                Upload file
              </button>
              <input
                ref={flowFile}
                type="file"
                className="wg-sr-only"
                tabIndex={-1}
                aria-hidden="true"
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  e.target.value = "";
                  if (!f) return;
                  setFlowRaw(await f.text());
                  if (!flowSource) setFlowSource(f.name);
                }}
              />
            </div>
            <label htmlFor={ids.flowRaw} className="wg-sr-only">
              Flow log text
            </label>
            <textarea
              id={ids.flowRaw}
              className="mono wg-textarea"
              rows={3}
              spellCheck={false}
              placeholder="Paste firewall allow/deny logs, Zeek conn.log (JSON lines) or generic JSON flows"
              value={flowRaw}
              onChange={(e) => setFlowRaw(e.target.value)}
            />
            <div>
              <button type="submit" disabled={!flowRaw.trim() || flows.isPending}>
                {flows.isPending ? "Loading…" : "Load flows"}
              </button>
            </div>
          </form>

          <form
            className="wg-ingest"
            aria-label="Probe results"
            onSubmit={(e) => {
              e.preventDefault();
              if (!probeRaw.trim()) return;
              let results;
              try {
                results = parseProbeResults(probeRaw);
              } catch (err) {
                pushToast({ text: (err as Error).message, severity: "high" });
                return;
              }
              probes.mutate({ results });
            }}
          >
            <h4 className="wg-ingest-h">Probe results</h4>
            <p className="wg-muted">
              Results your own probe or scanner recorded, from one named segment to another. Paddock sends no packets
              for this. A result counts for a crown jewel only if it ran from the entry segment to the jewel's segment,
              within the last 24 hours; errors never count.
            </p>
            <code className="wg-code-inline">POST /v1/wargame/twin/probes {"{ results: [...] }"}</code>
            <pre className="wg-code" tabIndex={0} aria-label="Example probe results">
              {PROBE_EXAMPLE}
            </pre>
            <div className="wg-ingest-row">
              <button type="button" className="ghost" onClick={() => probeFile.current?.click()}>
                Upload file
              </button>
              <input
                ref={probeFile}
                type="file"
                className="wg-sr-only"
                tabIndex={-1}
                aria-hidden="true"
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  e.target.value = "";
                  if (!f) return;
                  setProbeRaw(await f.text());
                }}
              />
            </div>
            <label htmlFor={ids.probeRaw} className="wg-sr-only">
              Probe results JSON
            </label>
            <textarea
              id={ids.probeRaw}
              className="mono wg-textarea"
              rows={3}
              spellCheck={false}
              placeholder="Paste probe results as JSON"
              value={probeRaw}
              onChange={(e) => setProbeRaw(e.target.value)}
            />
            <div>
              <button type="submit" disabled={!probeRaw.trim() || probes.isPending}>
                {probes.isPending ? "Recording…" : "Record results"}
              </button>
            </div>
          </form>
        </li>
      </ol>
    </section>
  );
}
