/**
 * TwinSetup: the empty state for a tenant with no Wargame assessment yet.
 * Three steps: load a config (read-only), describe the topology, recompute.
 * Step 1 can be done right here; step 2 is an API call (shown verbatim).
 */

import { useId, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import EmptyState from "../EmptyState";
import { ingestWargameConfig } from "../../api/wargame";
import type { WargameTwinSummary } from "../../api/types";
import { CONFIG_VENDORS } from "../../lib/wargame";
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
  const ids = { vendor: useId(), raw: useId(), source: useId() };
  const [vendor, setVendor] = useState(CONFIG_VENDORS[0].value);
  const [raw, setRaw] = useState("");
  const [source, setSource] = useState("");
  const file = useRef<HTMLInputElement>(null);
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

  const hasRules = (twin?.ruleset_count ?? 0) > 0;
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
      </ol>
    </section>
  );
}
