/**
 * Settings → About (admin). What version this is, which parts of Paddock are
 * solid and which are not proven yet, and what changed. The content is
 * CHANGELOG.md, turned into data by scripts/export_changelog.py, so this page
 * cannot say something the changelog does not.
 */
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { getSystem } from "../api/system";
import StatTile from "../components/StatTile";
import { CHANGELOG } from "./about/changelog.generated";
import type { AreaState, Release } from "./about/types";
import "../styles/system.css";
import "../styles/about.css";

const STATE_LABEL: Record<AreaState, string> = {
  working: "Working",
  beta: "Beta",
  unverified: "Not yet verified",
  "not released": "Not released",
};

const STATE_HELP: Record<AreaState, string> = {
  working: "Built and covered by automated tests.",
  beta: "Works, with known gaps.",
  unverified: "Tested in CI, never run on the real hardware, cluster or service it is for.",
  "not released": "Does not exist for users yet.",
};

const ORDER: AreaState[] = ["working", "beta", "unverified", "not released"];

export function StateChip({ state }: { state: AreaState }) {
  return (
    <span className="about-chip" data-state={state}>
      <i aria-hidden="true" />
      {STATE_LABEL[state]}
    </span>
  );
}

function ReleaseBlock({ r }: { r: Release }) {
  const title = r.version === "Unreleased" ? "Unreleased" : `Version ${r.version}`;
  return (
    <article className="about-release" data-version={r.version}>
      <h3>
        {title}
        {r.date && <time dateTime={r.date}>{r.date}</time>}
      </h3>
      {r.version === "Unreleased" && <p className="about-note">Changes on the way to the next release.</p>}
      {r.sections.map((s) => (
        <section key={s.kind} className="about-kind" data-kind={s.kind}>
          <h4>{s.kind}</h4>
          <ul>{s.items.map((it, i) => <li key={i}>{it}</li>)}</ul>
        </section>
      ))}
    </article>
  );
}

export default function AboutPage() {
  const q = useQuery({ queryKey: ["system"], queryFn: getSystem, staleTime: 15000 });
  const counts = ORDER.map((s) => [s, CHANGELOG.state.filter((r) => r.state === s).length] as const).filter(([, n]) => n > 0);
  const shipped = CHANGELOG.releases.find((r) => r.version !== "Unreleased");
  const pending = CHANGELOG.releases.find((r) => r.version === "Unreleased");
  const pendingCount = pending ? pending.sections.reduce((n, s) => n + s.items.length, 0) : 0;

  return (
    <div className="page system-page about-page">
      <div className="page-header">
        <div>
          <h1>About</h1>
          <div className="subtitle">What version this is, what is solid and what is not proven yet, and what changed.</div>
        </div>
        <Link to="/settings/system" className="about-back">System health →</Link>
      </div>

      <div className="sys-tiles">
        <StatTile label="Version" value={q.data?.version ?? (q.isError ? "Unknown" : "…")} hint={q.isError ? "Could not read it from the server" : undefined} />
        <StatTile label="Latest release" value={shipped ? shipped.version : "None yet"} hint={shipped ? shipped.date ?? undefined : "Pre-release: builds from source"} />
        <StatTile label="Waiting for release" value={String(pendingCount)} hint="changes in Unreleased" />
      </div>

      <section className="panel" aria-labelledby="about-state-h">
        <div className="panel-h"><h2 id="about-state-h">State of the app</h2></div>
        <p className="about-summary">
          {counts.map(([s, n], i) => (
            <span key={s}>{i > 0 && " · "}<strong>{n}</strong> {STATE_LABEL[s].toLowerCase()}</span>
          ))}
        </p>
        <table className="table about-table">
          <thead><tr><th>Area</th><th>State</th><th>Notes</th></tr></thead>
          <tbody>
            {CHANGELOG.state.map((r) => (
              <tr key={r.area} data-state={r.state}>
                <th scope="row">{r.area}</th>
                <td><StateChip state={r.state} /></td>
                <td className="about-notes">{r.notes}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <dl className="about-legend">
          {ORDER.map((s) => (
            <div key={s}><dt><StateChip state={s} /></dt><dd>{STATE_HELP[s]}</dd></div>
          ))}
        </dl>
      </section>

      <section className="panel" aria-labelledby="about-new-h">
        <div className="panel-h"><h2 id="about-new-h">What&rsquo;s new</h2></div>
        <div className="about-releases">
          {CHANGELOG.releases.map((r) => <ReleaseBlock key={r.version} r={r} />)}
        </div>
      </section>

      {CHANGELOG.other.map((o) => (
        <section key={o.title} className="panel">
          <div className="panel-h"><h2>{o.title}</h2></div>
          <ul className="about-history">{o.items.map((it, i) => <li key={i}>{it}</li>)}</ul>
        </section>
      ))}

      <p className="sys-foot">
        This page is generated from <code>CHANGELOG.md</code> in the repository. Detailed status for each area is in <code>docs/READINESS.md</code>.
      </p>
    </div>
  );
}
