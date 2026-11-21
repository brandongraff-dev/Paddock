/**
 * Explore — the ontology / semantic layer.
 *
 * The Palantir move: analysts navigate typed Entities and their links, not
 * rows. Left rail = object-type picker (colored, with live counts). Center =
 * the typed-object list for the selected type (or cross-type search results).
 * Clicking an object opens the object view: its typed properties plus its
 * linked objects grouped by link type + direction, each neighbour clickable to
 * pivot (object-to-object navigation).
 *
 * Dark/dense, self-contained styles in ../styles/ontology.css. Reuses the
 * shared ClassificationChip so markings stay consistent with the rest of the app.
 */

import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ClassificationChip } from "../components/Classification";
import {
  getOntologyObject,
  getOntologyTypes,
  listOntologyObjects,
  searchOntology,
  type OntologyObject,
  type OntologyObjectType,
} from "../api/ontology";
import "../styles/ontology.css";

const PAGE = 50;

function typeColor(t?: OntologyObjectType, fallback = "var(--accent)"): string {
  return t?.color || fallback;
}

/** A compact key/value table of an object's typed properties. */
function PropertyTable({ props }: { props: Record<string, unknown> }) {
  const entries = Object.entries(props).filter(([, v]) => v !== null && v !== undefined && v !== "");
  if (entries.length === 0) {
    return <div className="ont-empty">No properties.</div>;
  }
  return (
    <table className="ont-props">
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k}>
            <td className="ont-props-k mono">{k}</td>
            <td className="ont-props-v mono">{String(v)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** The object view panel: entity header, properties, and grouped neighbours. */
function ObjectView({
  id,
  colorFor,
  onPivot,
}: {
  id: string;
  colorFor: (type: string) => string;
  onPivot: (obj: OntologyObject) => void;
}) {
  const q = useQuery({
    queryKey: ["ontology", "object", id],
    queryFn: () => getOntologyObject(id),
  });

  if (q.isLoading) return <div className="ont-empty">Loading object…</div>;
  if (q.isError) return <div className="ont-error">Failed to load object: {(q.error as Error).message}</div>;
  const view = q.data!;
  const { object, groups } = view;
  const accent = colorFor(object.object_type);

  return (
    <div className="ont-view">
      <div className="ont-view-head" style={{ borderColor: accent }}>
        <div className="ont-view-type" style={{ color: accent }}>
          <span className="ont-dot" style={{ background: accent }} />
          {object.object_type}
        </div>
        <div className="ont-view-title">{object.title}</div>
        <ClassificationChip c={object.classification} compact />
      </div>

      <div className="ont-section-label">Properties</div>
      <PropertyTable props={object.properties} />

      <div className="ont-section-label">
        Links {groups.length > 0 && <span className="ont-count">{groups.reduce((n, g) => n + g.objects.length, 0)}</span>}
      </div>
      {groups.length === 0 && <div className="ont-empty">No linked objects.</div>}
      {groups.map((g) => (
        <div className="ont-linkgroup" key={`${g.link_type}:${g.direction}`}>
          <div className="ont-linkgroup-head">
            <span className="ont-linktype mono">{g.display}</span>
            <span className={`ont-dir ont-dir-${g.direction}`}>
              {g.direction === "out" ? "→" : "←"}
            </span>
            <span className="ont-count">{g.objects.length}</span>
          </div>
          <div className="ont-neighbours">
            {g.objects.map((o) => {
              const c = colorFor(o.object_type);
              return (
                <button
                  key={o.id}
                  className="ont-neighbour"
                  onClick={() => onPivot(o)}
                  title={`Pivot to ${o.object_type}: ${o.title}`}
                >
                  <span className="ont-dot" style={{ background: c }} />
                  <span className="ont-neighbour-type mono" style={{ color: c }}>
                    {o.object_type}
                  </span>
                  <span className="ont-neighbour-title">{o.title}</span>
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

export default function ExplorePage() {
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);

  const typesQ = useQuery({ queryKey: ["ontology", "types"], queryFn: getOntologyTypes });

  // Color lookup by object-type name (from the type system).
  const colorByType = useMemo(() => {
    const m = new Map<string, string>();
    for (const t of typesQ.data?.object_types ?? []) m.set(t.name, typeColor(t));
    return m;
  }, [typesQ.data]);
  const colorFor = (name: string) => colorByType.get(name) || "var(--accent)";

  // Default the selected type to the first non-empty type once loaded.
  useEffect(() => {
    if (selectedType || !typesQ.data) return;
    const first = [...typesQ.data.object_types].sort((a, b) => b.count - a.count)[0];
    if (first) setSelectedType(first.name);
  }, [typesQ.data, selectedType]);

  const searching = search.trim().length > 0;

  const listQ = useQuery({
    queryKey: ["ontology", "objects", selectedType, page],
    queryFn: () => listOntologyObjects({ type: selectedType!, limit: PAGE, offset: page * PAGE }),
    enabled: !searching && !!selectedType,
  });

  const searchQ = useQuery({
    queryKey: ["ontology", "search", search.trim()],
    queryFn: () => searchOntology(search.trim(), 100),
    enabled: searching,
  });

  const rows: OntologyObject[] = searching ? searchQ.data ?? [] : listQ.data?.items ?? [];
  const total = searching ? rows.length : listQ.data?.total ?? 0;

  return (
    <div className="page ont-page">
      <div className="page-header">
        <div>
          <h1>Explore</h1>
          <div className="subtitle">
            Typed entities &amp; links — projected from the raw tables. Click an object to pivot.
          </div>
        </div>
        <input
          className="ont-search mono"
          placeholder="Search entities across all types…"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(0);
          }}
        />
      </div>

      <div className="ont-layout">
        {/* Left: object-type picker */}
        <aside className="ont-types panel">
          <div className="ont-section-label">Object types</div>
          {typesQ.isLoading && <div className="ont-empty">Loading…</div>}
          {(typesQ.data?.object_types ?? []).map((t) => {
            const active = !searching && t.name === selectedType;
            const c = typeColor(t);
            return (
              <button
                key={t.name}
                className={`ont-type-item${active ? " active" : ""}`}
                style={active ? { borderColor: c } : undefined}
                onClick={() => {
                  setSearch("");
                  setSelectedType(t.name);
                  setPage(0);
                }}
                disabled={t.count === 0}
              >
                <span className="ont-dot" style={{ background: c }} />
                <span className="ont-type-name">{t.display}</span>
                <span className="ont-type-count">{t.count}</span>
              </button>
            );
          })}
        </aside>

        {/* Center: typed-object list / search results */}
        <section className="ont-list panel">
          <div className="ont-list-head">
            <span className="mono">
              {searching ? `Search: "${search.trim()}"` : selectedType ?? "—"}
            </span>
            <span className="ont-count">{total}</span>
          </div>
          <div className="ont-list-body">
            {(searching ? searchQ.isLoading : listQ.isLoading) && (
              <div className="ont-empty">Loading objects…</div>
            )}
            {rows.length === 0 && !(searching ? searchQ.isLoading : listQ.isLoading) && (
              <div className="ont-empty">No objects.</div>
            )}
            {rows.map((o) => {
              const c = colorFor(o.object_type);
              const active = o.id === selectedId;
              const keys = Object.keys(o.properties).slice(0, 3);
              return (
                <button
                  key={o.id}
                  className={`ont-row${active ? " active" : ""}`}
                  onClick={() => setSelectedId(o.id)}
                >
                  <span className="ont-dot" style={{ background: c }} />
                  <span className="ont-row-main">
                    <span className="ont-row-title">{o.title}</span>
                    <span className="ont-row-meta mono">
                      {searching && (
                        <span className="ont-row-type" style={{ color: c }}>
                          {o.object_type}
                        </span>
                      )}
                      {keys.map((k) => (
                        <span key={k} className="ont-kv">
                          {k}=<b>{String(o.properties[k])}</b>
                        </span>
                      ))}
                    </span>
                  </span>
                  <ClassificationChip c={o.classification} compact note={false} />
                </button>
              );
            })}
          </div>
          {!searching && total > PAGE && (
            <div className="ont-pager">
              <button className="ghost" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                ← Prev
              </button>
              <span className="mono">
                {page * PAGE + 1}–{Math.min((page + 1) * PAGE, total)} of {total}
              </span>
              <button
                className="ghost"
                disabled={(page + 1) * PAGE >= total}
                onClick={() => setPage((p) => p + 1)}
              >
                Next →
              </button>
            </div>
          )}
        </section>

        {/* Right: object view */}
        <section className="ont-detail panel">
          {selectedId ? (
            <ObjectView
              id={selectedId}
              colorFor={colorFor}
              onPivot={(obj) => setSelectedId(obj.id)}
            />
          ) : (
            <div className="ont-empty ont-detail-empty">
              Select an object to open its view.
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
