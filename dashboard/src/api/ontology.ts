/**
 * Ontology / semantic-layer API client.
 *
 * Typed fetchers for the orchestrator's `/v1/ontology/*` read surface. Local
 * TS types live here (the shared api/types.ts is intentionally untouched).
 * Paged endpoints return the standard `{items,total,limit,offset}` envelope;
 * the list/search helpers unwrap to the bare array the UI consumes, matching
 * the convention in api/findings.ts.
 */

import { apiFetch } from "./client";
import type { Classification } from "./types";

export interface OntologyObjectType {
  name: string;
  display: string;
  icon?: string | null;
  color?: string | null;
  property_schema: Record<string, string>;
  source: string;
  enabled: boolean;
  count: number;
}

export interface OntologyLinkType {
  name: string;
  display: string;
  from_type: string;
  to_type: string;
  cardinality: string;
}

export interface OntologyTypes {
  object_types: OntologyObjectType[];
  link_types: OntologyLinkType[];
}

export interface OntologyObject {
  id: string;
  object_type: string;
  title: string;
  properties: Record<string, unknown>;
  backing_table: string;
  backing_id: string;
  classification: Classification;
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface OntologyPage {
  items: OntologyObject[];
  total: number;
  limit: number;
  offset: number;
}

/** Neighbours reached from the focus object over one link type + direction. */
export interface OntologyLinkGroup {
  link_type: string;
  display: string;
  direction: "out" | "in";
  objects: OntologyObject[];
}

export interface OntologyObjectView {
  object: OntologyObject;
  groups: OntologyLinkGroup[];
}

/** Object types (with live counts) + all link types. */
export function getOntologyTypes(): Promise<OntologyTypes> {
  return apiFetch<OntologyTypes>("/v1/ontology/types");
}

/** Paged typed objects. Returns the full envelope so callers can page. */
export function listOntologyObjects(q?: {
  type?: string;
  q?: string;
  limit?: number;
  offset?: number;
}): Promise<OntologyPage> {
  return apiFetch<OntologyPage>("/v1/ontology/objects", { query: q });
}

/** The object view: an entity plus its neighbours grouped by link type. */
export function getOntologyObject(id: string): Promise<OntologyObjectView> {
  return apiFetch<OntologyObjectView>(`/v1/ontology/objects/${encodeURIComponent(id)}`);
}

/** Cross-type title search; unwraps to the bare array. */
export function searchOntology(query: string, limit = 50): Promise<OntologyObject[]> {
  return apiFetch<OntologyPage | OntologyObject[]>("/v1/ontology/search", {
    query: { q: query, limit },
  }).then((r) => (Array.isArray(r) ? r : r.items ?? []));
}
