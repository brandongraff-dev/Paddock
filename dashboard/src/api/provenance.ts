/**
 * Provenance / lineage endpoint (governance §A). One call per subject
 * (finding or asset) powers the "Provenance" section in the detail drawers.
 */

import { apiFetch } from "./client";
import type { ProvenanceRecord } from "./types";

/** GET /v1/provenance?subject_type=&subject_id= — lineage for one item. */
export function listProvenance(
  subjectType: "finding" | "asset" | string,
  subjectId: string,
): Promise<ProvenanceRecord[]> {
  return apiFetch<{ items: ProvenanceRecord[] } | ProvenanceRecord[]>("/v1/provenance", {
    query: { subject_type: subjectType, subject_id: subjectId },
  }).then((r) => (Array.isArray(r) ? r : r.items ?? []));
}
