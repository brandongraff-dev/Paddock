-- Ontology / semantic layer: a typed entity model projected over the raw
-- tables, so analysts work with Objects + Links (Palantir-style) instead of
-- rows. A projector derives objects/links from assets/findings/etc.
-- Applied after 001-011.

CREATE TABLE IF NOT EXISTS ontology_object_types (
  name            TEXT PRIMARY KEY,          -- Host, Service, Technology, Vulnerability, Repository, Secret, Team, Ticket, AttackPath, Package, Certificate
  display         TEXT NOT NULL,
  icon            TEXT,
  color           TEXT,
  property_schema JSONB NOT NULL DEFAULT '{}'::jsonb,   -- {property_name: type}
  source          TEXT NOT NULL,             -- backing table/view the projector reads
  enabled         BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS ontology_link_types (
  name         TEXT PRIMARY KEY,             -- RESOLVES_TO, RUNS, AFFECTS, OWNS, CONTAINS, ON_PATH, ASSIGNED_TO, DECLARES, MATCHES_IOC
  display      TEXT NOT NULL,
  from_type    TEXT NOT NULL REFERENCES ontology_object_types(name),
  to_type      TEXT NOT NULL REFERENCES ontology_object_types(name),
  cardinality  TEXT NOT NULL DEFAULT 'many_to_many'
);

CREATE TABLE IF NOT EXISTS ontology_objects (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  object_type    TEXT NOT NULL REFERENCES ontology_object_types(name),
  title          TEXT NOT NULL,
  properties     JSONB NOT NULL DEFAULT '{}'::jsonb,
  backing_table  TEXT NOT NULL,              -- provenance: where this object was projected from
  backing_id     TEXT NOT NULL,
  classification TEXT NOT NULL DEFAULT 'internal'
                   CHECK (classification IN ('public','internal','confidential','restricted')),
  first_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (object_type, backing_table, backing_id)
);

CREATE INDEX IF NOT EXISTS idx_ont_objects_type ON ontology_objects(object_type);
CREATE INDEX IF NOT EXISTS idx_ont_objects_title ON ontology_objects(title);
CREATE INDEX IF NOT EXISTS idx_ont_objects_backing ON ontology_objects(backing_table, backing_id);

CREATE TABLE IF NOT EXISTS ontology_links (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  link_type   TEXT NOT NULL REFERENCES ontology_link_types(name),
  from_object UUID NOT NULL REFERENCES ontology_objects(id) ON DELETE CASCADE,
  to_object   UUID NOT NULL REFERENCES ontology_objects(id) ON DELETE CASCADE,
  properties  JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (link_type, from_object, to_object)
);

CREATE INDEX IF NOT EXISTS idx_ont_links_from ON ontology_links(from_object, link_type);
CREATE INDEX IF NOT EXISTS idx_ont_links_to ON ontology_links(to_object, link_type);
