-- 018: standards exports / imports (orchestrator/app/routers/exports.py)
--
-- Which manifest files (lockfiles, or an imported CycloneDX/SPDX document) a
-- project's SBOM came from. The SBOM tables do not record a component's
-- source file; the SARIF export uses this to place dependency results on the
-- right lockfile so they show up against a real path in GitHub code scanning.
-- Only paths + digests are stored, never file contents.

CREATE TABLE IF NOT EXISTS sca_project_manifests (
  project_id   UUID NOT NULL REFERENCES sca_projects(id) ON DELETE CASCADE,
  path         TEXT NOT NULL,                       -- repo-relative path as uploaded
  ecosystem    TEXT,                                -- npm, PyPI, Go, ... (NULL for SBOM docs)
  kind         TEXT NOT NULL DEFAULT 'lockfile'
               CHECK (kind IN ('lockfile', 'cyclonedx', 'spdx')),
  sha256       TEXT,
  size_bytes   INTEGER,
  uploaded_by  TEXT,
  uploaded_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (project_id, path)
);

CREATE INDEX IF NOT EXISTS idx_sca_project_manifests_eco
  ON sca_project_manifests (project_id, ecosystem);
