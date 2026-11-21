-- 017: two-way ticketing (Jira / ServiceNow / Linear) -- additive to 015.
--
-- Inbound webhook replay protection: senders that stamp each delivery with
-- an id (Jira X-Atlassian-Webhook-Identifier, Linear-Delivery, the
-- ServiceNow business rule's X-Paddock-Delivery) are processed at most once.
-- Rows older than 7 days are pruned opportunistically by the inbound router.
CREATE TABLE IF NOT EXISTS integration_inbound_deliveries (
  integration_id  UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
  delivery_id     TEXT NOT NULL,
  received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (integration_id, delivery_id)
);
CREATE INDEX IF NOT EXISTS idx_integration_inbound_deliveries_received
  ON integration_inbound_deliveries (received_at);

-- Reverse lookups ("which tickets mirror this finding?") for the finding page.
CREATE INDEX IF NOT EXISTS idx_integration_links_finding
  ON integration_links (finding_id);
