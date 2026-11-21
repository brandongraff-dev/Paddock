-- 016: integrations core (dispatcher + delivery log). Additive to 015.

-- Delivery log page: newest first, per integration (GET /v1/integrations/{id}/deliveries).
CREATE INDEX IF NOT EXISTS idx_integration_deliveries_log
  ON integration_deliveries (integration_id, created_at DESC, id DESC);

-- Matching on emit: enabled integrations subscribed to an event type.
CREATE INDEX IF NOT EXISTS idx_integrations_events
  ON integrations USING GIN (events) WHERE enabled;
