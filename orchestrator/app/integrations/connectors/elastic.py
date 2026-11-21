"""Elasticsearch / Elastic Security connector -- OCSF JSON via ``_bulk``.

* ``POST {url}/_bulk`` (NDJSON) with ``Authorization: ApiKey <encoded>``
  (the base64 ``id:api_key`` value Kibana shows as "Encoded").
* Each document is the OCSF object plus ``@timestamp`` (required by data
  streams) and ``event.id``. The action is ``create`` with ``_id`` = the
  Paddock event id, so a dispatcher retry of an already-indexed event is a
  ``409 version_conflict`` -- treated as success (idempotent delivery).
* Target: a data stream (default ``logs-paddock.ocsf-default``, matching the
  built-in ``logs-*-*`` index template) or any index name.
* ``_bulk`` answers 200 even when items fail; per-item statuses are read:
  409 = duplicate (ok), 429/5xx = retryable, anything else (mapping errors,
  403 on the index) = not retryable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, ClassVar

from ..base import DeliveryResult, Event, register
from ._siem import SiemConnector, classify_status


@register
class ElasticConnector(SiemConnector):
    kind = "elastic"
    display_name = "Elasticsearch / Elastic Security"
    docs_url = "https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html"
    secret_fields = ("api_key",)
    max_batch: ClassVar[int] = 500
    config_schema = {
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string", "format": "uri",
                    "description": "Elasticsearch URL, e.g. https://my-deployment.es.us-east-1.aws.elastic.cloud"},
            "data_stream": {"type": "string", "default": "logs-paddock.ocsf-default",
                            "description": "Data stream (or index) name"},
            "pipeline": {"type": "string", "description": "Optional ingest pipeline"},
        },
    }

    def target(self) -> str:
        return str(self.config.get("data_stream") or "logs-paddock.ocsf-default")

    def endpoint(self) -> str:
        url = str(self.config.get("url") or "").rstrip("/") + "/_bulk"
        if self.config.get("pipeline"):
            from urllib.parse import quote

            url += "?pipeline=" + quote(str(self.config["pipeline"]), safe="")
        return url

    @staticmethod
    def to_doc(record: dict[str, Any], event: Event) -> dict[str, Any]:
        ts = record.get("time")
        when = (datetime.fromtimestamp(ts / 1000.0, tz=timezone.utc) if isinstance(ts, (int, float))
                else event.occurred_at)
        doc = {"@timestamp": when.isoformat().replace("+00:00", "Z"), **record}
        doc["event"] = {"id": event.id, "kind": "alert", "dataset": "paddock.ocsf",
                        "action": event.type}
        return doc

    def body(self, records: list[dict[str, Any]], events: list[Event]) -> bytes:
        lines: list[str] = []
        idx = self.target()
        for r, e in zip(records, events):
            lines.append(json.dumps({"create": {"_index": idx, "_id": e.id}}, separators=(",", ":")))
            lines.append(json.dumps(self.to_doc(r, e), separators=(",", ":"), default=str))
        return ("\n".join(lines) + "\n").encode("utf-8")

    async def send_records(self, records: list[dict[str, Any]], events: list[Event]) -> DeliveryResult:
        key = self.secrets.get("api_key")
        if not key:
            return self.fail("missing secret 'api_key'", retryable=False)
        if not self.config.get("url"):
            return self.fail("missing config 'url'", retryable=False)
        url = await self.safe_url(self.endpoint())
        resp = await self.client().post(url, content=self.body(records, events), headers={
            "Authorization": f"ApiKey {key}",
            "Content-Type": "application/x-ndjson",
        }, follow_redirects=False)
        if resp.status_code != 200:
            return self.http_failure(resp, "Elasticsearch")
        try:
            payload = resp.json()
        except ValueError:
            return self.fail("Elasticsearch returned a non-JSON _bulk response", retryable=True,
                             status_code=resp.status_code)
        if not payload.get("errors"):
            return DeliveryResult(ok=True, status_code=200,
                                  detail=f"Elasticsearch indexed {len(records)} document(s)")
        created = dup = 0
        retry_fail: list[str] = []
        hard_fail: list[str] = []
        for item in payload.get("items") or []:
            res = item.get("create") or item.get("index") or {}
            st = int(res.get("status") or 0)
            if 200 <= st < 300:
                created += 1
            elif st == 409:
                dup += 1
            else:
                err = res.get("error") or {}
                why = f"{st} {err.get('type', '')}".strip() if isinstance(err, dict) else str(st)
                (retry_fail if classify_status(st) else hard_fail).append(why)
        if not retry_fail and not hard_fail:
            return DeliveryResult(ok=True, status_code=200,
                                  detail=f"Elasticsearch indexed {created}, {dup} already present")
        worst = hard_fail or retry_fail
        detail = (f"Elasticsearch rejected {len(retry_fail) + len(hard_fail)} of {len(records)} "
                  f"document(s): {', '.join(sorted(set(worst))[:5])}")
        # Only retry when every failure is transient; a mapping error would
        # fail forever. Duplicates (409) make a retry of the whole batch safe.
        return self.fail(detail, retryable=not hard_fail, status_code=200)
