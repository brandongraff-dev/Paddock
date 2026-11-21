"""Request/response models for the verification API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

Verdict = Literal["confirmed", "not_reproducible", "inconclusive"]
Exploitability = Literal["unverified", "confirmed", "not_reproducible", "inconclusive"]
Purpose = Literal["exploitability", "fix"]
Status = Literal["scheduled", "queued", "done", "refused", "unsupported", "error", "cancelled"]

BULK_MAX = 100


class VerificationOut(BaseModel):
    id: UUID
    finding_id: UUID
    purpose: Purpose
    trigger: str
    requested_by: str
    status: Status
    verdict: Verdict | None = None
    check_id: str | None = None
    target: str | None = None
    scope_entry_id: int | None = None
    scope_proof: str | None = None
    scan_id: UUID | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    reason: str | None = None
    requested_at: datetime
    run_after: datetime | None = None
    dispatched_at: datetime | None = None
    checked_at: datetime | None = None
    completed_at: datetime | None = None
    # POST /verify only: an in-flight verification already existed and was returned
    already_in_flight: bool = False


class VerifyIn(BaseModel):
    """Optional body for POST /v1/findings/{id}/verify."""

    reason: str | None = Field(None, max_length=500, description="why (recorded on the ledger)")


class BulkVerifyIn(BaseModel):
    finding_ids: list[UUID] = Field(min_length=1, max_length=BULK_MAX)


class BulkVerifyItem(BaseModel):
    finding_id: UUID
    outcome: Literal["queued", "already_in_flight", "refused", "not_found", "error"]
    verification_id: UUID | None = None
    reason: str | None = None


class BulkVerifyOut(BaseModel):
    requested: int
    queued: int
    refused: int
    items: list[BulkVerifyItem]


class VerificationHistoryOut(BaseModel):
    finding_id: UUID
    exploitability: Exploitability
    last_verified_at: datetime | None = None
    fix_verified_at: datetime | None = None
    items: list[VerificationOut]


class ResultIn(BaseModel):
    """What the worker reports back for one verification job."""

    status: Literal["done", "refused", "unsupported", "error"]
    verdict: Verdict | None = None
    check_id: str | None = Field(None, max_length=64)
    reason: str | None = Field(None, max_length=1000)
    evidence: dict[str, Any] = Field(default_factory=dict)
    checked_at: datetime | None = None

    @model_validator(mode="after")
    def _verdict_matches_status(self) -> "ResultIn":
        if self.status == "done" and self.verdict is None:
            raise ValueError("a 'done' result needs a verdict")
        if self.status != "done" and self.verdict is not None:
            raise ValueError(f"a '{self.status}' result cannot carry a verdict")
        return self


class RemediationMergedIn(BaseModel):
    pr_url: str | None = Field(None, max_length=500)
