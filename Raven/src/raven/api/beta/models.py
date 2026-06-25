from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field

DecisionTaken = Literal["ACCEPT", "REVIEW", "BLOCK", "IGNORE", "INVESTIGATE", "OTHER"]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Existing models (unchanged public contract) ───────────────────────────────

class DecisionImpactRequest(BaseModel):
    incident_id: str = Field(min_length=1)
    request_id: str = Field(min_length=1)
    decision_taken: DecisionTaken
    action_taken: str = Field(min_length=1, max_length=1024)
    confidence: int = Field(ge=1, le=5)
    replaced_manual_process: bool
    time_saved_minutes: int = Field(ge=0)
    comments: Optional[str] = Field(default=None, max_length=4096)
    # ── Memory extension fields (optional — existing payloads unaffected) ──────
    hypothesis_correct: Optional[bool] = None
    resolution_text: Optional[str] = Field(default=None, max_length=4096)
    memory_write_approved: bool = False


class DecisionImpact(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=_utc_now)
    incident_id: str
    request_id: str
    decision_taken: DecisionTaken
    action_taken: str
    confidence: int
    replaced_manual_process: bool
    time_saved_minutes: int
    comments: Optional[str] = None
    # ── Memory extension fields (optional — existing stored records unaffected) ─
    hypothesis_correct: Optional[bool] = None
    resolution_text: Optional[str] = None
    memory_write_approved: bool = False


# ── Incident memory models ────────────────────────────────────────────────────

class ValidatedIncident(BaseModel):
    """A human-validated incident resolution stored in long-term memory."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=_utc_now)

    # Traceability — links back to the originating Sentinel analysis
    incident_id: str = Field(min_length=1)
    request_id: str = Field(min_length=1)
    signature: str = Field(min_length=1, description="Deterministic content signature from Sentinel normalizer.")

    # Incident classification
    event_type: str = Field(min_length=1)
    source: str = Field(min_length=1)

    # Signal content — normalized form used for similarity matching
    message_normalized: str = Field(min_length=1, max_length=8192)
    tokens: list[str] = Field(default_factory=list, description="Normalized token set from the signal layer.")

    # Validated resolution
    resolution_text: str = Field(min_length=1, max_length=4096)
    hypothesis_validated: bool

    # Analyst provenance
    analyst_confidence: int = Field(ge=1, le=5)
    validated_by: Optional[str] = Field(default=None, max_length=256)
    validation_timestamp: str = Field(default_factory=_utc_now)

    # Lineage — points to the record this supersedes, if any
    supersedes: Optional[str] = Field(default=None, description="ID of the ValidatedIncident this record replaces.")


class ValidatedMatch(BaseModel):
    """A historical validated incident returned as a memory match during analysis."""

    incident_id: str
    similarity_score: float = Field(ge=0.0, le=1.0)
    event_type: str
    resolution_text: str
    validation_timestamp: str
    analyst_confidence: int = Field(ge=1, le=5)


# ── Analyst validation workflow models ────────────────────────────────────────

class ValidateResolutionRequest(DecisionImpactRequest):
    """Request body for POST /beta/validate-resolution.

    Extends DecisionImpactRequest with optional signal metadata needed to
    construct a ValidatedIncident. All new fields are optional so that
    existing DecisionImpactRequest-compatible payloads remain valid.
    """
    # Signal metadata — populated automatically in Phase 5 integration;
    # supplied manually by analysts during standalone Phase 2 validation.
    signature: Optional[str] = Field(default=None, min_length=1, description="Sentinel content signature.")
    event_type: Optional[str] = Field(default=None, min_length=1)
    source: Optional[str] = Field(default=None, min_length=1)
    message_normalized: Optional[str] = Field(default=None, min_length=1, max_length=8192)
    tokens: list[str] = Field(default_factory=list)
    validated_by: Optional[str] = Field(default=None, max_length=256)
    supersedes: Optional[str] = Field(default=None, description="ID of the ValidatedIncident this replaces.")


class ValidateResolutionResponse(BaseModel):
    """Response from POST /beta/validate-resolution."""

    decision_impact_id: str
    memory_record_created: bool
    memory_record_id: Optional[str] = None
    status: str
