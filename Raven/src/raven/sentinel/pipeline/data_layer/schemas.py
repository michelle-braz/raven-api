"""
Layer 1 — Data Layer (Ingestion)
================================
Pure schema definitions and contracts. This module is the *only* place
where the wire format is described. It contains **no business logic** —
its sole responsibility is type enforcement, input safety, and providing
the typed contracts that every downstream layer consumes.

Design notes
------------
* Pydantic v2, strict-by-default (`extra="forbid"`, `frozen`).
* Severity / Source / Action enums are shared vocabulary across all layers,
  so they live here at the bottom of the dependency graph.
* Inbound models reject unknown fields to prevent schema drift and
  payload-smuggling. Outbound models are explicit, versioned contracts.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

# ── Shared vocabulary ────────────────────────────────────────────────────────


class Severity(StrEnum):
    """Normalized, ordered severity classification."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Monotonic ordering for comparisons and threshold checks."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class SourceType(StrEnum):
    """Origin of an ingested signal — drives source-aware risk weighting."""

    APPLICATION = "application"
    INFRASTRUCTURE = "infrastructure"
    NETWORK = "network"
    IAM = "iam"
    AUDIT = "audit"
    UNKNOWN = "unknown"


# ── Schema-safety primitives ─────────────────────────────────────────────────

RawMessage = Annotated[str, Field(min_length=1, max_length=8192)]
Metadata = Annotated[dict[str, str], Field(default_factory=dict, max_length=32)]


class _StrictModel(BaseModel):
    """Base for all inbound contracts: reject unknowns, validate on assign."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
        frozen=True,
    )


# ── Ingestion contracts (inbound) ────────────────────────────────────────────


class RawEvent(_StrictModel):
    """A single raw signal as accepted at the edge."""

    message: RawMessage
    source: SourceType = SourceType.UNKNOWN
    host: str | None = Field(default=None, max_length=255)
    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Producer-side event time; defaults to ingestion time.",
    )
    labels: Metadata

    @field_validator("observed_at")
    @classmethod
    def _normalize_tz(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class IngestionBatch(_StrictModel):
    """A bounded batch of raw events — the primary ingestion endpoint payload."""

    events: Annotated[list[RawEvent], Field(min_length=1, max_length=500)]


# ── Intelligence contracts (outbound) ────────────────────────────────────────


class RiskFactor(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    weight: float = Field(ge=0.0, le=1.0)
    detail: str


class RiskAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)

    signature: str = Field(description="Deterministic content signature (dedupe key).")
    incident_id: str = Field(description="Stable cluster identifier.")
    risk_score: float = Field(ge=0.0, le=1.0)
    severity: Severity
    is_anomaly: bool
    factors: tuple[RiskFactor, ...] = ()
    summary: str
    assessed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IngestionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    accepted: int
    assessments: tuple[RiskAssessment, ...]
    severity_breakdown: dict[Severity, int]
    actions_dispatched: int


# ── Action contracts ─────────────────────────────────────────────────────────


class ActionStatus(StrEnum):
    DISPATCHED = "dispatched"
    SKIPPED = "skipped"
    FAILED = "failed"


class ActionOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    channel: str
    status: ActionStatus
    detail: str | None = None


def to_envelope(assessment: RiskAssessment, event: RawEvent) -> dict[str, Any]:
    """Serialize assessment + triggering event into a transport-neutral dict."""
    return {
        "incident_id": assessment.incident_id,
        "signature": assessment.signature,
        "risk_score": round(assessment.risk_score, 4),
        "severity": assessment.severity.value,
        "summary": assessment.summary,
        "source": event.source.value,
        "host": event.host,
        "message": event.message,
        "observed_at": event.observed_at.isoformat(),
        "assessed_at": assessment.assessed_at.isoformat(),
        "factors": [
            {"name": f.name, "weight": round(f.weight, 4), "detail": f.detail}
            for f in assessment.factors
        ],
    }
