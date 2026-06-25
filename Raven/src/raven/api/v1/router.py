"""
RAVEN API — v1 Router
====================
Stable, versioned API surface for the SaaS product layer.
All endpoints are mounted under the /v1 prefix by main.py.

Design constraints:
  - No internal engine objects leak into responses.
  - Scoring is deterministic: identical inputs always produce identical outputs
    modulo window state (recurrence detection is intentionally stateful).
  - Structured logging fires at INFO level; suppress with LOG_LEVEL=WARNING.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from raven.api.auth import check_ip_rate_limit, require_api_key
from raven.api.beta.store import record_analyze_call
from raven.api.v1.enrichment import EnrichedAnalysis, enrich
from raven.sentinel.observability import BufferFull
from raven.sentinel.pipeline.app import IngestionPipeline
from raven.sentinel.pipeline.data_layer.schemas import RawEvent, SourceType

_log = logging.getLogger("nova.api.v1")

router = APIRouter(prefix="/v1", tags=["v1"])


# ── Request / response schemas ────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    message: str = Field(
        min_length=1,
        max_length=8192,
        description="Raw event message to assess.",
    )
    source: SourceType = Field(
        default=SourceType.UNKNOWN,
        description=(
            "Signal origin — drives source-aware risk weighting. "
            "One of: application, infrastructure, network, iam, audit, unknown."
        ),
    )


class AnalyzeResponse(BaseModel):
    # ── Traceability ──────────────────────────────────────────────────────────
    request_id: str = Field(description="Unique identifier for this request.")
    incident_id: str = Field(description="Stable cluster identifier — identical for recurrences of the same pattern.")

    # ── Analysis scope — eliminates 'risk score for what?' ambiguity ──────────
    analysis_scope: str = Field(description="Always 'operational_incident'.")
    event_type: str = Field(description="Detected event category: authentication_failure | latency_spike | error_rate_increase | deployment_related_failure | service_unavailable | suspicious_activity | unknown.")
    monitored_object: str = Field(description="Inferred service or system being analyzed.")

    # ── Input echo ────────────────────────────────────────────────────────────
    message: str = Field(description="The assessed event message, echoed back.")
    source: str = Field(description="Signal origin used during scoring.")

    # ── Core SENTINEL scoring (raw engine output) ─────────────────────────────
    risk_score: float = Field(description="Normalized risk score in [0.0, 1.0] from the Sentinel pipeline.")
    severity: str = Field(description="Discretized severity band: LOW | MEDIUM | HIGH | CRITICAL.")

    # ── Pillar 1 — Prioritization ─────────────────────────────────────────────
    priority: str = Field(description="Investigation priority: low | medium | high | critical.")
    confidence: int = Field(description="Confidence in the assessment as an integer percentage (0–100).")

    # ── Recommended action (replaces allow/review/block) ──────────────────────
    recommended_action: str = Field(description="Recommended operational action: escalate | investigate | monitor | group_as_noise | ignore.")

    # ── Pillar 2 — Evidence ───────────────────────────────────────────────────
    evidence: list[str] = Field(description="Evidence supporting the recommendation — derived from SENTINEL scoring factors.")

    # ── Pillar 3 — Context ────────────────────────────────────────────────────
    context: dict[str, Any] = Field(description="Operational context: related alerts, recent deployment flag, affected services.")

    # ── Pillar 6 — Historical context ─────────────────────────────────────────
    historical_context: dict[str, Any] = Field(description="Historical signal: similar incidents in last 30d, last occurrence, known resolution.")

    # ── Pillar 7 — Impact ─────────────────────────────────────────────────────
    impact: dict[str, Any] = Field(description="Estimated impact: affected users, affected services, business criticality.")

    # ── Pillar 4 — Hypothesis ─────────────────────────────────────────────────
    hypothesis: str = Field(description="Evidence-based investigation hypothesis.")

    # ── Recommended steps ─────────────────────────────────────────────────────
    recommended_steps: list[str] = Field(description="Ordered investigation steps tailored to the detected event type and priority.")

    # ── Pillar 5 — Controlled feedback ───────────────────────────────────────
    feedback: dict[str, Any] = Field(description="Feedback configuration — allowed types: helpful, not_helpful, correct, incorrect.")

    # ── Explainability (raw SENTINEL factor breakdown) ────────────────────────
    explain: dict[str, Any] | None = Field(
        default=None,
        description="Raw SENTINEL factor breakdown. Null when no significant threat signals fired.",
    )

    # ── Account metadata ──────────────────────────────────────────────────────
    tier: str = Field(description="API tier of the authenticating key.")
    impact_feedback_endpoint: str = Field(description="Endpoint to report whether this recommendation influenced a real decision.")


# ── Dependencies ──────────────────────────────────────────────────────────────

def _ip_guard(request: Request) -> None:
    """Enforce 30 req/min per source IP before any scoring work begins."""
    ip = request.client.host if request.client else "unknown"
    check_ip_rate_limit(ip)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Decision Intelligence analysis (Sentinel pipeline)",
    description=(
        "Full Sentinel pipeline: normalize → score → cluster → act, followed by "
        "the **Decision Intelligence** enrichment layer.\n\n"
        "Returns a complete investigation recommendation including:\n"
        "- **Priority** and **confidence** (what to investigate first)\n"
        "- **Evidence** (why this recommendation was produced)\n"
        "- **Context** (related alerts, recent deployment, affected services)\n"
        "- **Hypothesis** (evidence-based root cause candidate)\n"
        "- **Recommended steps** (ordered investigation playbook)\n"
        "- **Historical context** (similar incidents, known resolutions)\n"
        "- **Impact** (affected users, services, business criticality)\n\n"
        "**Recommended actions:** `escalate` · `investigate` · `monitor` · `group_as_noise` · `ignore`\n\n"
        "**Action thresholds** (deterministic, no randomness):\n"
        "- `risk_score ≥ 0.85` → `escalate`\n"
        "- `risk_score ≥ 0.60` → `investigate`\n"
        "- `risk_score ≥ 0.35` → `monitor`\n"
        "- `risk_score ≥ 0.10` → `group_as_noise`\n"
        "- `risk_score < 0.10` → `ignore`\n\n"
        "**Severity bands:** LOW · MEDIUM · HIGH · CRITICAL\n\n"
        "**Scoring factors** (weights sum to 1.0):\n"
        "- `lexical` — threat keyword density (0.45)\n"
        "- `recurrence` — repeated patterns score higher (0.20)\n"
        "- `source` — signal origin risk prior (0.15)\n"
        "- `novelty` — confirmed recurring threats score higher (0.10)\n"
        "- `volatility` — burst pattern detection (0.10)\n\n"
        "Returns HTTP 429 when the ingestion buffer is full. "
        "For a simple integer score (0–100) without pipeline overhead, use `POST /evaluate`."
    ),
    openapi_extra={
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "auth_failure": {
                            "summary": "Authentication failure — expect investigate/HIGH",
                            "value": {
                                "message": "unauthorized login failure detected — LDAP timeout on auth-service",
                                "source": "iam",
                            },
                        },
                        "suspicious_activity": {
                            "summary": "Privilege escalation — expect escalate/CRITICAL",
                            "value": {
                                "message": "unauthorized privilege escalation detected on host db-01",
                                "source": "iam",
                            },
                        },
                        "network_anomaly": {
                            "summary": "Unusual outbound traffic — expect investigate/HIGH",
                            "value": {
                                "message": "unusual outbound traffic detected to unknown destination",
                                "source": "network",
                            },
                        },
                        "benign": {
                            "summary": "Low-risk login — expect ignore/LOW",
                            "value": {
                                "message": "user login successful from known device",
                                "source": "application",
                            },
                        },
                    }
                }
            }
        }
    },
)
async def analyze(
    body: AnalyzeRequest,
    request: Request,
    auth: dict[str, str] = Depends(require_api_key),
    _ip: None = Depends(_ip_guard),
) -> AnalyzeResponse:
    pipeline: IngestionPipeline = request.app.state.pipeline

    try:
        assessment, _ = await pipeline.process_event(
            RawEvent(message=body.message, source=body.source)
        )
    except BufferFull:
        raise HTTPException(status_code=429, detail="Pipeline buffer full. Retry later.")

    request_id = str(uuid.uuid4())

    explain: dict[str, Any] | None = None
    if assessment.factors:
        explain = {
            "factors": [
                {"name": f.name, "weight": round(f.weight, 4), "detail": f.detail}
                for f in assessment.factors
            ]
        }

    enriched: EnrichedAnalysis = enrich(assessment, body.message, body.source)

    record_analyze_call(assessment.incident_id, request_id)

    _log.info(
        "endpoint=/v1/analyze ts=%s risk_score=%.4f severity=%s action=%s event_type=%s incident_id=%s tier=%s",
        datetime.now(timezone.utc).isoformat(),
        assessment.risk_score,
        assessment.severity.value,
        enriched.recommended_action,
        enriched.event_type,
        assessment.incident_id,
        auth["tier"],
    )

    return AnalyzeResponse(
        request_id=request_id,
        incident_id=assessment.incident_id,
        analysis_scope=enriched.analysis_scope,
        event_type=enriched.event_type,
        monitored_object=enriched.monitored_object,
        message=body.message,
        source=body.source.value,
        risk_score=round(assessment.risk_score, 4),
        severity=assessment.severity.value,
        priority=enriched.priority,
        confidence=enriched.confidence,
        recommended_action=enriched.recommended_action,
        evidence=enriched.evidence,
        context=enriched.context,
        historical_context=enriched.historical_context,
        impact=enriched.impact,
        hypothesis=enriched.hypothesis,
        recommended_steps=enriched.recommended_steps,
        feedback=enriched.feedback,
        explain=explain,
        tier=auth["tier"],
        impact_feedback_endpoint="/beta/decision-impact",
    )
