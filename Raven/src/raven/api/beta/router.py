from __future__ import annotations

from fastapi import APIRouter

from .models import (
    DecisionImpact,
    DecisionImpactRequest,
    ValidatedIncident,
    ValidateResolutionRequest,
    ValidateResolutionResponse,
)
from .store import (
    append_impact,
    append_validated_incident,
    count_analyze_calls,
    load_impacts,
)

router = APIRouter(prefix="/beta", tags=["beta"])

_RECOMMENDATIONS: dict[str, str] = {
    "NO_EVIDENCE":      "Find more testers",
    "EARLY_SIGNAL":     "Collect more feedback",
    "VALIDATING":       "Refine product using feedback",
    "REAL_WORLD_VALUE": "Prepare paid beta",
}

# Fields that map from the request payload onto DecisionImpact (excludes
# auto-generated id/timestamp and signal-metadata fields added in
# ValidateResolutionRequest that DecisionImpact does not own).
_IMPACT_FIELDS: frozenset[str] = frozenset(DecisionImpact.model_fields) - {"id", "timestamp"}


def _validation_status(n: int) -> str:
    if n >= 20:
        return "REAL_WORLD_VALUE"
    if n >= 5:
        return "VALIDATING"
    if n >= 1:
        return "EARLY_SIGNAL"
    return "NO_EVIDENCE"


# ── Existing endpoints (unchanged) ────────────────────────────────────────────

@router.post(
    "/decision-impact",
    status_code=201,
    summary="Record that RAVEN influenced a real decision",
    description=(
        "Submit after acting on a RAVEN recommendation. "
        "Use the `incident_id` and `request_id` from the `/v1/analyze` response."
    ),
)
async def submit_decision_impact(payload: DecisionImpactRequest) -> dict[str, str]:
    impact = DecisionImpact(**payload.model_dump())
    append_impact(impact)
    return {"id": impact.id, "status": "recorded"}


@router.get(
    "/impact-summary",
    summary="Aggregated decision impact metrics",
)
async def impact_summary() -> dict:
    impacts = load_impacts()
    calls = count_analyze_calls()
    n = len(impacts)

    decision_breakdown: dict[str, int] = {}
    for imp in impacts:
        decision_breakdown[imp.decision_taken] = decision_breakdown.get(imp.decision_taken, 0) + 1

    replaced = sum(1 for i in impacts if i.replaced_manual_process)
    avg_time = round(sum(i.time_saved_minutes for i in impacts) / n, 1) if n else 0
    avg_conf = round(sum(i.confidence for i in impacts) / n, 2) if n else 0

    action_counts: dict[str, int] = {}
    for imp in impacts:
        action_counts[imp.action_taken] = action_counts.get(imp.action_taken, 0) + 1
    top_actions = sorted(action_counts, key=lambda k: action_counts[k], reverse=True)[:5]

    return {
        "total_analyze_calls": calls,
        "total_decision_reports": n,
        "decision_influence_rate": round(n / calls, 4) if calls else 0.0,
        "manual_process_replacement_rate": round(replaced / n, 4) if n else 0.0,
        "average_time_saved_minutes": avg_time,
        "average_confidence": avg_conf,
        "decision_breakdown": decision_breakdown,
        "top_actions": top_actions,
    }


@router.get(
    "/business-proof",
    summary="Business validation report — is RAVEN creating real value?",
)
async def business_proof() -> dict:
    impacts = load_impacts()
    calls = count_analyze_calls()
    n = len(impacts)
    status = _validation_status(n)

    replaced = sum(1 for i in impacts if i.replaced_manual_process)
    total_minutes = sum(i.time_saved_minutes for i in impacts)
    avg_conf = round(sum(i.confidence for i in impacts) / n, 2) if n else 0.0

    return {
        "validation_status": status,
        "total_events": calls,
        "total_decisions_influenced": n,
        "estimated_total_minutes_saved": total_minutes,
        "manual_processes_replaced": replaced,
        "average_confidence": avg_conf,
        "recommendation": _RECOMMENDATIONS[status],
    }


# ── Analyst validation endpoint ───────────────────────────────────────────────

@router.post(
    "/validate-resolution",
    status_code=201,
    summary="Submit analyst validation and optionally store as incident memory",
    description=(
        "Records an analyst's validation of a RAVEN recommendation. "
        "Always writes a DecisionImpact record. "
        "When `memory_write_approved=true` and `resolution_text` is provided, "
        "also creates a ValidatedIncident in long-term memory (`validated_incidents.jsonl`)."
    ),
)
async def validate_resolution(
    payload: ValidateResolutionRequest,
) -> ValidateResolutionResponse:
    # Always record the decision impact — memory approval does not affect this.
    impact = DecisionImpact(
        **{k: v for k, v in payload.model_dump().items() if k in _IMPACT_FIELDS}
    )
    append_impact(impact)

    memory_record_id: str | None = None
    memory_record_created = False

    if payload.memory_write_approved and payload.resolution_text:
        validated = ValidatedIncident(
            incident_id=payload.incident_id,
            request_id=payload.request_id,
            # Signal metadata — analyst-supplied in Phase 2; auto-populated in Phase 5.
            signature=payload.signature or "unknown",
            event_type=payload.event_type or "unknown",
            source=payload.source or "unknown",
            message_normalized=payload.message_normalized or payload.resolution_text,
            tokens=payload.tokens,
            resolution_text=payload.resolution_text,
            hypothesis_validated=payload.hypothesis_correct or False,
            analyst_confidence=payload.confidence,
            validated_by=payload.validated_by,
            supersedes=payload.supersedes,
        )
        append_validated_incident(validated)
        memory_record_id = validated.id
        memory_record_created = True

    return ValidateResolutionResponse(
        decision_impact_id=impact.id,
        memory_record_created=memory_record_created,
        memory_record_id=memory_record_id,
        status="recorded",
    )
