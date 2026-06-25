"""
Decision Intelligence enrichment layer.

Pure Python, deterministic, zero external calls.
Derives the 7-pillar Decision Intelligence output from a SENTINEL RiskAssessment.
Input:  RiskAssessment  (from the Sentinel 4-layer pipeline)
Output: EnrichedAnalysis (the full Decision Intelligence envelope)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from raven.sentinel.pipeline.data_layer.schemas import RiskAssessment, Severity, SourceType


# ── Event type detection ──────────────────────────────────────────────────────
# Ordered by specificity — first match wins.

_EVENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("suspicious_activity", re.compile(
        # Security bypass / identity abuse signals — listed before auth_failure so
        # "MFA bypass" classifies as suspicious_activity, not authentication_failure.
        r"suspicious|anomaly|unusual|privilege.escal|injection|intrusion|exfil|lateral.mov"
        r"|backdoor|malware|ransomware|rootkit|bruteforce|brute.force"
        r"|bypass|mfa.bypass|impossible.travel|account.takeover|credential.stuf"
        r"|unknown.country|impossible.login",
        re.I,
    )),
    ("authentication_failure", re.compile(
        r"login.fail|auth.fail|auth.unavailable|password|invalid.cred|401|403|ldap|oauth|sso"
        r"|unauthorized|lockout|denied",
        re.I,
    )),
    ("deployment_related_failure", re.compile(
        # deploy (no word boundary) catches both "deploy" and "deployment".
        r"deploy|rollout|release|migration|restart|config.change|upgrade|post.deploy|after.deploy",
        re.I,
    )),
    ("service_unavailable", re.compile(
        r"\bdown\b|unavailable|unreachable|connection.refused|503|offline|not.respond|health.check.fail",
        re.I,
    )),
    ("error_rate_increase", re.compile(
        r"error.rate|5xx|\berrors.increas|\berror.spike|exception|traceback|crash|panic|oom|out.of.memory|fatal",
        re.I,
    )),
    ("latency_spike", re.compile(
        r"latency|slow|timeout|response.time|p99|degraded|delay|backpressure",
        re.I,
    )),
]


def _detect_event_type(message: str) -> str:
    for name, pattern in _EVENT_PATTERNS:
        if pattern.search(message):
            return name
    return "unknown"


# ── Monitored object detection ─────────────────────────────────────────────────

_OBJECT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("auth-service",         re.compile(r"auth[- ]?service|login.service|sso|ldap|oauth|iam|identity.provider", re.I)),
    ("payment-service",      re.compile(r"payment|billing|checkout|transaction|stripe|order.service", re.I)),
    ("database-cluster",     re.compile(r"\bdb\b|database|postgres|mysql|mongo|redis|elasticsearch|sql.server", re.I)),
    ("api-gateway",          re.compile(r"api.gateway|gateway|nginx|proxy|load.balancer|ingress", re.I)),
    ("user-api",             re.compile(r"user.api|user.service|account.service|profile.service|user.login", re.I)),
    ("notification-service", re.compile(r"notification|email.service|sms.service|push.notif|alert.service", re.I)),
    ("storage-service",      re.compile(r"\bs3\b|blob.storage|file.service|cdn|object.store", re.I)),
]

_SOURCE_OBJECT_FALLBACK: dict[SourceType, str] = {
    SourceType.IAM:            "identity-service",
    SourceType.NETWORK:        "network-layer",
    SourceType.INFRASTRUCTURE: "infrastructure",
    SourceType.AUDIT:          "audit-system",
    SourceType.APPLICATION:    "application-service",
}


def _detect_monitored_object(message: str, source: SourceType) -> str:
    for name, pattern in _OBJECT_PATTERNS:
        if pattern.search(message):
            return name
    return _SOURCE_OBJECT_FALLBACK.get(source, "unknown")


# ── Recurrence extraction from assessment ─────────────────────────────────────

_BURST_RE = re.compile(r"(\d+)x burst")
_OBSERVED_RE = re.compile(r"Observed (\d+)x")


def _recurrence_count(assessment: RiskAssessment) -> int:
    """Extract recurrence count from the assessment summary or recurrence factor detail."""
    m = _BURST_RE.search(assessment.summary)
    if m:
        return int(m.group(1))
    for factor in assessment.factors:
        if factor.name == "recurrence":
            m2 = _OBSERVED_RE.search(factor.detail)
            if m2:
                return int(m2.group(1))
    return 1


# ── Priority and recommended action ───────────────────────────────────────────

_PRIORITY: dict[Severity, str] = {
    Severity.LOW:      "low",
    Severity.MEDIUM:   "medium",
    Severity.HIGH:     "high",
    Severity.CRITICAL: "critical",
}


def _recommended_action(score: float) -> str:
    if score >= 0.85:
        return "escalate"
    if score >= 0.60:
        return "investigate"
    if score >= 0.35:
        return "monitor"
    if score >= 0.10:
        return "group_as_noise"
    return "ignore"


# ── Evidence extraction ────────────────────────────────────────────────────────

def _factor_to_evidence(name: str, weight: float, detail: str, source: SourceType) -> str | None:
    """Convert a single RiskFactor into a human-readable evidence string, or None to skip."""
    if name == "lexical":
        if weight >= 0.6:
            return f"High-severity threat keyword pattern detected (density score {weight:.0%})"
        if weight >= 0.3:
            return f"Threat keyword pattern detected in event message (density score {weight:.0%})"
        return None
    if name == "source":
        if weight >= 0.65:
            return f"Elevated-risk signal source '{source.value}' — high intrinsic risk prior ({weight:.0%})"
        if weight >= 0.50:
            return f"Moderate-risk signal source '{source.value}' (risk prior {weight:.0%})"
        return None
    if name == "recurrence":
        if weight > 0.0:
            # Extract count from detail: "Observed Nx in the active window."
            m = _OBSERVED_RE.search(detail)
            count_str = f"{m.group(1)}x" if m else "multiple times"
            return f"Pattern observed {count_str} in the active detection window — recurring incident"
        return None
    if name == "novelty":
        if weight > 0.0:
            return "Confirmed recurring threat pattern — prior occurrences exist in detection window"
        return None
    if name == "volatility":
        if weight >= 0.4:
            return f"High-cardinality event structure detected — burst noise pattern ({weight:.0%})"
        return None
    if name == "cluster_match":
        if weight >= 0.3:
            return f"Matched existing incident cluster with {weight:.0%} token similarity"
        return None
    return None


def _extract_evidence(assessment: RiskAssessment, source: SourceType) -> list[str]:
    lines: list[str] = []
    for factor in assessment.factors:
        line = _factor_to_evidence(factor.name, factor.weight, factor.detail, source)
        if line:
            lines.append(line)
    if not lines:
        lines.append(
            f"Risk score {assessment.risk_score:.2f} — severity classified as {assessment.severity.value}"
        )
    return lines[:5]


# ── Context derivation ─────────────────────────────────────────────────────────

_DEPLOYMENT_RE = re.compile(r"deploy|rollout|release|restart|migration|config.change|upgrade", re.I)

_DOWNSTREAM: dict[str, list[str]] = {
    "auth-service":    ["user-api", "api-gateway"],
    "database-cluster":["application-service", "user-api"],
    "api-gateway":     ["application-service"],
    "payment-service": ["checkout-api", "notification-service"],
    "user-api":        ["api-gateway"],
}

_TICKET_ESTIMATE: dict[Severity, int] = {
    Severity.LOW:      0,
    Severity.MEDIUM:   1,
    Severity.HIGH:     2,
    Severity.CRITICAL: 4,
}


def _derive_context(
    message: str,
    recurrence: int,
    monitored_object: str,
    assessment: RiskAssessment,
) -> dict[str, Any]:
    recent_deployment = bool(_DEPLOYMENT_RE.search(message))

    affected: list[str] = []
    if monitored_object != "unknown":
        affected.append(monitored_object)
    for svc in _DOWNSTREAM.get(monitored_object, []):
        if svc not in affected:
            affected.append(svc)

    return {
        "related_alerts": max(0, recurrence - 1),
        "related_tickets": _TICKET_ESTIMATE.get(assessment.severity, 0),
        "recent_deployment": recent_deployment,
        "affected_services": affected[:4],
    }


# ── Historical context ─────────────────────────────────────────────────────────

_KNOWN_RESOLUTIONS: dict[str, str] = {
    "authentication_failure":     "Restart authentication service; validate LDAP/OAuth connectivity and credentials",
    "service_unavailable":        "Verify pod/container health; check resource limits; roll back if post-deployment",
    "error_rate_increase":        "Identify dominant error class; correlate with deployments; check dependency health",
    "latency_spike":              "Profile slowest operations; check external dependency latency; review scaling",
    "deployment_related_failure": "Roll back to previous version; validate configuration and secrets",
    "suspicious_activity":        "Isolate affected system; capture forensic snapshot; escalate to security team",
    "unknown":                    "Collect logs and metrics; correlate signals; escalate if impact is confirmed",
}


def _historical_context(event_type: str, recurrence: int) -> dict[str, Any]:
    if recurrence <= 1:
        last_occurrence = "first occurrence"
    elif recurrence <= 3:
        last_occurrence = "within last hour"
    elif recurrence <= 10:
        last_occurrence = "within last 24 hours"
    else:
        last_occurrence = "within last 7 days"

    return {
        "similar_incidents_last_30d": min(recurrence * 3, 30),
        "last_occurrence": last_occurrence,
        "known_resolution": _KNOWN_RESOLUTIONS.get(event_type, _KNOWN_RESOLUTIONS["unknown"]),
    }


# ── Impact estimation ──────────────────────────────────────────────────────────

_USER_IMPACT: dict[Severity, int] = {
    Severity.LOW:      0,
    Severity.MEDIUM:   50,
    Severity.HIGH:     500,
    Severity.CRITICAL: 2000,
}

_CRITICALITY: dict[Severity, str] = {
    Severity.LOW:      "low",
    Severity.MEDIUM:   "medium",
    Severity.HIGH:     "high",
    Severity.CRITICAL: "critical",
}


def _estimate_impact(assessment: RiskAssessment, context: dict[str, Any]) -> dict[str, Any]:
    affected_count = len(context.get("affected_services", []))
    return {
        "affected_users": _USER_IMPACT.get(assessment.severity, 0),
        "affected_services": affected_count if assessment.severity != Severity.LOW else 0,
        "business_criticality": _CRITICALITY.get(assessment.severity, "low"),
    }


# ── Hypothesis generation ──────────────────────────────────────────────────────

_HYPOTHESES: dict[str, dict[str, str]] = {
    "authentication_failure": {
        "deployment":  "Authentication service failure likely caused by a recent deployment change",
        "recurrence":  "Ongoing authentication degradation — possible LDAP or OAuth connectivity issue",
        "default":     "Possible authentication service failure or credential-based attack in progress",
    },
    "service_unavailable": {
        "deployment":  "Service outage likely triggered by recent deployment or configuration change",
        "recurrence":  "Persistent service unavailability — possible resource exhaustion or cascading failure",
        "default":     "Service may be down due to infrastructure failure or resource saturation",
    },
    "error_rate_increase": {
        "deployment":  "Error rate spike likely introduced by a recent deployment",
        "recurrence":  "Sustained error rate increase — possible dependency failure or data corruption",
        "default":     "Anomalous error rate increase — investigate recent changes and dependency health",
    },
    "latency_spike": {
        "deployment":  "Latency regression likely introduced by recent deployment or infrastructure change",
        "recurrence":  "Recurring latency spikes — possible resource saturation or slow external dependency",
        "default":     "Latency increase detected — investigate database queries, external calls, or resource limits",
    },
    "deployment_related_failure": {
        "deployment":  "Failure directly correlated with recent deployment — rollback candidate",
        "recurrence":  "Repeated deployment failures — investigate CI/CD pipeline and configuration management",
        "default":     "Post-deployment issue detected — validate configuration, secrets, and service health",
    },
    "suspicious_activity": {
        "deployment":  "Suspicious activity coinciding with deployment — validate access controls and change log",
        "recurrence":  "Repeated suspicious pattern — possible persistent threat actor or misconfigured security policy",
        "default":     "Suspicious operational pattern detected — investigate for potential security incident",
    },
    "unknown": {
        "default":     "Anomalous operational signal — investigate service logs and recent infrastructure changes",
    },
}


def _generate_hypothesis(event_type: str, context: dict[str, Any], recurrence: int) -> str:
    variants = _HYPOTHESES.get(event_type, _HYPOTHESES["unknown"])
    if context.get("recent_deployment"):
        return variants.get("deployment", variants["default"])
    if recurrence > 3:
        return variants.get("recurrence", variants["default"])
    return variants["default"]


# ── Recommended steps ──────────────────────────────────────────────────────────

_STEPS: dict[str, list[str]] = {
    "authentication_failure": [
        "Review authentication service logs for error patterns and failure timestamps",
        "Check LDAP, OAuth, and SSO service health and network connectivity",
        "Verify recent deployments for authentication-related configuration changes",
        "Monitor failed login rate over the next 15 minutes for trend direction",
        "Validate secrets and certificates have not expired or been rotated incorrectly",
    ],
    "service_unavailable": [
        "Verify pod, container, or VM health in the affected environment",
        "Check resource utilization: CPU, memory, disk, and network saturation",
        "Inspect load balancer health checks and upstream service availability",
        "Review recent deployments and configuration changes in the 2-hour window",
        "Initiate rollback procedure if failure correlates with a recent deployment",
    ],
    "error_rate_increase": [
        "Identify the dominant error class and first-occurrence timestamp in service logs",
        "Correlate error spike with recent deployments or configuration changes",
        "Check health of upstream and downstream service dependencies",
        "Review database query performance and connection pool saturation",
        "Temporarily increase log verbosity to capture full error context",
    ],
    "latency_spike": [
        "Profile the slowest operations using distributed tracing",
        "Check external dependency latency: databases, caches, and third-party APIs",
        "Review auto-scaling policies and current resource headroom",
        "Inspect recent deployments for performance-impacting code or configuration changes",
        "Check for resource saturation: CPU throttling, memory pressure, and I/O wait",
    ],
    "deployment_related_failure": [
        "Compare service health metrics before and after the deployment timestamp",
        "Review the deployment changelog for potentially impacting changes",
        "Validate environment configuration and secrets are correctly applied",
        "Initiate rollback if impact is confirmed and root cause is unclear",
        "Run smoke tests against the deployed version to identify the failing surface",
    ],
    "suspicious_activity": [
        "Isolate the affected system from lateral movement paths immediately",
        "Capture a forensic snapshot of current process state and network connections",
        "Review access logs for unusual authentication or authorization patterns",
        "Escalate to the security team with full event context and timeline",
        "Preserve evidence integrity before any remediation actions are taken",
    ],
    "unknown": [
        "Collect recent logs and metrics from the affected service",
        "Correlate the signal with other operational alerts in the same time window",
        "Check infrastructure health for related anomalies",
        "Review recent deployments, configuration changes, and dependency updates",
        "Escalate to the on-call engineer if the signal persists beyond 5 minutes",
    ],
}

_CRITICAL_PREAMBLE: list[str] = [
    "Page the on-call engineer immediately via incident management system",
    "Open a Sev-1 incident ticket and begin timeline documentation now",
]


def _recommended_steps(event_type: str, priority: str) -> list[str]:
    base = _STEPS.get(event_type, _STEPS["unknown"])[:4]
    if priority == "critical":
        return _CRITICAL_PREAMBLE + base
    return base


# ── Authentication incident escalation rules ───────────────────────────────────
# Applied AFTER initial derivation. Operates only on enrichment-layer values;
# SENTINEL output (risk_score, severity) is never modified.

_AUTH_LDAP_RE:    re.Pattern[str] = re.compile(r"ldap[._\-]?timeout|ldap[._\-]?error|ldap[._\-]?fail", re.I)
_AUTH_VOLUME_RE:  re.Pattern[str] = re.compile(r"\d+\s+(?:login|auth(?:entication)?)\s+fail", re.I)
_AUTH_UNAVAIL_RE: re.Pattern[str] = re.compile(r"unavailable|service[.\s_]?down|unreachable|cannot[.\s]connect", re.I)

# Ordered rank tables — enforce minimum floors without downgrading a higher existing value.
_PRIORITY_RANK:    dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_ACTION_RANK:      dict[str, int] = {"ignore": 0, "group_as_noise": 1, "monitor": 2, "investigate": 3, "escalate": 4}
_CRITICALITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _floor(current: str, minimum: str, rank: dict[str, int]) -> str:
    """Return `current` if it already meets or exceeds `minimum`; otherwise `minimum`."""
    return current if rank.get(current, 0) >= rank.get(minimum, 0) else minimum


def _auth_escalation(
    message: str,
    event_type: str,
    priority: str,
    action: str,
    confidence: int,
    evidence: list[str],
    impact: dict[str, Any],
    affected_services: list[str],
) -> tuple[str, str, int, list[str], dict[str, Any]]:
    """Deterministic escalation rules for authentication_failure incidents.

    Returns (priority, action, confidence, evidence, impact) — same types, potentially upgraded.
    Rules are additive: each independently raises the floor without overriding a higher value.
    """
    if event_type != "authentication_failure":
        return priority, action, confidence, evidence, impact

    has_ldap    = bool(_AUTH_LDAP_RE.search(message))
    has_volume  = bool(_AUTH_VOLUME_RE.search(message))
    has_unavail = bool(_AUTH_UNAVAIL_RE.search(message))
    has_auth_svc = "auth-service" in affected_services

    # Rule 1: volume (login failure count) + service unavailable → floor at high/investigate.
    # Rationale: multiple login failures against an unavailable auth service is an operational
    # incident with broad user impact, regardless of the raw SENTINEL lexical score.
    if has_volume and has_unavail:
        priority = _floor(priority, "high",        _PRIORITY_RANK)
        action   = _floor(action,   "investigate",  _ACTION_RANK)

    # Rule 2: LDAP_TIMEOUT explicitly present → confidence floor at 70, surface explicit evidence.
    # Rationale: LDAP timeout is a concrete, named failure mode — not a probabilistic signal —
    # and warrants high confidence independent of keyword-density scoring.
    if has_ldap:
        confidence = max(confidence, 70)
        ldap_line = "LDAP_TIMEOUT detected — identity provider connectivity failure confirmed"
        if ldap_line not in evidence:
            evidence = [ldap_line, *evidence]

    # Rule 3: auth-service is in scope → business criticality at least high.
    # Rationale: auth-service outages affect every authenticated user and service.
    if has_auth_svc and _CRITICALITY_RANK.get(impact.get("business_criticality", "low"), 0) < _CRITICALITY_RANK["high"]:
        impact = {**impact, "business_criticality": "high"}

    return priority, action, confidence, evidence, impact


# ── Public API ─────────────────────────────────────────────────────────────────

@dataclass(slots=True)
class EnrichedAnalysis:
    analysis_scope: str
    event_type: str
    monitored_object: str
    priority: str
    confidence: int
    recommended_action: str
    evidence: list[str]
    context: dict[str, Any]
    historical_context: dict[str, Any]
    impact: dict[str, Any]
    hypothesis: str
    recommended_steps: list[str]
    feedback: dict[str, Any]


_FEEDBACK_ENVELOPE: dict[str, Any] = {
    "allowed": True,
    "feedback_types": ["helpful", "not_helpful", "correct", "incorrect"],
}


def enrich(assessment: RiskAssessment, message: str, source: SourceType) -> EnrichedAnalysis:
    """Derive the 7-pillar Decision Intelligence output from a SENTINEL assessment.

    Deterministic and evidence-based — identical inputs always produce identical output.
    """
    event_type       = _detect_event_type(message)
    monitored_object = _detect_monitored_object(message, source)
    priority         = _PRIORITY.get(assessment.severity, "low")
    confidence       = round(assessment.risk_score * 100)
    recommended_action = _recommended_action(assessment.risk_score)
    recurrence       = _recurrence_count(assessment)

    evidence = _extract_evidence(assessment, source)
    context  = _derive_context(message, recurrence, monitored_object, assessment)
    historical = _historical_context(event_type, recurrence)
    impact   = _estimate_impact(assessment, context)

    # Apply deterministic escalation rules — enrichment layer only; SENTINEL unchanged.
    priority, recommended_action, confidence, evidence, impact = _auth_escalation(
        message=message,
        event_type=event_type,
        priority=priority,
        action=recommended_action,
        confidence=confidence,
        evidence=evidence,
        impact=impact,
        affected_services=context.get("affected_services", []),
    )

    hypothesis = _generate_hypothesis(event_type, context, recurrence)
    # Re-derive steps after escalation so CRITICAL preamble fires on escalated priority.
    steps = _recommended_steps(event_type, priority)

    return EnrichedAnalysis(
        analysis_scope="operational_incident",
        event_type=event_type,
        monitored_object=monitored_object,
        priority=priority,
        confidence=confidence,
        recommended_action=recommended_action,
        evidence=evidence,
        context=context,
        historical_context=historical,
        impact=impact,
        hypothesis=hypothesis,
        recommended_steps=steps,
        feedback=_FEEDBACK_ENVELOPE,
    )
