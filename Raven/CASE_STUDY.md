# RAVEN in Practice — A Real Incident Scenario

## Scenario: Authentication service degradation during peak traffic

**Context:** 14:32 UTC. Payment processing window. An SRE receives a PagerDuty alert:
`auth-service: error rate 12% (threshold: 5%)`

Without RAVEN, this means: open Datadog, cross-reference logs, check recent deploys, decide whether to escalate or wait. Estimated time to first decision: 8–15 minutes.

**With RAVEN**, the alert fires into the API immediately.

---

## The API call

```bash
curl -X POST https://api.raven.dev/v1/analyze \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "auth-service error rate 12%, 847 failed logins in 60s, MFA validation service unavailable, downstream payment-service reporting auth dependency timeout",
    "source": "iam"
  }'
```

---

## What RAVEN returns (actual response)

```json
{
  "request_id": "7f3a1c2d-9e4b-4a8f-b2c1-5d6e7f8a9b0c",
  "incident_id": "inc_a3f2c1",
  "event_type": "authentication_failure",
  "monitored_object": "auth-service",
  "risk_score": 0.8471,
  "severity": "HIGH",
  "priority": "critical",
  "confidence": 91,
  "recommended_action": "escalate",
  "evidence": [
    "Authentication service in unavailable state",
    "MFA validation service unreachable — bypass risk elevated",
    "IAM source prior: elevated risk baseline",
    "847 failed logins in 60 seconds — burst pattern detected",
    "Downstream payment-service reporting auth timeout — blast radius confirmed"
  ],
  "hypothesis": "Authentication service is degraded, likely due to MFA validation service failure. High login failure volume suggests either a dependency cascade or an active attack exploiting the degraded MFA path. Payment-service dependency timeout confirms customer-facing impact.",
  "recommended_steps": [
    "Check MFA validation service health — it is the most likely root cause",
    "Confirm whether any logins succeeded without MFA during the degradation window",
    "Determine if this is correlated with a recent deployment to auth-service or MFA service",
    "If MFA service is down: assess whether to fail-open (allow logins without MFA) or fail-closed (block logins)",
    "Notify payment team — auth dependency timeout is causing customer-facing failures",
    "Page security team if any successful logins occurred without MFA validation"
  ],
  "impact": {
    "affected_users": "all users attempting to authenticate",
    "affected_services": ["auth-service", "mfa-validation-service", "payment-service"],
    "business_criticality": "critical"
  },
  "context": {
    "recent_deployment": false,
    "related_alerts": ["auth_service_error_rate", "mfa_service_unavailable", "payment_auth_timeout"]
  },
  "historical_context": {
    "similar_incidents_last_30d": 1,
    "last_occurrence": "2026-05-18T09:14:00Z",
    "known_resolution": "MFA service pod OOMKilled — restarted by infra team"
  }
}
```

---

## What happened

RAVEN identified three things a dashboard cannot:

**1. The blast radius.** The alert said "auth-service error rate." RAVEN identified that the actual scope includes `auth-service`, `mfa-validation-service`, and `payment-service` — three systems, not one.

**2. The probable root cause.** The MFA validation service being unreachable is a more specific and actionable signal than the aggregate error rate. RAVEN surfaced it as the likely root cause from the compound signal.

**3. Historical context.** One month earlier, the same pattern occurred. MFA service OOMKilled. An SRE who wasn't on-call that day would have no way to know this without searching incident history manually.

---

## What the engineer did next

Checked the MFA validation service pod. `kubectl get pods -n auth` showed it in `OOMKilled` state. Restarted. Auth error rate normalized within 90 seconds. Incident duration: 4 minutes from first RAVEN response to resolution.

No Datadog. No log grep. No incident bridge.

---

## The tradeoff RAVEN is making

RAVEN does not have access to your Datadog metrics, your Kubernetes state, or your deployment history. It infers structure from the signal text and source type. The historical context comes from RAVEN's own incident memory, not your ITSM system.

This means RAVEN is most accurate when incident signals are descriptive (log lines, alert messages with context) rather than bare metric names. It is not a replacement for observability tooling — it is the decision layer on top of it.

---

## Who this is for

This scenario maps to a team where:
- On-call engineers are skilled but context-switching frequently
- Incidents require correlating 3–5 signals before a decision can be made
- The current bottleneck is time-to-first-decision, not time-to-fix

If your team's on-call runbook says "open Datadog, check logs, check recent deploys" before any action is taken — RAVEN compresses that step.

**Contact:** `contact@ravenrisk.dev` to discuss a pilot.
