# RAVEN — Incident Intelligence

**Turn operational signals into investigation decisions.**

RAVEN is a decision intelligence API for engineering and operations teams. You send it an incident signal — a log line, an alert message, an anomaly description — and it returns a structured investigation recommendation: what to do, why, where to start, and what it means for your users.

---

## The problem

On-call engineers receive alerts. They do not receive answers.

A single page can arrive as 30 separate signals — CPU spike, 5xx surge, auth failures, latency increase — each with no context, no history, and no recommended action. The engineer's job is to manually correlate these into a decision while the clock is running.

RAVEN compresses that loop. It scores each signal, clusters related events into incidents, detects recurrence, identifies affected services, and returns a single recommended action with an ordered investigation playbook.

---

## What RAVEN returns

Every call to `/v1/analyze` returns a **7-pillar decision package**:

| Pillar | Field | Description |
|---|---|---|
| **Priority** | `priority`, `confidence` | What to investigate first, with confidence % |
| **Evidence** | `evidence` | Why this recommendation was produced |
| **Context** | `context` | Related alerts, deployment status, affected services |
| **Hypothesis** | `hypothesis` | Evidence-based root cause candidate |
| **Steps** | `recommended_steps` | Ordered investigation playbook |
| **History** | `historical_context` | Similar incidents in last 30d, known resolutions |
| **Impact** | `impact` | Affected users, services, business criticality |

Plus: `risk_score` (0.0–1.0), `severity` (LOW/MEDIUM/HIGH/CRITICAL), `recommended_action`, `event_type`, `incident_id` for clustering.

---

## Quick start

**1. Get a key**

RAVEN is currently in pilot with Engineering and SRE teams.

Request access: `contact@ravenrisk.dev`

**2. Send a signal**

```bash
curl -X POST https://your-deployment/v1/analyze \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "authentication service unavailable — 847 failed logins in 60s, MFA bypass attempts detected",
    "source": "iam"
  }'
```

**3. Get a decision**

```json
{
  "request_id": "a3f2c1d0-...",
  "incident_id": "inc_8f3a...",
  "event_type": "authentication_failure",
  "monitored_object": "authentication-service",
  "risk_score": 0.847,
  "severity": "HIGH",
  "priority": "critical",
  "confidence": 91,
  "recommended_action": "escalate",
  "evidence": [
    "Authentication service reporting unavailable state",
    "MFA bypass attempts detected — high-risk attack pattern",
    "IAM source prior: elevated risk baseline",
    "847 failed logins in 60 seconds — high frequency burst"
  ],
  "hypothesis": "Possible credential stuffing attack targeting authentication service. MFA bypass pattern suggests targeted access attempt, not opportunistic scanning.",
  "recommended_steps": [
    "Immediately check auth-service health and error logs",
    "Confirm whether MFA bypass attempts succeeded — check audit trail",
    "Rate-limit or block originating IPs if pattern continues",
    "Notify security team — MFA bypass is a critical escalation trigger",
    "Check for lateral movement from any accounts that may have been compromised"
  ],
  "impact": {
    "affected_users": "all users attempting authentication",
    "affected_services": ["authentication-service"],
    "business_criticality": "critical"
  },
  "context": {
    "recent_deployment": false,
    "related_alerts": ["auth_service_unavailable", "mfa_bypass_attempt"]
  },
  "historical_context": {
    "similar_incidents_last_30d": 0,
    "last_occurrence": null,
    "known_resolution": null
  }
}
```

---

## Source types

The `source` field drives risk weighting. Supported values:

| Value | Use case |
|---|---|
| `iam` | Auth service, identity provider, SSO |
| `application` | App-layer logs, service errors |
| `infrastructure` | Host metrics, Kubernetes, databases |
| `network` | Firewall, load balancer, DNS |
| `audit` | Audit logs, compliance events |
| `unknown` | Unclassified signals (default) |

---

## Recommended actions

| Action | Risk score | Meaning |
|---|---|---|
| `escalate` | ≥ 0.85 | Page on-call immediately |
| `investigate` | ≥ 0.60 | Engineer should investigate within the hour |
| `monitor` | ≥ 0.35 | Watch for recurrence; no immediate action |
| `group_as_noise` | ≥ 0.10 | Low signal; cluster with related events |
| `ignore` | < 0.10 | Below detection threshold |

---

## Deploying RAVEN

**Requirements:** Python 3.11+, pip

```bash
git clone https://github.com/your-org/raven.git
cd raven
pip install -e .
cp .env.example .env       # fill in RAVEN_API_KEY
python -m raven.api.main
```

All configuration is via environment variables. See `.env.example` for the full list.

**Railway / Render:** A `Procfile` and `railway.toml` are included. Set `RAVEN_API_KEY` in your platform's env var settings and deploy.

---

## API reference

| Endpoint | Method | Description |
|---|---|---|
| `/v1/analyze` | POST | Full Sentinel pipeline — decision intelligence |
| `/health` | GET | Service health + buffer metrics |
| `/evaluate` | POST | Legacy integer score (0–100), no pipeline |
| `/beta/impact-summary` | GET | Impact feedback aggregate |

Full OpenAPI docs available at `/docs` when the server is running.

---

## Status

RAVEN is in **closed beta**. The API is stable; the infrastructure is not yet hardened for production scale. We are validating with engineering and SRE teams before general availability.

**Contact:** `contact@ravenrisk.dev`
