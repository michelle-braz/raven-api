# RAVEN — Risk Decision API · Closed Beta Guide

> **This document is for approved beta testers only.**
> Base URL: `https://YOUR_RAVEN_APP.railway.app` ← replace with your deployment URL before sharing

---

## What RAVEN does

You send an event description. RAVEN returns a verdict: **ALLOW**, **REVIEW**, or **BLOCK** — plus a score, a reason code, and a plain-English explanation.

You don't interpret scores. You act on the decision.

---

## Step 1 — Get your API key

Email **beta@ravenrisk.dev** with your name and use case.  
You'll receive a private key in the format `raven_beta_XXXXXXXXXXXXXXXX`.

Each key is unique to you. Do not share it.

---

## Step 2 — Send your first request

Replace `YOUR_KEY` with your assigned beta key.  
Replace `YOUR_API_URL` with the production base URL.

```bash
curl -X POST https://YOUR_API_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "failed login attempt from unknown IP address",
    "source": "iam"
  }'
```

That's the entire API call. Two fields in. Decision out.

---

## Step 3 — Read the response

```json
{
  "message":      "failed login attempt from unknown IP address",
  "source":       "iam",
  "risk_score":   0.87,
  "severity":     "HIGH",
  "decision":     "BLOCK",
  "reason_code":  "HIGH_RISK_SCORE",
  "explanation":  "Risk score exceeded the blocking threshold.",
  "incident_id":  "evt_a1b2c3d4",
  "tier":         "pro",
  "explain":      null
}
```

**The three fields you care about:**

| Field | What it means |
|---|---|
| `decision` | What to do: `ALLOW`, `REVIEW`, or `BLOCK` |
| `explanation` | Why in plain English |
| `incident_id` | Stable ID — same event pattern always gets the same ID |

---

## Decision reference

| `decision` | `risk_score` range | What it means |
|---|---|---|
| `ALLOW` | < 0.50 | Safe to proceed |
| `REVIEW` | 0.50 – 0.79 | Flag for manual review |
| `BLOCK` | ≥ 0.80 | Stop — risk exceeds threshold |

---

## The `source` field

`source` tells RAVEN where the event originated. It adjusts scoring weights.

| Value | Use for |
|---|---|
| `iam` | Identity and access events (logins, privilege changes) |
| `network` | Traffic, firewall, connection events |
| `application` | App-layer events (form submissions, API calls, errors) |
| `infrastructure` | Server, container, or cloud events |
| `audit` | Compliance and audit log events |
| `unknown` | Default — use when source is unclear |

---

## Public endpoints (no key required)

| Endpoint | Purpose |
|---|---|
| `GET /` | Product landing page |
| `GET /health` | Health check (`{"status": "ok"}`) |
| `GET /status` | Service uptime and version |
| `GET /docs` | Interactive API documentation (Swagger UI) |

---

## Rate limits

- **30 requests / minute** per IP address
- Exceeding the limit returns `HTTP 429`

---

## Error reference

**Auth gate errors** (missing/invalid key) use this envelope:
```json
{ "error": "missing_api_key", "message": "API key required (beta access)" }
{ "error": "invalid_api_key", "message": "Invalid or inactive beta key" }
```

**API errors** (bad request, rate limit) use FastAPI's standard envelope:
```json
{ "detail": "Rate limit exceeded (30 req/min per IP)." }
{ "detail": [{ "loc": ["body", "source"], "msg": "...", "type": "..." }] }
```

| HTTP status | Meaning |
|---|---|
| `401` | No `X-API-Key` header sent |
| `403` | Key not recognized or revoked |
| `422` | Request body failed schema validation |
| `429` | Rate limit exceeded (30 req/min per IP, or daily key quota) |
| `500` | Internal error — contact beta@ravenrisk.dev with the full response body |

---

## Step 4 — Send feedback

After testing, reply to your beta invitation email with:

1. What you tried to detect
2. Whether the decisions matched your expectations
3. Any friction you hit during integration

Feedback directly shapes what gets built next.

---

## Quick test matrix

Try these to verify your key works and see the full decision range:

```bash
# Expect: BLOCK
curl -X POST https://YOUR_API_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"message": "unauthorized privilege escalation on production database", "source": "iam"}'

# Expect: REVIEW
curl -X POST https://YOUR_API_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"message": "unusual outbound connection to external IP", "source": "network"}'

# Expect: ALLOW
curl -X POST https://YOUR_API_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"message": "user login successful from registered device", "source": "application"}'
```

---

## Did RAVEN help? — Report a decision

Every `/v1/analyze` response includes `request_id` and `impact_feedback_endpoint`.  
After acting on a recommendation, send one more request to close the loop:

```bash
curl -X POST https://YOUR_API_URL/beta/decision-impact \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id":              "<from analyze response>",
    "request_id":               "<from analyze response>",
    "decision_taken":           "BLOCK",
    "action_taken":             "Blocked suspicious login attempt",
    "confidence":               4,
    "replaced_manual_process":  true,
    "time_saved_minutes":       15,
    "comments":                 "Would normally require a manual review ticket"
  }'
```

`decision_taken` options: `ACCEPT` · `REVIEW` · `BLOCK` · `IGNORE` · `INVESTIGATE` · `OTHER`

`confidence` scale: 1 (guessing) → 5 (certain RAVEN was right)

---

## North Star Metric

RAVEN's primary KPI is:

> **Number of real decisions influenced.**

Not:
- lines of code
- API calls
- architecture complexity
- dashboards
- ML sophistication

Success means: a real person received a RAVEN recommendation and changed or accelerated a real decision because of it.

This is measured via `POST /beta/decision-impact`. Every submission counts directly toward the North Star.

---

## Need help?

**Email:** beta@ravenrisk.dev  
**Swagger UI:** `https://YOUR_API_URL/docs`  
**Service status:** `https://YOUR_API_URL/status`
