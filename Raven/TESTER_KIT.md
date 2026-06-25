# RAVEN — Beta Tester Kit

> Send this file (or its contents) directly to a tester. Replace `YOUR_KEY` and `YOUR_URL` before sending.

---

**Your API key:** `YOUR_KEY`  
**API URL:** `https://YOUR_URL`

---

## What I need from you (5 minutes)

RAVEN is an incident intelligence API. You send it an event description — a log line, alert, or anomaly — and it returns a structured investigation recommendation: what to do, why, and where to start.

Recommended actions: `escalate` · `investigate` · `monitor` · `group_as_noise` · `ignore`

I need to know if the recommendation matches your intuition as someone who handles these incidents.

Run any of the scenarios below. After each one, tell RAVEN what you actually decided to do.

---

## How to run a scenario

Two requests. Copy both, replace the placeholders, run them.

**Request 1 — analyze the event:**

```bash
curl -X POST https://YOUR_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"message": "5 failed login attempts in 2 minutes from unknown IP", "source": "iam"}'
```

You'll get back something like:
```json
{
  "request_id": "req_xyz789",
  "incident_id": "evt_abc123",
  "event_type": "authentication_failure",
  "monitored_object": "authentication-service",
  "risk_score": 0.7823,
  "severity": "HIGH",
  "priority": "high",
  "confidence": 84,
  "recommended_action": "investigate",
  "evidence": [
    "5 failed login attempts detected",
    "IAM source prior: elevated risk baseline",
    "Unknown IP — not previously seen on this account"
  ],
  "hypothesis": "Possible credential stuffing or brute-force attempt targeting authentication service.",
  "recommended_steps": [
    "Check auth-service logs for the originating IP",
    "Determine if any login succeeded after the failures",
    "Rate-limit or block the IP if pattern continues",
    "Notify security team if failures exceed 10 within 5 minutes"
  ],
  "impact": {
    "affected_users": "account under attack",
    "affected_services": ["authentication-service"],
    "business_criticality": "high"
  },
  "impact_feedback_endpoint": "/beta/decision-impact"
}
```

**Request 2 — tell me what you actually did:**

Copy `incident_id` and `request_id` from above. Fill in what you actually decided.

```bash
curl -X POST https://YOUR_URL/beta/decision-impact \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id":              "PASTE_INCIDENT_ID",
    "request_id":               "PASTE_REQUEST_ID",
    "decision_taken":           "BLOCK",
    "action_taken":             "Describe what you actually did or would do",
    "confidence":               4,
    "replaced_manual_process":  true,
    "time_saved_minutes":       10
  }'
```

`decision_taken` options: `ACCEPT` `REVIEW` `BLOCK` `IGNORE` `INVESTIGATE` `OTHER`

`confidence` scale: 1 = guessing, 5 = certain RAVEN was right

---

## 10 Ready-to-run scenarios

Pick any that feel relevant to your work. Replace `YOUR_URL` and `YOUR_KEY` in each.

---

### 1. Repeated failed logins

```bash
curl -X POST https://YOUR_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"message": "5 failed login attempts in 2 minutes from IP 45.33.32.156", "source": "iam"}'
```

---

### 2. Unknown device login

```bash
curl -X POST https://YOUR_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"message": "Login from device never seen before in account history", "source": "iam"}'
```

---

### 3. Password reset abuse

```bash
curl -X POST https://YOUR_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"message": "Password reset requested 4 times in 10 minutes for same account", "source": "iam"}'
```

---

### 4. API key from new country

```bash
curl -X POST https://YOUR_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"message": "API key used from country where account has never been active", "source": "network"}'
```

---

### 5. Rate abuse — search endpoint

```bash
curl -X POST https://YOUR_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"message": "1000 requests to /api/search in 60 seconds from single user", "source": "application"}'
```

---

### 6. Privilege escalation

```bash
curl -X POST https://YOUR_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"message": "User granted admin role by non-admin account", "source": "iam"}'
```

---

### 7. After-hours SSH

```bash
curl -X POST https://YOUR_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"message": "SSH login to production server at 3am outside business hours", "source": "infrastructure"}'
```

---

### 8. Large outbound transfer

```bash
curl -X POST https://YOUR_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"message": "Outbound data transfer of 2GB to unknown external IP in 5 minutes", "source": "network"}'
```

---

### 9. Unusual payroll access

```bash
curl -X POST https://YOUR_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"message": "User accessed payroll data for the first time after 2 years on account", "source": "audit"}'
```

---

### 10. Normal login — baseline

```bash
curl -X POST https://YOUR_URL/v1/analyze \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"message": "User login successful from registered device during business hours", "source": "application"}'
```

---

## Feedback template (plain text — reply by email if curl is annoying)

If the curl for the feedback endpoint is too much friction, reply to this email with:

```
Scenario: [which one you tested]
RAVEN decision: [what it said]
Your decision: [what you would actually do]
Was it right: [yes / no / partially]
Time it would have saved: [minutes]
Would you use this: [yes / no / maybe]
```

That's all I need. Reply whenever — no deadline.
