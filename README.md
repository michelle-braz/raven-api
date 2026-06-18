# RAVEN by NOVA

**Real-time risk scoring for every user action — one API call, under 5ms.**

---

## What It Does

RAVEN scores every event — login attempt, transaction, access request — and returns a risk verdict in milliseconds. No ML pipeline to maintain. No model drift. No false positives from stale training data. Rules are explicit, auditable, and tunable.

```bash
curl -X POST https://api.nova.dev/evaluate \
  -H "X-API-Key: your_key" \
  -H "Content-Type: application/json" \
  -d '{"action": "login_failed", "ip": "192.168.1.1", "attempts": 5}'
```

```json
{
  "risk_score": 80,
  "level": "HIGH",
  "signals": ["attempts>=3", "action=login_failed", "unknown_ip"],
  "plan": "free"
}
```

---

## Architecture

```
NOVA (company)
└── RAVEN  ─  product API layer (FastAPI, auth, rate limiting)
    └── SENTINEL  ─  risk intelligence engine (pure Python, zero HTTP deps)
        ├── core/      fast synchronous evaluate() for the API
        └── pipeline/  async 4-layer ingestion pipeline for high-volume streams
```

```
Raven/
├── apps/
│   ├── api/          RAVEN API — FastAPI, API key auth, rate limiting
│   └── frontend/     landing page
├── services/
│   └── sentinel/     SENTINEL engine — domain logic only, no FastAPI coupling
├── packages/
│   └── shared/       cross-cutting primitives
├── tests/            pytest suite
└── pyproject.toml
```

**Boundaries enforced:**
- `sentinel` has zero FastAPI dependency — pure Python, zero runtime coupling to the API layer
- `apps/api` is a thin HTTP adapter over `sentinel.core.engine.evaluate()`
- Rules are pure functions: deterministic, testable in isolation

---

## Quickstart

```bash
git clone <repo> && cd Raven
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
export RAVEN_API_KEY=your-secret-key               # Windows: set RAVEN_API_KEY=your-secret-key
python -m raven.api.main
```

API available at `http://localhost:8000` — interactive docs at `/docs`.
All endpoints (except `/health`) require the header `X-API-Key: your-secret-key`.

---

## API

### `POST /evaluate`

**Header:** `X-API-Key: nova_free_demo`

| Field | Type | Description |
|---|---|---|
| `user_id` | string/int | User identifier (optional) |
| `action` | string | Event type (e.g. `login_failed`, `purchase`) |
| `ip` | string | Client IP address |
| `attempts` | int | Number of consecutive attempts |

**Response:**

| Field | Description |
|---|---|
| `risk_score` | 0–100 integer |
| `level` | `LOW` / `MEDIUM` / `HIGH` |
| `signals` | Named rules that fired |
| `plan` | `free` or `pro` |

### `GET /health`

```json
{"status": "ok", "service": "nova-risk-api", "version": "1.0.0"}
```

---

## Risk Scoring

| Rule | Score | Signal |
|---|---|---|
| `attempts >= 3` | +40 | `attempts>=3` |
| `action == login_failed` | +30 | `action=login_failed` |
| IP in suspicious set | +10 | `unknown_ip` |
| Maximum score | 100 | — |

Thresholds: **LOW** < 40 · **MEDIUM** 40–69 · **HIGH** ≥ 70

---

## API Key Tiers

| Tier | Limit | Key (demo) |
|---|---|---|
| Free | 100 req/day | `nova_free_demo` |
| Pro | 10,000 req/day | `nova_pro_demo` |

Production: set `RAVEN_API_KEY` — all requests must present this key in the `X-API-Key` header.
Dev only (when `RAVEN_API_KEY` is unset): demo keys `nova_free_demo` (100 req/day) and `nova_pro_demo` (10,000 req/day) are accepted.

---

## Development

```bash
# Install in editable mode
pip install -e .

# Run tests
pytest -q

# Validate scoring scenarios
python scripts/validate_nova_product.py

# Check a single event inline
python -c "from raven.sentinel.core.engine import evaluate; print(evaluate({'action':'login_failed','ip':'192.168.1.1','attempts':5}))"
```

---

## Deployment

Procfile included for Railway / Render / Fly.io:

```
web: uvicorn raven.api.main:app --host 0.0.0.0 --port $PORT
```

Environment variables:
- `RAVEN_API_KEY` — **required**; all API requests must present this key in `X-API-Key` header
- `PORT` — set automatically by the platform
- `HOST` — bind address (default `0.0.0.0`)
- `LOG_LEVEL` — uvicorn log level (default `info`)
- `SENTINEL_WEBHOOK_URL` — optional outbound webhook for HIGH/CRITICAL alerts
- `FREE_API_KEYS` — dev only; ignored when `RAVEN_API_KEY` is set
- `PRO_API_KEYS` — dev only; ignored when `RAVEN_API_KEY` is set
