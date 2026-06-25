"""
RAVEN API — Authentication and Rate Limiting
============================================
All auth and rate-limiting logic lives here so the key store can be
swapped (env-var → DB → OAuth) by changing only this module.

Migration path to DB-backed keys:
  Replace the body of _tier() with a DB lookup. The rest of the auth
  flow (HTTPException codes, rate limit enforcement) stays the same.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict

from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader

# ── Key store (env-var backed) ────────────────────────────────────────────────

def _load_keys(env_var: str, default: str) -> frozenset[str]:
    return frozenset(filter(None, os.getenv(env_var, default).split(",")))

# Re-export so callers can inspect the live sets without re-reading env vars.
# Populate FREE_API_KEYS / PRO_API_KEYS env vars with comma-separated keys
# for multi-key deployments. For single-key deployments use RAVEN_API_KEY only.
FREE_KEYS: frozenset[str] = _load_keys("FREE_API_KEYS", "")
PRO_KEYS: frozenset[str] = _load_keys("PRO_API_KEYS", "")

# RAVEN_API_KEY is the production master key — always accepted as pro tier.
# Set this env var before starting the server; all API calls require a valid key.
_master_key = os.getenv("RAVEN_API_KEY")
if _master_key:
    PRO_KEYS = PRO_KEYS | frozenset({_master_key})

_DAILY_LIMITS: dict[str, int] = {"free": 100, "pro": 10_000}
_DAY = 86_400.0


def _tier(api_key: str) -> str | None:
    """Return plan tier for a key, or None if unrecognised.

    DB-migration point: replace this body with a database lookup.
    Signature and return type must not change.
    """
    if api_key in PRO_KEYS:
        return "pro"
    if api_key in FREE_KEYS:
        return "free"
    return None


# ── Per-key daily rate limiter (sliding window, in-memory) ────────────────────

_key_window: dict[str, list[float]] = defaultdict(list)


def _check_key_limit(api_key: str, tier: str) -> None:
    now = time.time()
    _key_window[api_key] = [t for t in _key_window[api_key] if now - t < _DAY]
    if len(_key_window[api_key]) >= _DAILY_LIMITS[tier]:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Daily limit reached ({_DAILY_LIMITS[tier]} req/day on {tier} plan)."
                " Upgrade at raven.dev/pricing."
            ),
        )
    _key_window[api_key].append(now)


# ── Per-IP per-minute rate limiter (sliding window, in-memory) ────────────────

_IP_LIMIT = 30
_MINUTE = 60.0
_ip_window: dict[str, list[float]] = defaultdict(list)


def check_ip_rate_limit(ip: str) -> None:
    """Enforce 30 req/min per source IP. Raises HTTP 429 on breach."""
    now = time.time()
    _ip_window[ip] = [t for t in _ip_window[ip] if now - t < _MINUTE]
    if len(_ip_window[ip]) >= _IP_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({_IP_LIMIT} req/min per IP).",
        )
    _ip_window[ip].append(now)


# ── FastAPI auth dependency ───────────────────────────────────────────────────

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(
    api_key: str | None = Depends(_api_key_header),
) -> dict[str, str]:
    """FastAPI dependency: authenticate via X-API-Key.

    Production (RAVEN_API_KEY set): master key or active beta key → tier="pro".
    Dev fallback (RAVEN_API_KEY unset): demo keys accepted with daily quota.
    All auth failures raise HTTP 401.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header.")
    if _master_key:
        if api_key == _master_key:
            return {"key": api_key, "tier": "pro"}
        # Closed-beta: active beta keys are accepted alongside the master key.
        # Late import avoids the beta_keys → auth ← main circular dependency.
        from raven.api.beta_keys import is_valid_beta_key as _ibk
        if _ibk(api_key):
            return {"key": api_key, "tier": "pro"}
        raise HTTPException(status_code=401, detail="Invalid API key.")
    # Dev fallback: accept demo keys with quota enforcement.
    tier = _tier(api_key)
    if tier is None:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    _check_key_limit(api_key, tier)
    return {"key": api_key, "tier": tier}
