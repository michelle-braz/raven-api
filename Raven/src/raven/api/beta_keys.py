from __future__ import annotations

import json
import os
import secrets
import string
from datetime import datetime, timezone
from typing import Literal, TypedDict


class BetaEntry(TypedDict):
    name: str
    status: Literal["active", "revoked"]
    created_at: str  # ISO 8601 UTC


def _load_registry_from_env() -> dict[str, BetaEntry]:
    """Populate the beta registry from the BETA_KEYS_JSON environment variable.

    Expected format (compact JSON):
      {"raven_beta_xxx": {"name": "Tester Name", "status": "active", "created_at": "2026-01-01T00:00:00Z"}}

    Returns an empty dict if the variable is unset or contains invalid JSON.
    Use `python scripts/manage_beta.py generate "<Name>"` to generate new keys.
    """
    raw = os.getenv("BETA_KEYS_JSON", "")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


# In-memory registry — seeded from BETA_KEYS_JSON at startup.
# Swap is_valid_beta_key() for a DB lookup when the beta graduates.
# Schema and public interface stay the same.
BETA_REGISTRY: dict[str, BetaEntry] = _load_registry_from_env()


# ── Validation ────────────────────────────────────────────────────────────────

def is_valid_beta_key(key: str) -> bool:
    """Return True iff key is present in BETA_REGISTRY with status='active'."""
    entry = BETA_REGISTRY.get(key)
    return entry is not None and entry["status"] == "active"


# ── Key generation ────────────────────────────────────────────────────────────

_KEY_ALPHABET = string.ascii_lowercase + string.digits
_KEY_SUFFIX_LEN = 16


def generate_beta_key(prefix: str = "raven_beta") -> str:
    """Return a cryptographically secure beta key string.

    Format: <prefix>_<16 random lowercase-alphanumeric chars>
    Uses secrets.choice — safe for security-sensitive identifiers.
    """
    suffix = "".join(secrets.choice(_KEY_ALPHABET) for _ in range(_KEY_SUFFIX_LEN))
    return f"{prefix}_{suffix}"


# ── Registry management ───────────────────────────────────────────────────────

def add_key(key: str, name: str) -> None:
    """Add an active beta key to the in-memory registry.

    Idempotent: re-adding an existing key updates name and resets status to active.
    """
    BETA_REGISTRY[key] = {
        "name":       name,
        "status":     "active",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def revoke_key(key: str) -> bool:
    """Set a key's status to 'revoked'. Returns False if key not found."""
    entry = BETA_REGISTRY.get(key)
    if entry is None:
        return False
    entry["status"] = "revoked"
    return True


def list_keys(*, active_only: bool = False) -> list[dict[str, str]]:
    """Return registry entries as a list of plain dicts, sorted by created_at."""
    rows = [
        {"key": k, **v}
        for k, v in BETA_REGISTRY.items()
        if not active_only or v["status"] == "active"
    ]
    return sorted(rows, key=lambda r: r["created_at"])


# ── Auth integration ──────────────────────────────────────────────────────────

def register_with_auth() -> None:
    """Inject active beta keys into the live PRO_KEYS store at startup.

    Late import breaks the beta_keys → auth ← main circular dependency.
    Covers dev mode (no RAVEN_API_KEY); production mode is covered by the
    is_valid_beta_key check added to require_api_key in auth.py.
    """
    import raven.api.auth as _auth

    active_keys = frozenset(k for k, v in BETA_REGISTRY.items() if v["status"] == "active")
    _auth.PRO_KEYS = _auth.PRO_KEYS | active_keys
