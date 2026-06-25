"""
RAVEN — Beta Key Management CLI
================================
Usage (run from repo root):

  python scripts/manage_beta.py generate "Tester Name"
  python scripts/manage_beta.py list
  python scripts/manage_beta.py list --active-only
  python scripts/manage_beta.py revoke <key>
  python scripts/manage_beta.py info <key>

This tool operates on the in-memory BETA_REGISTRY defined in
src/raven/api/beta_keys.py. It prints the commands needed to persist
changes — copy the output into beta_keys.py to make them permanent.
"""
from __future__ import annotations

import argparse
import sys

# Allow running from repo root without installing the package.
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from raven.api.beta_keys import (
    BETA_REGISTRY,
    add_key,
    generate_beta_key,
    is_valid_beta_key,
    list_keys,
    revoke_key,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

_W  = "\033[93m"   # yellow
_G  = "\033[92m"   # green
_R  = "\033[91m"   # red
_B  = "\033[94m"   # blue
_DIM = "\033[2m"
_RST = "\033[0m"

def _ok(msg: str)   -> None: print(f"{_G}[OK]{_RST}   {msg}")
def _err(msg: str)  -> None: print(f"{_R}[ERR]{_RST}  {msg}", file=sys.stderr)
def _info(msg: str) -> None: print(f"{_B}[--]{_RST}   {msg}")
def _warn(msg: str) -> None: print(f"{_W}[!!]{_RST}   {msg}")


def _entry_line(prefix: str, key: str, entry: dict) -> None:
    status_color = _G if entry["status"] == "active" else _R
    print(
        f"  {_DIM}{prefix}{_RST}"
        f"  {status_color}{entry['status']:8}{_RST}"
        f"  {_B}{key}{_RST}"
        f"  {entry['name']}"
        f"  {_DIM}{entry['created_at']}{_RST}"
    )


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_generate(name: str, prefix: str) -> None:
    key = generate_beta_key(prefix)
    add_key(key, name)
    _ok(f"Key generated for '{name}'")
    print()
    _info(f"Key   : {_B}{key}{_RST}")
    _info(f"Name  : {name}")
    _info(f"Status: active")
    print()
    _warn("This key exists in memory only. To persist it, add to BETA_REGISTRY in:")
    _warn("  src/raven/api/beta_keys.py")
    print()
    print("  Paste this entry:")
    print(f'    "{key}": {{')
    print(f'        "name":       "{name}",')
    print(f'        "status":     "active",')
    print(f'        "created_at": "{BETA_REGISTRY[key]["created_at"]}",')
    print(f'    }},')


def cmd_list(active_only: bool) -> None:
    rows = list_keys(active_only=active_only)
    if not rows:
        _info("No keys found.")
        return
    label = "active keys" if active_only else "all keys"
    print(f"\n  {len(rows)} {label} in BETA_REGISTRY:\n")
    print(f"  {'#':3}  {'STATUS':8}  {'KEY':36}  {'NAME':20}  CREATED")
    print("  " + "-" * 90)
    for i, row in enumerate(rows, 1):
        entry = {"name": row["name"], "status": row["status"], "created_at": row["created_at"]}
        _entry_line(f"{i:3}", row["key"], entry)
    print()


def cmd_revoke(key: str) -> None:
    if not BETA_REGISTRY.get(key):
        _err(f"Key not found: {key}")
        sys.exit(1)
    if BETA_REGISTRY[key]["status"] == "revoked":
        _warn(f"Key already revoked: {key}")
        return
    revoke_key(key)
    _ok(f"Key revoked in memory: {key}")
    _warn("To persist, update status to 'revoked' in src/raven/api/beta_keys.py")


def cmd_info(key: str) -> None:
    entry = BETA_REGISTRY.get(key)
    if not entry:
        _err(f"Key not found: {key}")
        sys.exit(1)
    print()
    _info(f"Key       : {_B}{key}{_RST}")
    _info(f"Name      : {entry['name']}")
    status_color = _G if entry["status"] == "active" else _R
    _info(f"Status    : {status_color}{entry['status']}{_RST}")
    _info(f"Created   : {entry['created_at']}")
    _info(f"Valid now : {'yes' if is_valid_beta_key(key) else 'no'}")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="manage_beta",
        description="RAVEN Beta Key Management",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate a new beta key")
    gen.add_argument("name", help="Tester display name")
    gen.add_argument("--prefix", default="raven_beta", help="Key prefix (default: raven_beta)")

    lst = sub.add_parser("list", help="List registry entries")
    lst.add_argument("--active-only", action="store_true", help="Show only active keys")

    rev = sub.add_parser("revoke", help="Revoke a beta key")
    rev.add_argument("key", help="Key to revoke")

    inf = sub.add_parser("info", help="Show details for a key")
    inf.add_argument("key", help="Key to inspect")

    args = parser.parse_args()

    if args.command == "generate":
        cmd_generate(args.name, args.prefix)
    elif args.command == "list":
        cmd_list(args.active_only)
    elif args.command == "revoke":
        cmd_revoke(args.key)
    elif args.command == "info":
        cmd_info(args.key)


if __name__ == "__main__":
    main()
