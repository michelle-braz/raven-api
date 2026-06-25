"""
System Contract Layer — pipeline/contracts.py
=============================================
Cross-module invariants for the NOVA Sentinel pipeline, expressed as
verifiable assertions that catch misconfiguration before it touches live data.

Each check is a zero-argument callable that raises AssertionError on violation
with a self-explaining message. Checks import only what they need (lazy
imports inside the callable), so this module can be imported at any point
in the startup sequence without triggering the full pipeline import chain.

Activation: called by build_engine() when strict=True or SENTINEL_STRICT_MODE=1.
Production (neither flag set): not called — zero overhead.

Seven checks, four categories:
  SCORING       — weight table, severity thresholds, source priors
  NORMALIZATION — scrubber ordering, signature namespace stability
  SCHEMA        — severity rank monotonicity
  CONTRACT      — feature key/weight registry alignment
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, Literal

# ── Contract registry ─────────────────────────────────────────────────────────

Layer = Literal["scoring", "normalization", "schema", "contract"]


@dataclass(frozen=True, slots=True)
class SystemContract:
    """Formal declaration of a cross-module pipeline invariant."""
    name: str
    description: str
    layer: Layer
    check: Callable[[], None]


# ── Check implementations ─────────────────────────────────────────────────────

def _check_weights_sum() -> None:
    from raven.sentinel.pipeline.intelligence_layer.engine import _WEIGHTS
    total = sum(_WEIGHTS.values())
    assert math.isclose(total, 1.0, rel_tol=1e-9), (
        "SystemContract VIOLATED — 'weights_sum_to_one'\n"
        f"  _WEIGHTS values sum to {total:.10f}, expected 1.0\n"
        "  Impact: risk_score range is no longer guaranteed to be in [0, 1].\n"
        "  Fix   : ensure all weight values sum to exactly 1.0"
    )


def _check_feature_keys_match() -> None:
    from raven.sentinel.pipeline.intelligence_layer.engine import (
        _WEIGHTS,
        _CONTRACT_BY_NAME,
    )
    weight_keys = set(_WEIGHTS.keys())
    contract_keys = set(_CONTRACT_BY_NAME.keys())
    assert weight_keys == contract_keys, (
        "SystemContract VIOLATED — 'feature_keys_match_weights'\n"
        f"  _WEIGHTS keys      : {sorted(weight_keys)}\n"
        f"  FeatureContract keys: {sorted(contract_keys)}\n"
        f"  In weights, missing contract: {sorted(weight_keys - contract_keys)}\n"
        f"  In contracts, missing weight: {sorted(contract_keys - weight_keys)}\n"
        "  Impact: a scored feature has no invariant declared, or a declared\n"
        "  invariant belongs to a feature that is not scored."
    )


def _check_severity_thresholds_monotone() -> None:
    from raven.sentinel.pipeline.intelligence_layer.engine import _SEVERITY_THRESHOLDS
    floors = [floor for floor, _ in _SEVERITY_THRESHOLDS]
    for i in range(len(floors) - 1):
        assert floors[i] > floors[i + 1], (
            "SystemContract VIOLATED — 'severity_thresholds_monotone'\n"
            f"  _SEVERITY_THRESHOLDS[{i}].floor={floors[i]} is not greater than\n"
            f"  _SEVERITY_THRESHOLDS[{i + 1}].floor={floors[i + 1]}\n"
            "  Impact: _severity_of() first-match loop may skip or repeat severity bands,\n"
            "  producing wrong severity classifications silently."
        )


def _check_source_priors_in_range() -> None:
    from raven.sentinel.pipeline.intelligence_layer.engine import _SOURCE_PRIOR
    for source, prior in _SOURCE_PRIOR.items():
        assert 0.0 < prior <= 1.0, (
            "SystemContract VIOLATED — 'source_priors_in_range'\n"
            f"  _SOURCE_PRIOR[{source!r}] = {prior}, expected in (0.0, 1.0]\n"
            "  Impact: source_factor would be outside the FeatureContract bounds [0, 1],\n"
            "  corrupting the weighted sum and violating the FeatureGuard."
        )


def _check_scrubber_order() -> None:
    from raven.sentinel.pipeline.signal_layer.normalizer import _SCRUBBERS, _PLACEHOLDERS

    placeholders = [ph for _, ph in _SCRUBBERS]

    def _first(ph: str) -> int:
        return next((i for i, p in enumerate(placeholders) if p == ph), -1)

    def _last(ph: str) -> int:
        return next((i for i in range(len(placeholders) - 1, -1, -1) if placeholders[i] == ph), -1)

    ts_idx = _first(_PLACEHOLDERS["ts"])
    uuid_idx = _first(_PLACEHOLDERS["uuid"])
    hash_idx = _first(_PLACEHOLDERS["hash"])
    hex_idx = _first(_PLACEHOLDERS["hex"])
    num_idx = _last(_PLACEHOLDERS["num"])

    assert ts_idx != -1, "SystemContract: timestamp scrubber missing from _SCRUBBERS"
    assert uuid_idx != -1, "SystemContract: uuid scrubber missing from _SCRUBBERS"
    assert hash_idx != -1, "SystemContract: hash scrubber missing from _SCRUBBERS"
    assert hex_idx != -1, "SystemContract: hex scrubber missing from _SCRUBBERS"
    assert num_idx != -1, "SystemContract: number scrubber missing from _SCRUBBERS"

    assert ts_idx < num_idx, (
        "SystemContract VIOLATED — 'scrubber_order'\n"
        f"  Timestamp scrubber is at index {ts_idx}, number scrubber at {num_idx}.\n"
        "  Timestamp scrubber must run before number scrubber or date components\n"
        "  (e.g. '2026', '06', '15') will be replaced with <num> tokens before the\n"
        "  timestamp pattern can match, corrupting signatures."
    )
    assert uuid_idx < hex_idx, (
        "SystemContract VIOLATED — 'scrubber_order'\n"
        f"  UUID scrubber is at index {uuid_idx}, hex scrubber at {hex_idx}.\n"
        "  UUID scrubber must precede hex scrubber or UUID hex segments will be\n"
        "  matched by the shorter hex pattern, fragmenting the token."
    )
    assert hash_idx < hex_idx, (
        "SystemContract VIOLATED — 'scrubber_order'\n"
        f"  Hash scrubber (32+ chars) is at index {hash_idx}, hex scrubber at {hex_idx}.\n"
        "  Long-hash scrubber must precede hex scrubber or 32+ char hashes will be\n"
        "  matched by the 6+ hex pattern, losing the hash-vs-hex distinction."
    )


def _check_signature_namespace_stable() -> None:
    from raven.sentinel.pipeline.signal_layer.normalizer import _SIGNATURE_NAMESPACE
    expected = "sentinel.signal.v1"
    assert _SIGNATURE_NAMESPACE == expected, (
        "SystemContract VIOLATED — 'signature_namespace_stable'\n"
        f"  _SIGNATURE_NAMESPACE={_SIGNATURE_NAMESPACE!r}, expected {expected!r}\n"
        "  Impact: changing the namespace invalidates ALL existing signatures,\n"
        "  breaking deduplication for every event currently in the window.\n"
        "  If a namespace bump is intentional, update this contract and drain the window."
    )


def _check_severity_rank_monotone() -> None:
    from raven.sentinel.pipeline.data_layer.schemas import Severity, _SEVERITY_RANK
    members = list(Severity)
    for i in range(len(members) - 1):
        lo, hi = members[i], members[i + 1]
        assert _SEVERITY_RANK[lo] < _SEVERITY_RANK[hi], (
            "SystemContract VIOLATED — 'severity_rank_monotone'\n"
            f"  _SEVERITY_RANK[{lo}]={_SEVERITY_RANK[lo]} is not less than\n"
            f"  _SEVERITY_RANK[{hi}]={_SEVERITY_RANK[hi]}\n"
            "  Impact: Severity.rank comparisons in ActionDispatcher will dispatch\n"
            "  to wrong channels (min_severity checks will silently misbehave)."
        )


# ── Contract registry ─────────────────────────────────────────────────────────

_SYSTEM_CONTRACTS: tuple[SystemContract, ...] = (
    SystemContract(
        name="weights_sum_to_one",
        description=(
            "Feature weights must sum to 1.0 so the sigmoid's weighted input "
            "remains in its calibrated range and risk_score stays in [0, 1]."
        ),
        layer="scoring",
        check=_check_weights_sum,
    ),
    SystemContract(
        name="feature_keys_match_weights",
        description=(
            "FeatureContract registry keys must exactly match _WEIGHTS keys. "
            "A mismatch means a feature is scored with no declared invariant, "
            "or an invariant is declared for a feature not in the scoring formula."
        ),
        layer="contract",
        check=_check_feature_keys_match,
    ),
    SystemContract(
        name="severity_thresholds_monotone",
        description=(
            "_SEVERITY_THRESHOLDS floors must be strictly decreasing. "
            "The first-match loop in _severity_of() relies on this order to "
            "assign the correct severity band."
        ),
        layer="scoring",
        check=_check_severity_thresholds_monotone,
    ),
    SystemContract(
        name="source_priors_in_range",
        description=(
            "All _SOURCE_PRIOR values must be in (0.0, 1.0]. "
            "Values outside this range violate the 'source' FeatureContract bounds."
        ),
        layer="scoring",
        check=_check_source_priors_in_range,
    ),
    SystemContract(
        name="scrubber_order",
        description=(
            "_SCRUBBERS must process timestamps and UUIDs before the catch-all "
            "number scrubber, and long hashes before shorter hex patterns. "
            "Wrong ordering corrupts signatures."
        ),
        layer="normalization",
        check=_check_scrubber_order,
    ),
    SystemContract(
        name="signature_namespace_stable",
        description=(
            "_SIGNATURE_NAMESPACE is embedded in every content signature. "
            "Changing it invalidates all existing signatures and breaks "
            "global deduplication."
        ),
        layer="normalization",
        check=_check_signature_namespace_stable,
    ),
    SystemContract(
        name="severity_rank_monotone",
        description=(
            "Severity.rank must strictly increase from LOW to CRITICAL. "
            "The ActionDispatcher uses rank comparisons to filter channels "
            "by min_severity."
        ),
        layer="schema",
        check=_check_severity_rank_monotone,
    ),
)

_CONTRACT_BY_NAME: dict[str, SystemContract] = {c.name: c for c in _SYSTEM_CONTRACTS}


# ── Public entry point ────────────────────────────────────────────────────────

def verify_system_contracts() -> None:
    """
    Run all system-level invariant checks.

    Called by build_engine() when strict=True or SENTINEL_STRICT_MODE=1.
    Runs after _verify_feature_contracts() so feature-level invariants are
    confirmed before system-level cross-module invariants are checked.

    Raises AssertionError on first violation with a self-explaining message
    that names the contract, shows the computed vs expected values, and
    describes the production impact of the violation.
    """
    for contract in _SYSTEM_CONTRACTS:
        contract.check()
