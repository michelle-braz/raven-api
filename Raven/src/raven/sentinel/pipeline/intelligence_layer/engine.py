"""
Layer 3 — Intelligence Layer (Anomaly Detection & Risk Scoring)
===============================================================
Multi-variate heuristic scoring model that fuses several independent
signals into one normalized risk_score in [0.0, 1.0], then discretizes
into a Severity. The engine is pure and deterministic: all mutable
knowledge is passed in via ScoringContext.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field

from raven.sentinel.pipeline.data_layer.schemas import (
    RiskAssessment,
    RiskFactor,
    Severity,
    SourceType,
)
from raven.sentinel.pipeline.signal_layer.normalizer import NormalizedSignal

_log = logging.getLogger(__name__)

# ── Tunable model parameters ─────────────────────────────────────────────────
_WEIGHTS: dict[str, float] = {
    "lexical": 0.45,
    "source": 0.15,
    "volatility": 0.10,
    "recurrence": 0.20,
    "novelty": 0.10,
}

_SIGMOID_MIDPOINT = 0.30
_SIGMOID_STEEPNESS = 9.0

_SEVERITY_THRESHOLDS: tuple[tuple[float, Severity], ...] = (
    (0.85, Severity.CRITICAL),
    (0.60, Severity.HIGH),
    (0.35, Severity.MEDIUM),
    (0.0, Severity.LOW),
)

_ANOMALY_FLOOR = 0.35
_CLUSTER_SIMILARITY_THRESHOLD = 0.30

_SOURCE_PRIOR: dict[SourceType, float] = {
    SourceType.IAM: 0.90,
    SourceType.NETWORK: 0.75,
    SourceType.AUDIT: 0.65,
    SourceType.INFRASTRUCTURE: 0.55,
    SourceType.APPLICATION: 0.45,
    SourceType.UNKNOWN: 0.50,
}

_THREAT_LEXICON: dict[str, float] = {
    # ── Existing security / APT vocabulary ────────────────────────────────────
    "breach": 1.0, "compromise": 1.0, "exfiltration": 1.0, "ransomware": 1.0,
    "malware": 0.95, "rootkit": 0.95, "privilege": 0.9, "escalation": 0.9,
    "unauthorized": 0.9, "intrusion": 0.9, "exploit": 0.9, "injection": 0.85,
    "fatal": 0.85, "crash": 0.8, "panic": 0.8, "corruption": 0.8,
    "denied": 0.6, "forbidden": 0.6, "lockout": 0.6, "bruteforce": 0.85,
    "tampering": 0.85, "backdoor": 0.95, "exception": 0.55, "failure": 0.55,
    "down": 0.5, "timeout": 0.5, "error": 0.45, "unreachable": 0.5,
    "anomaly": 0.6, "suspicious": 0.7, "retry": 0.35, "throttled": 0.4,
    "degraded": 0.4, "latency": 0.3, "slow": 0.3, "warning": 0.35,
    "expired": 0.4, "rejected": 0.45, "blocked": 0.5, "quarantine": 0.6,
    # ── Operational availability ──────────────────────────────────────────────
    # "unavailable" is the single most common word in service outage messages;
    # 0.90 matches "unreachable" / "unauthorized" tier — all signal loss of access.
    "unavailable": 0.90, "outage": 0.85, "failed": 0.55,
    # ── Resource exhaustion ───────────────────────────────────────────────────
    "exhausted": 0.75,   # "connection pool exhausted", "thread pool exhausted"
    # ── Security — auth and identity bypass ───────────────────────────────────
    # "bypass" at 0.90 matches "unauthorized" — circumventing a control is as
    # serious as performing an unauthorized action.
    "bypass": 0.90, "mfa": 0.75, "impossible": 0.80, "credential": 0.75,
    # ── Operational signal quality ────────────────────────────────────────────
    "rollback": 0.70,    # rollback = production failure already confirmed
    "spike": 0.65,       # metric spike — quantitative anomaly signal
    "unusual": 0.65,     # mirrors "anomaly"=0.60; covers "unusual activity"
    "degradation": 0.55, # "service degradation" — matches "degraded"=0.40 tier
    # ── Inflected / plural forms absent from the original lexicon ────────────
    "errors": 0.50,      # "HTTP errors", "errors increased" — mirrors "error"=0.45
    "failures": 0.55,    # "login failures" — mirrors "failure"=0.55
}

_INCIDENT_PREFIX: dict[Severity, str] = {
    Severity.CRITICAL: "CRIT",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MED",
    Severity.LOW: "LOW",
}


# ── Feature contract layer ────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class FeatureContract:
    """Immutable declaration of a scoring feature's semantic invariant and value bounds."""
    name: str
    # Plain-English statement of what must always be true about this feature.
    # Used in error messages so contract violations are self-explaining.
    invariant: str
    lo: float = 0.0   # inclusive lower bound for all computed values
    hi: float = 1.0   # inclusive upper bound for all computed values


_FEATURE_CONTRACTS: tuple[FeatureContract, ...] = (
    FeatureContract(
        name="lexical",
        invariant=(
            "Higher threat-keyword density raises risk. "
            "Zero when no keywords match; at most 1.0 after clamping."
        ),
    ),
    FeatureContract(
        name="source",
        invariant=(
            "IAM and NETWORK sources carry the highest prior risk. "
            "Always a positive value in (0, 1]."
        ),
    ),
    FeatureContract(
        name="volatility",
        invariant=(
            "More high-cardinality tokens stripped → noisier event → higher volatility. "
            "Zero when nothing was scrubbed; grows toward 1.0 with more substitutions."
        ),
    ),
    FeatureContract(
        name="recurrence",
        invariant=(
            "Monotonically non-decreasing with recurrence_count. "
            "Zero for the first occurrence (count ≤ 1); positive and growing for repeated sightings."
        ),
    ),
    FeatureContract(
        name="novelty",
        invariant=(
            "1.0 when seen_signature=True (a recurring threat pattern has been confirmed), "
            "0.0 when seen_signature=False (first-time observation, no recurrence data yet). "
            "MUST be strictly higher for seen events than for novel ones — "
            "recurring attacks are more dangerous, not less."
        ),
    ),
)

_CONTRACT_BY_NAME: dict[str, FeatureContract] = {c.name: c for c in _FEATURE_CONTRACTS}

# Feature origin categories — recorded as provenance metadata, NOT used in scoring.
# Categories: "lexical" | "source" | "temporal" | "context"
_FEATURE_ORIGINS: dict[str, str] = {
    "lexical":    "lexical",   # derived from raw text token analysis
    "source":     "source",    # derived from event source type classification
    "volatility": "temporal",  # derived from normalization entropy (cardinality stripped)
    "recurrence": "context",   # derived from SignalWindow sliding-window state
    "novelty":    "context",   # derived from SignalWindow seen-signature flag
}


# ── Immutable feature vector ──────────────────────────────────────────────────

class ImmutableFeatureVector(Mapping[str, float]):
    """
    Read-only mapping of feature name → computed value, with per-feature provenance tags.

    Created once per event inside RiskEngine.assess() and cannot be modified
    after construction. This prevents accidental or deliberate mutation of the
    feature values that feed the scoring formula.

    Provenance tags (via tag_of()) record the origin category of each feature
    for auditability and debug output. They play no part in scoring.
    """

    # Annotate slot types so that attribute access is correctly typed.
    _data: dict[str, float]
    _tags: dict[str, str]
    __slots__ = ("_data", "_tags")

    def __init__(
        self,
        values: dict[str, float],
        tags: dict[str, str] | None = None,
    ) -> None:
        # Bypass our own __setattr__ guard to write the slot values exactly once.
        object.__setattr__(self, "_data", dict(values))
        object.__setattr__(self, "_tags", dict(tags) if tags else {})

    def __setattr__(self, name: str, value: object) -> None:
        raise TypeError(f"{type(self).__name__} is read-only")

    def __delattr__(self, name: str) -> None:
        raise TypeError(f"{type(self).__name__} is read-only")

    # ── Mapping protocol ──────────────────────────────────────────────────────

    def __getitem__(self, key: str) -> float:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    # ── Provenance ────────────────────────────────────────────────────────────

    def tag_of(self, name: str) -> str:
        """Origin category for a feature (e.g. 'lexical', 'context'), or 'unknown'."""
        return self._tags.get(name, "unknown")

    def __repr__(self) -> str:
        pairs = ", ".join(f"{k}={v:.4f}" for k, v in self._data.items())
        return f"ImmutableFeatureVector({{{pairs}}})"


# ── Core dataclasses ──────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class KnownIncident:
    incident_id: str
    tokens: frozenset[str]


@dataclass(frozen=True, slots=True)
class ScoringContext:
    recurrence_count: int = 0
    seen_signature: bool = False
    known_incidents: tuple[KnownIncident, ...] = field(default_factory=tuple)


# ── Math helpers ──────────────────────────────────────────────────────────────

def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-_SIGMOID_STEEPNESS * (x - _SIGMOID_MIDPOINT)))


def _jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a and not b:
        return 1.0
    union = len(a | b)
    return len(a & b) / union if union else 0.0


# ── Risk engine ───────────────────────────────────────────────────────────────

class RiskEngine:
    """Stateless, deterministic, multi-variate risk scorer."""

    def __init__(self, *, debug: bool = False, strict: bool = False) -> None:
        self._debug = debug
        # strict=True activates the runtime FeatureGuard on every assess() call.
        # debug implies strict so that debug runs always include guard output.
        self._strict = strict or debug

    def assess(
        self,
        signal: NormalizedSignal,
        context: ScoringContext | None = None,
    ) -> RiskAssessment:
        ctx = context or ScoringContext()

        # Build an immutable feature vector — values are frozen the moment it is
        # constructed and cannot be altered by any downstream code.
        features = ImmutableFeatureVector(
            values={
                "lexical": self._lexical_factor(signal.tokens),
                "source": self._source_factor(signal.source),
                "volatility": self._volatility_factor(signal.cardinality_stripped),
                "recurrence": self._recurrence_factor(ctx.recurrence_count),
                "novelty": self._novelty_factor(ctx.seen_signature),
            },
            tags=_FEATURE_ORIGINS,
        )

        # Runtime invariant guard — disabled in production for zero overhead.
        if self._strict:
            _feature_guard(features, ctx)

        if self._debug:
            _log.debug(
                "feature_vector sig=%.16s %s",
                signal.signature,
                " ".join(
                    f"{k}={v:.4f}[{features.tag_of(k)}]" for k, v in features.items()
                ),
            )

        # Scoring formula — unchanged; Mapping.items() is structurally identical to dict.items()
        weighted = sum(_WEIGHTS[name] * value for name, value in features.items())
        risk_score = _clamp(_sigmoid(weighted))
        severity = self._severity_of(risk_score)
        incident_id, similarity = self._cluster(signal, severity, ctx.known_incidents)

        return RiskAssessment(
            signature=signal.signature,
            incident_id=incident_id,
            risk_score=risk_score,
            severity=severity,
            is_anomaly=risk_score >= _ANOMALY_FLOOR,
            factors=self._explain(features, similarity, ctx.recurrence_count),
            summary=self._summary(severity, signal, similarity, ctx.recurrence_count),
        )

    @staticmethod
    def _novelty_factor(seen: bool) -> float:
        # Contract: 1.0 for confirmed recurring threat patterns, 0.0 for first-time observations.
        # When seen=True a prior sighting already exists in the window, confirming the threat.
        # Verified against FeatureContract['novelty'] at startup by _verify_feature_contracts().
        return 1.0 if seen else 0.0

    @staticmethod
    def _lexical_factor(tokens: tuple[str, ...]) -> float:
        hits = sorted(
            (_THREAT_LEXICON[t] for t in tokens if t in _THREAT_LEXICON),
            reverse=True,
        )
        if not hits:
            return 0.0
        return _clamp(hits[0] + sum(hits[1:]) * 0.15)

    @staticmethod
    def _source_factor(source: SourceType) -> float:
        return _SOURCE_PRIOR.get(source, 0.5)

    @staticmethod
    def _volatility_factor(cardinality_stripped: int) -> float:
        return _clamp(1.0 - math.exp(-0.35 * cardinality_stripped))

    @staticmethod
    def _recurrence_factor(count: int) -> float:
        if count <= 1:
            return 0.0
        return _clamp(math.log1p(count - 1) / math.log1p(50))

    @staticmethod
    def _severity_of(risk_score: float) -> Severity:
        for floor, severity in _SEVERITY_THRESHOLDS:
            if risk_score >= floor:
                return severity
        return Severity.LOW

    def _cluster(
        self,
        signal: NormalizedSignal,
        severity: Severity,
        known: tuple[KnownIncident, ...],
    ) -> tuple[str, float]:
        token_set = frozenset(signal.tokens)
        best_id: str | None = None
        best_score = 0.0
        for incident in known:
            score = _jaccard(token_set, incident.tokens)
            # Tiebreak by incident_id lexicographic order so the winner is
            # independent of the order incidents appear in the window (FM-1).
            if score > best_score or (
                score == best_score and incident.incident_id < (best_id or "")
            ):
                best_score, best_id = score, incident.incident_id

        if best_id is not None and best_score >= _CLUSTER_SIMILARITY_THRESHOLD:
            return best_id, round(best_score, 3)
        return self._mint_incident_id(signal.signature, severity), 0.0

    @staticmethod
    def _mint_incident_id(signature: str, severity: Severity) -> str:
        digest = hashlib.sha1(signature.encode("utf-8")).hexdigest()[:6].upper()
        return f"{_INCIDENT_PREFIX[severity]}-{digest}"

    @staticmethod
    def _explain(
        components: Mapping[str, float],   # accepts ImmutableFeatureVector or plain dict
        similarity: float,
        recurrence_count: int,
    ) -> tuple[RiskFactor, ...]:
        details = {
            "lexical": "Weighted threat-keyword density.",
            "source": "Source-type risk prior.",
            "volatility": "High-cardinality noise stripped during normalization.",
            "recurrence": f"Observed {recurrence_count}x in the active window.",
            "novelty": "Confirmed recurring threat pattern in the active window.",
        }
        factors = [
            RiskFactor(name=name, weight=_clamp(value), detail=details[name])
            for name, value in components.items()
            if value > 0.0
        ]
        if similarity > 0.0:
            factors.append(RiskFactor(
                name="cluster_match",
                weight=_clamp(similarity),
                detail="Matched an existing incident cluster.",
            ))
        factors.sort(key=lambda f: f.weight, reverse=True)
        return tuple(factors)

    @staticmethod
    def _summary(
        severity: Severity,
        signal: NormalizedSignal,
        similarity: float,
        recurrence_count: int,
    ) -> str:
        head = signal.normalized_text[:120] or "(empty)"
        cluster = " | recurring cluster" if similarity > 0.0 else ""
        burst = f" | {recurrence_count}x burst" if recurrence_count > 1 else ""
        return f"[{severity.value}] {head}{cluster}{burst}"


# ── Runtime feature guard ─────────────────────────────────────────────────────

def _feature_guard(fv: ImmutableFeatureVector, ctx: ScoringContext) -> None:
    """
    Runtime validation of a computed feature vector against contracts and context.

    Called only when strict=True (or debug=True). Not in the hot path for
    production engines. Raises RuntimeError with a self-explaining message on
    the first violation found.

    Three categories of check:
      1. Bounds — each value must be within its contract's [lo, hi].
      2. Novelty–context consistency — novelty sign must match seen_signature.
      3. Recurrence–context consistency — recurrence sign must match recurrence_count.

    These checks catch two distinct failure modes:
      • Formula regression: the feature method was changed to produce out-of-range
        or semantically wrong values (similar to the June-2026 inversion bug).
      • Context corruption: a wrong ScoringContext was passed to assess(), causing
        the window-derived features to disagree with the context that produced them.
    """
    # 1. Bounds check — every value must lie in [lo, hi] per its contract
    for name, value in fv.items():
        contract = _CONTRACT_BY_NAME.get(name)
        if contract and not (contract.lo <= value <= contract.hi):
            raise RuntimeError(
                f"FeatureGuard: '{name}' value {value:.6f} is outside "
                f"[{contract.lo}, {contract.hi}]\n"
                f"  origin   : {fv.tag_of(name)}\n"
                f"  invariant: {contract.invariant}"
            )

    # 2. Novelty–context consistency
    #    seen_signature=True  → novelty must be positive  (confirms recurring pattern)
    #    seen_signature=False → novelty must be exactly 0.0 (first-time observation)
    novelty = fv["novelty"]
    if ctx.seen_signature and novelty <= 0.0:
        raise RuntimeError(
            f"FeatureGuard: 'novelty'={novelty:.4f} but seen_signature=True — "
            "a confirmed recurring signature must produce positive novelty.\n"
            f"  invariant: {_CONTRACT_BY_NAME['novelty'].invariant}"
        )
    if not ctx.seen_signature and novelty != 0.0:
        raise RuntimeError(
            f"FeatureGuard: 'novelty'={novelty:.4f} but seen_signature=False — "
            "a first-time observation must produce novelty=0.0.\n"
            f"  invariant: {_CONTRACT_BY_NAME['novelty'].invariant}"
        )

    # 3. Recurrence–context consistency
    #    recurrence_count ≤ 1 → recurrence must be 0.0  (no prior window entries)
    #    recurrence_count > 1 → recurrence must be positive (burst detected)
    recurrence = fv["recurrence"]
    if ctx.recurrence_count <= 1 and recurrence != 0.0:
        raise RuntimeError(
            f"FeatureGuard: 'recurrence'={recurrence:.4f} but recurrence_count="
            f"{ctx.recurrence_count} — first occurrence must produce recurrence=0.0.\n"
            f"  invariant: {_CONTRACT_BY_NAME['recurrence'].invariant}"
        )
    if ctx.recurrence_count > 1 and recurrence <= 0.0:
        raise RuntimeError(
            f"FeatureGuard: 'recurrence'={recurrence:.4f} but recurrence_count="
            f"{ctx.recurrence_count} — a burst event must produce positive recurrence.\n"
            f"  invariant: {_CONTRACT_BY_NAME['recurrence'].invariant}"
        )


# ── Feature contract verification (startup) ───────────────────────────────────

def _verify_feature_contracts(engine: RiskEngine) -> None:
    """
    Probe all feature method invariants at startup using synthetic inputs.

    Designed to catch formula inversions (e.g. the June-2026 novelty inversion
    bug) before the engine touches any live data. Raises AssertionError with a
    self-explaining message on the first violated contract.

    Overhead: ~10 method calls — effectively zero compared to any real workload.
    """
    # ── novelty: seen=True must score strictly higher than seen=False ─────────
    seen_val = engine._novelty_factor(seen=True)
    novel_val = engine._novelty_factor(seen=False)
    assert seen_val > novel_val, (
        "FeatureContract VIOLATED — 'novelty'\n"
        f"  invariant : {_CONTRACT_BY_NAME['novelty'].invariant}\n"
        f"  computed  : _novelty_factor(True)={seen_val}  "
        f"_novelty_factor(False)={novel_val}\n"
        "  fix       : _novelty_factor(seen=True) must return a strictly higher "
        "value than _novelty_factor(seen=False)"
    )

    # ── recurrence: must be monotonically non-decreasing with count ───────────
    probe_counts = (1, 2, 5, 10, 20, 50)
    for n in probe_counts:
        lo_val = engine._recurrence_factor(n)
        hi_val = engine._recurrence_factor(n + 1)
        assert hi_val >= lo_val, (
            "FeatureContract VIOLATED — 'recurrence'\n"
            f"  invariant : {_CONTRACT_BY_NAME['recurrence'].invariant}\n"
            f"  computed  : _recurrence_factor({n + 1})={hi_val} "
            f"< _recurrence_factor({n})={lo_val}"
        )

    # ── value bounds: every feature probe must stay in [0.0, 1.0] ─────────────
    probes: list[tuple[float, str]] = [
        (engine._lexical_factor(()), "lexical(empty-tokens)"),
        (engine._lexical_factor(("ransomware", "breach", "exfiltration")), "lexical(max-hits)"),
        (engine._source_factor(SourceType.IAM), "source(IAM)"),
        (engine._source_factor(SourceType.UNKNOWN), "source(UNKNOWN)"),
        (engine._volatility_factor(0), "volatility(0)"),
        (engine._volatility_factor(100), "volatility(100)"),
        (engine._recurrence_factor(0), "recurrence(0)"),
        (engine._recurrence_factor(100), "recurrence(100)"),
        (engine._novelty_factor(False), "novelty(False)"),
        (engine._novelty_factor(True), "novelty(True)"),
    ]
    for val, label in probes:
        feature_name = label.split("(")[0]
        contract = _CONTRACT_BY_NAME.get(feature_name)
        lo_b = contract.lo if contract else 0.0
        hi_b = contract.hi if contract else 1.0
        assert lo_b <= val <= hi_b, (
            f"FeatureContract VIOLATED — '{feature_name}' out of [{lo_b}, {hi_b}]\n"
            f"  probe     : {label} → {val}\n"
            f"  invariant : {contract.invariant if contract else 'value must be in [0,1]'}"
        )


# ── Engine factory ────────────────────────────────────────────────────────────

def build_engine(*, debug: bool | None = None, strict: bool | None = None) -> RiskEngine:
    """
    Construct a RiskEngine and verify all feature contracts before returning it.

    Feature contract verification runs once here — before the engine touches
    live data — so any formula inversion is caught at startup rather than
    silently producing wrong scores.

    debug=None   → reads SENTINEL_DEBUG env var ("1" enables debug logging + guard)
    debug=True   → always enable debug feature-vector logging and runtime guard
    debug=False  → always disable debug logging (guard follows strict flag)
    strict=None  → reads SENTINEL_STRICT_MODE env var ("1" enables runtime guard only)
    strict=True  → always enable runtime FeatureGuard on every assess() call
    strict=False → always disable (unless debug=True, which implies strict)
    """
    _debug = (os.getenv("SENTINEL_DEBUG") == "1") if debug is None else debug
    _strict = (os.getenv("SENTINEL_STRICT_MODE") == "1") if strict is None else strict
    engine = RiskEngine(debug=_debug, strict=_strict)
    _verify_feature_contracts(engine)
    return engine
