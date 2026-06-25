"""
Layer 2 — Signal Layer (Normalization & Noise Reduction)
========================================================
Turns a noisy `RawEvent` into a deterministic `NormalizedSignal`.

Two jobs, both pure and stateless:

  1. **Noise reduction** — strip high-cardinality dynamic data (IPs, UUIDs,
     hashes, hex blobs, timestamps, emails, numbers, paths) so that two
     semantically identical events collapse to the same shape regardless of
     their volatile particulars.

  2. **Signature & tokenization** — emit a stable SHA-256 content signature
     (the deduplication key) and a normalized token set (the unit the
     Intelligence Layer reasons over).

The regex order matters: broad/structured patterns (UUID, IP) run before
the catch-all number scrub so we don't shred them into fragments first.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from raven.sentinel.pipeline.data_layer.schemas import RawEvent, SourceType

# ── Placeholder tokens ───────────────────────────────────────────────────────
_PLACEHOLDERS = {
    "uuid": "<uuid>",
    "ip": "<ip>",
    "hash": "<hash>",
    "hex": "<hex>",
    "email": "<email>",
    "path": "<path>",
    "ts": "<ts>",
    "num": "<num>",
}

# Order is significant — see module docstring.
_SCRUBBERS: tuple[tuple[re.Pattern[str], str], ...] = (
    # ISO-8601 / RFC3339 timestamps
    (re.compile(r"\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:?\d{2})?", re.I), _PLACEHOLDERS["ts"]),
    # UUIDs
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), _PLACEHOLDERS["uuid"]),
    # Emails
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), _PLACEHOLDERS["email"]),
    # IPv4 (optionally with port) and IPv6
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), _PLACEHOLDERS["ip"]),
    (re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b", re.I), _PLACEHOLDERS["ip"]),
    # Long hashes (md5/sha-ish): 32+ hex chars
    (re.compile(r"\b[0-9a-f]{32,}\b", re.I), _PLACEHOLDERS["hash"]),
    # 0x hex blobs and shorter hex tokens (>=6)
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), _PLACEHOLDERS["hex"]),
    (re.compile(r"\b[0-9a-f]{6,}\b", re.I), _PLACEHOLDERS["hex"]),
    # Filesystem / URL-ish paths
    (re.compile(r"(?:[a-z]:)?(?:/[\w.+-]+){2,}/?", re.I), _PLACEHOLDERS["path"]),
    # Any remaining standalone numbers (ports, counts, pids, durations)
    (re.compile(r"\b\d+\b"), _PLACEHOLDERS["num"]),
)

# Token extraction over the *scrubbed* text. Placeholders survive as <type>.
_TOKEN_RE = re.compile(r"<[a-z]+>|[a-z][a-z]+")

_STOPWORDS: frozenset[str] = frozenset({
    "a", "an", "the", "on", "in", "at", "to", "for", "of", "and", "or",
    "is", "are", "was", "were", "be", "been", "being", "has", "have", "had",
    "do", "does", "did", "will", "would", "should", "could", "may", "might",
    "must", "shall", "can", "with", "by", "from", "after", "before", "under",
    "over", "about", "its", "it", "this", "that", "no", "not", "as", "but",
})

_SIGNATURE_NAMESPACE = "sentinel.signal.v1"


@dataclass(frozen=True, slots=True)
class NormalizedSignal:
    """Deterministic, noise-reduced representation of an event."""

    signature: str
    normalized_text: str
    tokens: tuple[str, ...]
    source: SourceType
    cardinality_stripped: int


def _scrub(message: str) -> tuple[str, int]:
    text = message.lower()
    stripped = 0
    for pattern, placeholder in _SCRUBBERS:
        text, count = pattern.subn(placeholder, text)
        stripped += count
    return re.sub(r"\s+", " ", text).strip(), stripped


def _tokenize(scrubbed: str) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for tok in _TOKEN_RE.findall(scrubbed):
        if tok in _STOPWORDS or len(tok) < 2:
            continue
        if tok not in seen:
            seen.add(tok)
            ordered.append(tok)
    return tuple(ordered)


def _signature(source: SourceType, tokens: tuple[str, ...]) -> str:
    canonical = f"{_SIGNATURE_NAMESPACE}|{source.value}|" + "|".join(sorted(tokens))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def normalize(event: RawEvent) -> NormalizedSignal:
    """Pure transform: RawEvent → NormalizedSignal."""
    scrubbed, stripped = _scrub(event.message)
    tokens = _tokenize(scrubbed)
    return NormalizedSignal(
        signature=_signature(event.source, tokens),
        normalized_text=scrubbed,
        tokens=tokens,
        source=event.source,
        cardinality_stripped=stripped,
    )
