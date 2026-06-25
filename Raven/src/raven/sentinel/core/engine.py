from __future__ import annotations

from typing import Any

from raven.sentinel.core.models import Event, RiskResult
from raven.sentinel.core.rules import RULES


def _normalize(raw: dict[str, Any]) -> Event:
    return Event(
        user_id=raw.get("user_id"),
        action=str(raw.get("action", "")).strip().lower(),
        ip=raw.get("ip") if isinstance(raw.get("ip"), str) else None,
        attempts=max(int(raw.get("attempts", 0)), 0),
        raw=raw,
    )


def _level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def evaluate(raw: dict[str, Any]) -> dict[str, Any]:
    event = _normalize(raw)

    total = 0
    signals: list[str] = []

    for rule in RULES:
        delta, signal = rule(event)
        total += delta
        if signal is not None:
            signals.append(signal)

    score = min(total, 100)
    result = RiskResult(
        risk_score=score,
        level=_level(score),
        signals=signals,
        raw_event=raw,
    )

    return {
        "risk_score": result.risk_score,
        "level": result.level,
        "signals": result.signals,
        "raw_event": result.raw_event,
    }
