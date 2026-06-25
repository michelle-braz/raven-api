from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Event:
    user_id: int | str | None
    action: str
    ip: str | None
    attempts: int
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskResult:
    risk_score: int
    level: str
    signals: list[str] = field(default_factory=list)
    raw_event: dict[str, Any] = field(default_factory=dict)
