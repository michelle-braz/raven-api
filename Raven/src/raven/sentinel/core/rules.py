from __future__ import annotations

from collections.abc import Callable

from raven.sentinel.core.models import Event

_UNKNOWN_IPS: frozenset[str] = frozenset({"10.0.0.1", "192.168.1.1"})

RuleFn = Callable[[Event], tuple[int, str | None]]


def _rule_attempts(event: Event) -> tuple[int, str | None]:
    if event.attempts >= 3:
        return 40, "attempts>=3"
    return 0, None


def _rule_login_failed(event: Event) -> tuple[int, str | None]:
    if event.action == "login_failed":
        return 30, "action=login_failed"
    return 0, None


def _rule_unknown_ip(event: Event) -> tuple[int, str | None]:
    if event.ip and event.ip in _UNKNOWN_IPS:
        return 10, "unknown_ip"
    return 0, None


RULES: tuple[RuleFn, ...] = (
    _rule_attempts,
    _rule_login_failed,
    _rule_unknown_ip,
)
