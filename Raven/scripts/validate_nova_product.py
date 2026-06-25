"""NOVA Product Validation Script — run: python scripts/validate_nova_product.py"""
from __future__ import annotations

import sys
from typing import Any

from raven.sentinel.core.engine import evaluate

PASS = "PASS"
FAIL = "FAIL"


def check(label: str, condition: bool) -> bool:
    status = PASS if condition else FAIL
    print(f"  [{status}]  {label}")
    return condition


def run_scenario(
    name: str,
    event: dict[str, Any],
    assertions: list[tuple[str, bool]],
) -> bool:
    print(f"\n{'='*55}")
    print(f"  {name}")
    print(f"{'='*55}")

    result = evaluate(event)

    print(f"  risk_score : {result['risk_score']}")
    print(f"  level      : {result['level']}")
    print(f"  signals    : {result['signals']}")
    print()

    results = [check(label, condition) for label, condition in assertions]
    return all(results)


def main() -> None:
    passed: list[bool] = []

    # Scenario 1: Fraud-like behavior — attempts=7, login_failed, suspicious IP
    # Score: attempts>=3 (+40) + login_failed (+30) + unknown_ip (+10) = 80 → HIGH
    event_1 = {"user_id": "user_001", "action": "login_failed", "ip": "192.168.1.1", "attempts": 7}
    result_1 = evaluate(event_1)
    passed.append(run_scenario(
        "Scenario 1 — Fraud-like behavior (HIGH RISK)",
        event_1,
        [
            ("level is HIGH", result_1["level"] == "HIGH"),
            ("risk_score > 70", result_1["risk_score"] > 70),
            ("multiple signals triggered", len(result_1["signals"]) >= 2),
        ],
    ))

    # Scenario 2: Normal user behavior — page_view, clean IP, 0 attempts → score 0 = LOW
    event_2 = {"user_id": "user_002", "action": "page_view", "ip": "8.8.8.8", "attempts": 0}
    result_2 = evaluate(event_2)
    passed.append(run_scenario(
        "Scenario 2 — Normal user behavior (LOW RISK)",
        event_2,
        [
            ("level is LOW", result_2["level"] == "LOW"),
            ("risk_score < 40", result_2["risk_score"] < 40),
            ("no signals triggered", len(result_2["signals"]) == 0),
        ],
    ))

    # Scenario 3: login_failed (+30), attempts=1 (below threshold), clean IP → score 30 = LOW
    event_3 = {"user_id": "user_003", "action": "login_failed", "ip": "8.8.8.8", "attempts": 1}
    result_3 = evaluate(event_3)
    passed.append(run_scenario(
        "Scenario 3 — Suspicious but not critical (LOW RISK)",
        event_3,
        [
            ("level is LOW", result_3["level"] == "LOW"),
            ("risk_score is 30", result_3["risk_score"] == 30),
            ("at least one signal triggered", len(result_3["signals"]) >= 1),
        ],
    ))

    total = len(passed)
    ok = sum(passed)
    print(f"\n{'='*55}")
    print(f"  RESULTS: {ok}/{total} scenarios passed")
    print(f"{'='*55}\n")

    sys.exit(0 if all(passed) else 1)


if __name__ == "__main__":
    main()
