"""
Minimal test runner — executes tests/test_smoke.py without pytest.
Usage: python run_tests.py
"""
import sys
import traceback

sys.path.insert(0, "src")

from tests.test_smoke import (
    test_normalization_dedupe,
    test_scoring_monotonicity,
    test_pipeline,
)

TESTS = [
    test_normalization_dedupe,
    test_scoring_monotonicity,
    test_pipeline,
]

passed = 0
failed = 0

for fn in TESTS:
    try:
        fn()
        print(f"  PASS  {fn.__name__}")
        passed += 1
    except Exception as exc:
        print(f"  FAIL  {fn.__name__}")
        traceback.print_exc()
        failed += 1

print(f"\n{'='*40}")
print(f"  {passed} passed, {failed} failed")
print(f"{'='*40}")

sys.exit(1 if failed else 0)
