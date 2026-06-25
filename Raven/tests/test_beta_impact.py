"""
Tests for the Decision Impact Validation Layer.

Each test gets an isolated tmp_path data directory via the autouse fixture,
so JSONL files never bleed between tests.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from raven.api.beta.router import router as beta_router
from raven.api.beta.store import record_analyze_call


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    """Point RAVEN_DATA_DIR at a fresh tmp directory for every test."""
    monkeypatch.setenv("RAVEN_DATA_DIR", str(tmp_path))


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(beta_router)
    return TestClient(app)


# ── Helpers ───────────────────────────────────────────────────────────────────

_BASE_IMPACT = {
    "incident_id": "evt_abc123",
    "request_id": "req_xyz789",
    "decision_taken": "BLOCK",
    "action_taken": "Blocked suspicious login",
    "confidence": 5,
    "replaced_manual_process": True,
    "time_saved_minutes": 20,
}


# ── Endpoint: POST /beta/decision-impact ─────────────────────────────────────

def test_submit_decision_impact_returns_201(client):
    resp = client.post("/beta/decision-impact", json=_BASE_IMPACT)
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "recorded"
    assert "id" in data and len(data["id"]) > 0


def test_submit_persists_to_disk(client, tmp_path):
    client.post("/beta/decision-impact", json=_BASE_IMPACT)
    impacts_file = tmp_path / "decision_impacts.jsonl"
    assert impacts_file.exists()
    lines = [l for l in impacts_file.read_text().splitlines() if l.strip()]
    assert len(lines) == 1


def test_submit_optional_comments(client):
    payload = {**_BASE_IMPACT, "comments": "Would normally take 30 min of manual review"}
    resp = client.post("/beta/decision-impact", json=payload)
    assert resp.status_code == 201


def test_submit_rejects_invalid_confidence(client):
    resp = client.post("/beta/decision-impact", json={**_BASE_IMPACT, "confidence": 6})
    assert resp.status_code == 422


def test_submit_rejects_negative_time_saved(client):
    resp = client.post("/beta/decision-impact", json={**_BASE_IMPACT, "time_saved_minutes": -1})
    assert resp.status_code == 422


def test_submit_all_decision_taken_values(client):
    for value in ("ACCEPT", "REVIEW", "BLOCK", "IGNORE", "INVESTIGATE", "OTHER"):
        resp = client.post("/beta/decision-impact", json={**_BASE_IMPACT, "decision_taken": value})
        assert resp.status_code == 201, f"Failed for decision_taken={value}"


# ── Endpoint: GET /beta/impact-summary ───────────────────────────────────────

def test_impact_summary_empty_state(client):
    resp = client.get("/beta/impact-summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_analyze_calls"] == 0
    assert data["total_decision_reports"] == 0
    assert data["decision_influence_rate"] == 0.0
    assert data["manual_process_replacement_rate"] == 0.0
    assert data["average_time_saved_minutes"] == 0
    assert data["average_confidence"] == 0
    assert data["decision_breakdown"] == {}
    assert data["top_actions"] == []


def test_impact_summary_aggregates_correctly(client):
    # Report 1: BLOCK, replaced manual, 10 min, confidence 4
    client.post("/beta/decision-impact", json={
        **_BASE_IMPACT,
        "decision_taken": "BLOCK",
        "replaced_manual_process": True,
        "time_saved_minutes": 10,
        "confidence": 4,
        "action_taken": "Blocked user",
    })
    # Report 2: ACCEPT (accepted RAVEN's low-risk verdict), no manual replacement, 5 min, confidence 4
    client.post("/beta/decision-impact", json={
        **_BASE_IMPACT,
        "incident_id": "evt_2",
        "request_id": "req_2",
        "decision_taken": "ACCEPT",
        "replaced_manual_process": False,
        "time_saved_minutes": 5,
        "confidence": 4,
        "action_taken": "Let through",
    })

    resp = client.get("/beta/impact-summary")
    assert resp.status_code == 200
    data = resp.json()

    assert data["total_decision_reports"] == 2
    assert data["manual_process_replacement_rate"] == 0.5
    assert data["average_time_saved_minutes"] == 7.5
    assert data["average_confidence"] == 4.0
    assert data["decision_breakdown"] == {"BLOCK": 1, "ACCEPT": 1}


def test_impact_summary_counts_analyze_calls(client):
    record_analyze_call("evt_a", "req_a")
    record_analyze_call("evt_b", "req_b")

    resp = client.get("/beta/impact-summary")
    assert resp.json()["total_analyze_calls"] == 2


def test_decision_influence_rate(client):
    record_analyze_call("evt_a", "req_a")
    record_analyze_call("evt_b", "req_b")
    client.post("/beta/decision-impact", json=_BASE_IMPACT)

    data = client.get("/beta/impact-summary").json()
    assert data["total_analyze_calls"] == 2
    assert data["total_decision_reports"] == 1
    assert data["decision_influence_rate"] == 0.5


def test_top_actions_ordering(client):
    for _ in range(3):
        client.post("/beta/decision-impact", json={**_BASE_IMPACT, "action_taken": "common action"})
    client.post("/beta/decision-impact", json={**_BASE_IMPACT, "action_taken": "rare action"})

    data = client.get("/beta/impact-summary").json()
    assert data["top_actions"][0] == "common action"
    assert "rare action" in data["top_actions"]


# ── Endpoint: GET /beta/business-proof ───────────────────────────────────────

def test_business_proof_no_evidence(client):
    resp = client.get("/beta/business-proof")
    assert resp.status_code == 200
    data = resp.json()
    assert data["validation_status"] == "NO_EVIDENCE"
    assert data["recommendation"] == "Find more testers"
    assert data["total_decisions_influenced"] == 0
    assert data["estimated_total_minutes_saved"] == 0


def test_business_proof_aggregates(client):
    for i in range(3):
        client.post("/beta/decision-impact", json={
            **_BASE_IMPACT,
            "incident_id": f"evt_{i}",
            "replaced_manual_process": True,
            "time_saved_minutes": 10,
        })

    data = client.get("/beta/business-proof").json()
    assert data["total_decisions_influenced"] == 3
    assert data["estimated_total_minutes_saved"] == 30
    assert data["manual_processes_replaced"] == 3


# ── Validation status progression ────────────────────────────────────────────

@pytest.mark.parametrize("count,expected_status", [
    (0,  "NO_EVIDENCE"),
    (1,  "EARLY_SIGNAL"),
    (4,  "EARLY_SIGNAL"),
    (5,  "VALIDATING"),
    (19, "VALIDATING"),
    (20, "REAL_WORLD_VALUE"),
    (50, "REAL_WORLD_VALUE"),
])
def test_validation_status_thresholds(client, count, expected_status):
    for i in range(count):
        client.post("/beta/decision-impact", json={
            **_BASE_IMPACT,
            "incident_id": f"evt_{i}",
            "request_id": f"req_{i}",
        })
    data = client.get("/beta/business-proof").json()
    assert data["validation_status"] == expected_status, (
        f"count={count}: expected {expected_status}, got {data['validation_status']}"
    )


@pytest.mark.parametrize("status,recommendation", [
    ("NO_EVIDENCE",      "Find more testers"),
    ("EARLY_SIGNAL",     "Collect more feedback"),
    ("VALIDATING",       "Refine product using feedback"),
    ("REAL_WORLD_VALUE", "Prepare paid beta"),
])
def test_recommendations_match_status(client, status, recommendation):
    counts = {"NO_EVIDENCE": 0, "EARLY_SIGNAL": 1, "VALIDATING": 5, "REAL_WORLD_VALUE": 20}
    for i in range(counts[status]):
        client.post("/beta/decision-impact", json={
            **_BASE_IMPACT,
            "incident_id": f"evt_{i}",
            "request_id": f"req_{i}",
        })
    data = client.get("/beta/business-proof").json()
    assert data["recommendation"] == recommendation
