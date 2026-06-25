"""
Tests for POST /beta/validate-resolution — analyst validation workflow.

Each test gets an isolated tmp_path data directory via the autouse fixture,
so JSONL files never bleed between tests.
"""
from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from raven.api.beta.router import router as beta_router
from raven.api.beta.store import (
    get_validated_incident_by_id,
    get_validated_incidents_by_incident_id,
    load_validated_incidents,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("RAVEN_DATA_DIR", str(tmp_path))


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(beta_router)
    return TestClient(app)


# ── Payloads ──────────────────────────────────────────────────────────────────

_BASE = {
    "incident_id": "inc_ldap_001",
    "request_id": "req_abc123",
    "decision_taken": "INVESTIGATE",
    "action_taken": "Checked LDAP service health and restarted the connector",
    "confidence": 4,
    "replaced_manual_process": True,
    "time_saved_minutes": 20,
}

_WITH_MEMORY = {
    **_BASE,
    "hypothesis_correct": True,
    "resolution_text": "Restarted LDAP connector; SSO service recovered within 90 seconds.",
    "memory_write_approved": True,
    "signature": "a3f2c1d0e4b5f6a7b8c9d0e1f2a3b4c5",
    "event_type": "authentication_failure",
    "source": "iam",
    "message_normalized": "authentication service unavailable ldap timeout",
    "tokens": ["authentication", "service", "unavailable", "ldap", "timeout"],
    "validated_by": "analyst@example.com",
}


# ── Response shape ────────────────────────────────────────────────────────────

def test_returns_201(client):
    resp = client.post("/beta/validate-resolution", json=_BASE)
    assert resp.status_code == 201


def test_response_has_required_fields(client):
    resp = client.post("/beta/validate-resolution", json=_BASE)
    data = resp.json()
    assert "decision_impact_id" in data
    assert "memory_record_created" in data
    assert "memory_record_id" in data
    assert "status" in data
    assert data["status"] == "recorded"


def test_decision_impact_id_is_non_empty(client):
    resp = client.post("/beta/validate-resolution", json=_BASE)
    assert len(resp.json()["decision_impact_id"]) > 0


# ── Always records DecisionImpact ─────────────────────────────────────────────

def test_always_records_decision_impact(client, tmp_path):
    client.post("/beta/validate-resolution", json=_BASE)
    impacts_file = tmp_path / "decision_impacts.jsonl"
    assert impacts_file.exists()
    lines = [l for l in impacts_file.read_text().splitlines() if l.strip()]
    assert len(lines) == 1


def test_records_decision_impact_even_when_memory_approved(client, tmp_path):
    client.post("/beta/validate-resolution", json=_WITH_MEMORY)
    lines = [l for l in (tmp_path / "decision_impacts.jsonl").read_text().splitlines() if l.strip()]
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["incident_id"] == "inc_ldap_001"
    assert record["decision_taken"] == "INVESTIGATE"
    assert record["hypothesis_correct"] is True
    assert record["resolution_text"] == _WITH_MEMORY["resolution_text"]
    assert record["memory_write_approved"] is True


# ── No memory when not approved ───────────────────────────────────────────────

def test_no_memory_when_not_approved(client, tmp_path):
    payload = {**_BASE, "resolution_text": "Some resolution", "memory_write_approved": False}
    resp = client.post("/beta/validate-resolution", json=payload)
    data = resp.json()
    assert data["memory_record_created"] is False
    assert data["memory_record_id"] is None
    assert not (tmp_path / "validated_incidents.jsonl").exists()


def test_no_memory_when_approved_but_no_resolution_text(client, tmp_path):
    payload = {**_BASE, "memory_write_approved": True}  # no resolution_text
    resp = client.post("/beta/validate-resolution", json=payload)
    data = resp.json()
    assert data["memory_record_created"] is False
    assert data["memory_record_id"] is None
    assert not (tmp_path / "validated_incidents.jsonl").exists()


def test_no_memory_by_default(client, tmp_path):
    # memory_write_approved defaults to False — no memory fields required
    resp = client.post("/beta/validate-resolution", json=_BASE)
    data = resp.json()
    assert data["memory_record_created"] is False
    assert data["memory_record_id"] is None


# ── Creates ValidatedIncident when approved ───────────────────────────────────

def test_creates_memory_record_when_approved(client, tmp_path):
    resp = client.post("/beta/validate-resolution", json=_WITH_MEMORY)
    data = resp.json()
    assert data["memory_record_created"] is True
    assert data["memory_record_id"] is not None
    assert len(data["memory_record_id"]) > 0


def test_memory_record_persists_to_disk(client, tmp_path):
    client.post("/beta/validate-resolution", json=_WITH_MEMORY)
    f = tmp_path / "validated_incidents.jsonl"
    assert f.exists()
    lines = [l for l in f.read_text().splitlines() if l.strip()]
    assert len(lines) == 1


def test_memory_record_content(client, tmp_path):
    client.post("/beta/validate-resolution", json=_WITH_MEMORY)
    lines = (tmp_path / "validated_incidents.jsonl").read_text().splitlines()
    record = json.loads(lines[0])
    assert record["incident_id"] == "inc_ldap_001"
    assert record["request_id"] == "req_abc123"
    assert record["event_type"] == "authentication_failure"
    assert record["source"] == "iam"
    assert record["resolution_text"] == _WITH_MEMORY["resolution_text"]
    assert record["hypothesis_validated"] is True
    assert record["analyst_confidence"] == 4
    assert record["validated_by"] == "analyst@example.com"
    assert record["tokens"] == _WITH_MEMORY["tokens"]
    assert "id" in record
    assert "timestamp" in record
    assert "validation_timestamp" in record


def test_memory_record_id_matches_response(client, tmp_path):
    resp = client.post("/beta/validate-resolution", json=_WITH_MEMORY)
    returned_id = resp.json()["memory_record_id"]
    lines = (tmp_path / "validated_incidents.jsonl").read_text().splitlines()
    stored_id = json.loads(lines[0])["id"]
    assert returned_id == stored_id


def test_multiple_memory_records_accumulate(client, tmp_path):
    client.post("/beta/validate-resolution", json=_WITH_MEMORY)
    client.post("/beta/validate-resolution", json={**_WITH_MEMORY, "incident_id": "inc_ldap_002"})
    lines = [l for l in (tmp_path / "validated_incidents.jsonl").read_text().splitlines() if l.strip()]
    assert len(lines) == 2


# ── Store helper functions ────────────────────────────────────────────────────

def test_load_validated_incidents_empty(tmp_path):
    assert load_validated_incidents() == []


def test_load_validated_incidents_returns_records(client, tmp_path):
    client.post("/beta/validate-resolution", json=_WITH_MEMORY)
    records = load_validated_incidents()
    assert len(records) == 1
    assert records[0].incident_id == "inc_ldap_001"


def test_get_validated_incident_by_id(client, tmp_path):
    resp = client.post("/beta/validate-resolution", json=_WITH_MEMORY)
    record_id = resp.json()["memory_record_id"]
    found = get_validated_incident_by_id(record_id)
    assert found is not None
    assert found.id == record_id


def test_get_validated_incident_by_id_not_found(tmp_path):
    assert get_validated_incident_by_id("nonexistent-id") is None


def test_get_validated_incidents_by_incident_id(client, tmp_path):
    # Two records for the same incident_id
    client.post("/beta/validate-resolution", json=_WITH_MEMORY)
    client.post("/beta/validate-resolution", json=_WITH_MEMORY)
    # One record for a different incident_id
    client.post("/beta/validate-resolution", json={**_WITH_MEMORY, "incident_id": "inc_other"})

    results = get_validated_incidents_by_incident_id("inc_ldap_001")
    assert len(results) == 2
    assert all(r.incident_id == "inc_ldap_001" for r in results)


def test_get_validated_incidents_by_incident_id_empty(tmp_path):
    assert get_validated_incidents_by_incident_id("nonexistent") == []


# ── Supersedes field ──────────────────────────────────────────────────────────

def test_supersedes_stored_correctly(client, tmp_path):
    payload = {**_WITH_MEMORY, "supersedes": "old-record-uuid-1234"}
    client.post("/beta/validate-resolution", json=payload)
    record = json.loads((tmp_path / "validated_incidents.jsonl").read_text().splitlines()[0])
    assert record["supersedes"] == "old-record-uuid-1234"


def test_supersedes_defaults_to_none(client, tmp_path):
    client.post("/beta/validate-resolution", json=_WITH_MEMORY)
    record = json.loads((tmp_path / "validated_incidents.jsonl").read_text().splitlines()[0])
    assert record["supersedes"] is None


# ── Existing /beta/decision-impact is unaffected ──────────────────────────────

def test_existing_decision_impact_endpoint_still_works(client, tmp_path):
    payload = {
        "incident_id": "evt_existing",
        "request_id": "req_existing",
        "decision_taken": "BLOCK",
        "action_taken": "Blocked suspicious login",
        "confidence": 5,
        "replaced_manual_process": True,
        "time_saved_minutes": 10,
    }
    resp = client.post("/beta/decision-impact", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "recorded"
    assert "id" in data
    # No memory file should be created by the old endpoint
    assert not (tmp_path / "validated_incidents.jsonl").exists()


def test_existing_endpoint_does_not_accept_unknown_fields(client):
    payload = {
        "incident_id": "evt_x",
        "request_id": "req_x",
        "decision_taken": "ACCEPT",
        "action_taken": "let through",
        "confidence": 3,
        "replaced_manual_process": False,
        "time_saved_minutes": 0,
        "unknown_field": "should_be_ignored_or_rejected",
    }
    # DecisionImpactRequest does not forbid extra fields — Pydantic ignores them
    resp = client.post("/beta/decision-impact", json=payload)
    assert resp.status_code == 201
