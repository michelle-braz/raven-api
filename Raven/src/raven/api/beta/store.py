from __future__ import annotations

import json
import os
from pathlib import Path

from .models import DecisionImpact, ValidatedIncident


def _data_dir() -> Path:
    d = Path(os.getenv("RAVEN_DATA_DIR", "data"))
    d.mkdir(parents=True, exist_ok=True)
    return d


# ── Analyze call tracking ─────────────────────────────────────────────────────

def record_analyze_call(incident_id: str, request_id: str) -> None:
    f = _data_dir() / "analyze_calls.jsonl"
    with f.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"incident_id": incident_id, "request_id": request_id}) + "\n")


def count_analyze_calls() -> int:
    f = _data_dir() / "analyze_calls.jsonl"
    if not f.exists():
        return 0
    with f.open("r", encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


# ── Decision impact persistence ───────────────────────────────────────────────

def append_impact(impact: DecisionImpact) -> None:
    f = _data_dir() / "decision_impacts.jsonl"
    with f.open("a", encoding="utf-8") as fh:
        fh.write(impact.model_dump_json() + "\n")


def load_impacts() -> list[DecisionImpact]:
    f = _data_dir() / "decision_impacts.jsonl"
    if not f.exists():
        return []
    results: list[DecisionImpact] = []
    with f.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                results.append(DecisionImpact.model_validate_json(line))
    return results


# ── Validated incident memory persistence ─────────────────────────────────────

def append_validated_incident(record: ValidatedIncident) -> None:
    f = _data_dir() / "validated_incidents.jsonl"
    with f.open("a", encoding="utf-8") as fh:
        fh.write(record.model_dump_json() + "\n")


def load_validated_incidents() -> list[ValidatedIncident]:
    f = _data_dir() / "validated_incidents.jsonl"
    if not f.exists():
        return []
    results: list[ValidatedIncident] = []
    with f.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                results.append(ValidatedIncident.model_validate_json(line))
    return results


def get_validated_incident_by_id(record_id: str) -> ValidatedIncident | None:
    for record in load_validated_incidents():
        if record.id == record_id:
            return record
    return None


def get_validated_incidents_by_incident_id(incident_id: str) -> list[ValidatedIncident]:
    return [r for r in load_validated_incidents() if r.incident_id == incident_id]
