"""End-to-end smoke tests for the Sentinel 4-layer pipeline."""

from __future__ import annotations

import asyncio

from raven.sentinel.pipeline.data_layer.schemas import IngestionBatch, RawEvent, Severity, SourceType
from raven.sentinel.pipeline.signal_layer.normalizer import normalize
from raven.sentinel.pipeline.intelligence_layer.engine import build_engine
from raven.sentinel.pipeline.app import IngestionPipeline, SignalWindow
from raven.sentinel.pipeline.action_layer.notifier import ActionDispatcher, LogChannel


def test_normalization_dedupe() -> None:
    a = RawEvent(message="connection timeout from 10.0.0.4:5432 at 2026-06-14T10:00:00Z")
    b = RawEvent(message="connection timeout from 192.168.1.9:6000 at 2026-06-15T22:31:11Z")
    sa, sb = normalize(a), normalize(b)
    assert sa.signature == sb.signature, "volatile data should not change signature"
    assert sa.cardinality_stripped >= 2


def test_scoring_monotonicity() -> None:
    engine = build_engine()
    info = engine.assess(normalize(RawEvent(message="user login successful")))
    crit = engine.assess(
        normalize(
            RawEvent(
                message="unauthorized privilege escalation breach detected",
                source=SourceType.IAM,
            )
        )
    )
    assert 0.0 <= info.risk_score <= 1.0 and 0.0 <= crit.risk_score <= 1.0
    assert crit.risk_score > info.risk_score
    assert crit.severity.rank > info.severity.rank


def test_pipeline() -> None:
    asyncio.run(_run_pipeline())


async def _run_pipeline() -> None:
    pipeline = IngestionPipeline(
        engine=build_engine(),
        dispatcher=ActionDispatcher([LogChannel(min_severity=Severity.LOW)]),
        window=SignalWindow(),
    )
    batch = IngestionBatch(
        events=[
            RawEvent(message="ransomware exfiltration detected on host db-1", source=SourceType.NETWORK),
            RawEvent(message="ransomware exfiltration detected on host db-2", source=SourceType.NETWORK),
            RawEvent(message="api response slow under load"),
        ]
    )
    result = await pipeline.process_batch(batch)
    assert result.accepted == 3
    assert result.actions_dispatched >= 1
    assert result.assessments[0].incident_id == result.assessments[1].incident_id
    assert result.assessments[1].risk_score >= result.assessments[0].risk_score
