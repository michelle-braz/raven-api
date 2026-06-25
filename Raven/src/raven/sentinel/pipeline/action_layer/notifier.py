"""
Layer 4 — Action Layer (Orchestration & Automation Hooks)
=========================================================
Asynchronously dispatches automation when an assessment breaks a configured
risk threshold. Pluggable channel system: each channel implements the
ActionChannel protocol. Channels fire concurrently via asyncio.gather.
One channel failing never blocks others — failures are captured as
ActionOutcome(status=FAILED) and returned, never raised.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Protocol, runtime_checkable

import httpx

from raven.sentinel.pipeline.data_layer.schemas import (
    ActionOutcome,
    ActionStatus,
    RawEvent,
    RiskAssessment,
    Severity,
    to_envelope,
)

logger = logging.getLogger("sentinel.action")


@runtime_checkable
class ActionChannel(Protocol):
    name: str
    min_severity: Severity

    async def deliver(
        self, assessment: RiskAssessment, event: RawEvent
    ) -> ActionOutcome: ...


class WebhookChannel:
    """Generic outbound webhook — POSTs the transport-neutral envelope as JSON."""

    def __init__(
        self,
        *,
        name: str,
        url: str,
        client: httpx.AsyncClient,
        min_severity: Severity = Severity.HIGH,
        timeout: float = 5.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.name = name
        self.url = url
        self.min_severity = min_severity
        self._client = client
        self._timeout = timeout
        self._headers = headers or {}

    async def deliver(
        self, assessment: RiskAssessment, event: RawEvent
    ) -> ActionOutcome:
        payload = to_envelope(assessment, event)
        try:
            response = await self._client.post(
                self.url,
                json=payload,
                headers=self._headers,
                timeout=self._timeout,
            )
            response.raise_for_status()
            return ActionOutcome(
                channel=self.name,
                status=ActionStatus.DISPATCHED,
                detail=f"HTTP {response.status_code}",
            )
        except httpx.HTTPError as exc:
            logger.warning("Webhook '%s' failed: %s", self.name, exc)
            return ActionOutcome(channel=self.name, status=ActionStatus.FAILED, detail=str(exc))


class LogChannel:
    """Always-on structured-log sink."""

    def __init__(self, *, min_severity: Severity = Severity.MEDIUM) -> None:
        self.name = "structured-log"
        self.min_severity = min_severity

    async def deliver(
        self, assessment: RiskAssessment, event: RawEvent
    ) -> ActionOutcome:
        logger.info(
            "risk.alert incident=%s severity=%s score=%.4f host=%s",
            assessment.incident_id,
            assessment.severity.value,
            assessment.risk_score,
            event.host,
        )
        return ActionOutcome(channel=self.name, status=ActionStatus.DISPATCHED)


class ActionDispatcher:
    """Threshold-aware fan-out over registered channels."""

    def __init__(self, channels: list[ActionChannel] | None = None) -> None:
        # Tuple prevents accidental mid-iteration mutation during dispatch (FM-5).
        self._channels: tuple[ActionChannel, ...] = tuple(channels or [])

    def register(self, channel: ActionChannel) -> None:
        self._channels = (*self._channels, channel)

    @staticmethod
    def _eligible(channel: ActionChannel, assessment: RiskAssessment) -> bool:
        return assessment.severity.rank >= channel.min_severity.rank

    async def dispatch(
        self, assessment: RiskAssessment, event: RawEvent
    ) -> tuple[ActionOutcome, ...]:
        eligible = [c for c in self._channels if self._eligible(c, assessment)]
        if not eligible:
            return ()

        results = await asyncio.gather(
            *(c.deliver(assessment, event) for c in eligible),
            return_exceptions=True,
        )

        outcomes: list[ActionOutcome] = []
        for channel, result in zip(eligible, results):
            if isinstance(result, ActionOutcome):
                outcomes.append(result)
            else:
                logger.error("Channel '%s' raised: %s", channel.name, result)
                outcomes.append(ActionOutcome(
                    channel=channel.name,
                    status=ActionStatus.FAILED,
                    detail=repr(result),
                ))
        return tuple(outcomes)
