from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from enum import Enum, auto
from typing import Generic, TypeVar

T = TypeVar("T")


class BackpressurePolicy(Enum):
    BLOCK = auto()        # await until capacity frees
    DROP_NEWEST = auto()  # reject incoming; keep existing


class BufferFull(Exception):
    """Raised by put_nowait when the buffer is at capacity."""


@dataclass(frozen=True, slots=True)
class EventBufferMetrics:
    capacity: int
    pending: int
    accepted: int
    dropped: int

    @property
    def utilization(self) -> float:
        return self.pending / self.capacity if self.capacity else 0.0


class EventBuffer(Generic[T]):
    """Bounded async event buffer with explicit backpressure and thread-safe metrics."""

    def __init__(self, maxsize: int) -> None:
        if maxsize < 1:
            raise ValueError(f"maxsize must be >= 1, got {maxsize}")
        self._queue: asyncio.Queue[T] = asyncio.Queue(maxsize=maxsize)
        self._maxsize = maxsize
        self._lock = threading.Lock()
        self._accepted = 0
        self._dropped = 0

    def put_nowait(self, item: T) -> None:
        """Enqueue without waiting. Raises BufferFull if at capacity."""
        try:
            self._queue.put_nowait(item)
        except asyncio.QueueFull as exc:
            with self._lock:
                self._dropped += 1
            raise BufferFull(f"Event buffer at capacity ({self._maxsize})") from exc
        with self._lock:
            self._accepted += 1

    async def put(
        self, item: T, *, policy: BackpressurePolicy = BackpressurePolicy.DROP_NEWEST
    ) -> bool:
        """
        Enqueue under the given backpressure policy.
        Returns True if accepted, False if dropped. Never raises except CancelledError.
        """
        try:
            if policy is BackpressurePolicy.BLOCK:
                await self._queue.put(item)
                with self._lock:
                    self._accepted += 1
                return True
            try:
                self._queue.put_nowait(item)
            except asyncio.QueueFull:
                with self._lock:
                    self._dropped += 1
                return False
            with self._lock:
                self._accepted += 1
            return True
        except asyncio.CancelledError:
            raise
        except Exception:
            with self._lock:
                self._dropped += 1
            return False

    async def get(self) -> T:
        return await self._queue.get()

    def get_nowait(self) -> T:
        return self._queue.get_nowait()

    def task_done(self) -> None:
        self._queue.task_done()

    def metrics(self) -> EventBufferMetrics:
        with self._lock:
            accepted, dropped = self._accepted, self._dropped
        return EventBufferMetrics(
            capacity=self._maxsize,
            pending=self._queue.qsize(),
            accepted=accepted,
            dropped=dropped,
        )
