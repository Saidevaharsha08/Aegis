"""In-process pub/sub for mesh events: campaigns + countermeasures.

Lets the SSE endpoint (``/mesh/stream``) fan out updates to many
concurrent clients without each one polling Redis.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator


class EventBus:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=128)
        async with self._lock:
            self._subscribers.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue) -> None:
        async with self._lock:
            self._subscribers.discard(q)

    async def publish(self, kind: str, payload: dict[str, Any]) -> None:
        envelope = {"kind": kind, "payload": payload}
        async with self._lock:
            dead = []
            for q in self._subscribers:
                try:
                    q.put_nowait(envelope)
                except asyncio.QueueFull:
                    dead.append(q)
            for q in dead:
                self._subscribers.discard(q)


bus = EventBus()


async def publish_campaign(campaign: dict[str, Any]) -> None:
    await bus.publish("campaign", campaign)


async def publish_countermeasure(cm: dict[str, Any]) -> None:
    await bus.publish("countermeasure", cm)


async def publish_attack(event: dict[str, Any]) -> None:
    await bus.publish("attack", event)


async def publish_federated(update: dict[str, Any]) -> None:
    await bus.publish("federated", update)


async def publish_redteam(update: dict[str, Any]) -> None:
    await bus.publish("redteam", update)


async def iter_events() -> AsyncIterator[dict[str, Any]]:
    """Async generator yielding mesh events until the consumer cancels."""
    q = await bus.subscribe()
    try:
        while True:
            yield await q.get()
    finally:
        await bus.unsubscribe(q)


__all__ = [
    "bus",
    "iter_events",
    "publish_campaign",
    "publish_countermeasure",
    "publish_attack",
    "publish_federated",
    "publish_redteam",
]
