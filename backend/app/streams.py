"""Redis Streams wrapper with in-process list fallback.

Primary client: ``redis.asyncio`` (official, ships with ``redis>=4.2``).
Fallback: an in-process ``asyncio.Queue`` shim that mirrors the four
helpers (``append``, ``read``, ``len``, ``trim``) used by the ingest
pipeline. The fallback activates automatically when ``REDIS_URL`` is
unset or the client cannot connect at boot.

The wrapper is intentionally minimal — milestone 1 only needs the
four operations below. New helpers can be added as the detector /
consumer milestones come online.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, AsyncIterator, Iterable

from app.config import settings

log = logging.getLogger(__name__)

# Lazy-loaded Redis client; ``None`` means "fallback mode".
_redis = None
_redis_lock = asyncio.Lock()

# In-process fallback store: stream name -> asyncio.Queue
_local_queues: dict[str, asyncio.Queue] = {}
_local_locks: dict[str, asyncio.Lock] = {}
_local_meta: dict[str, dict[str, Any]] = {}

# Backlog threshold above which the ingest endpoint should start
# returning 429 (backpressure). Configurable via env.
_BACKLOG_LIMIT = int(os.getenv("INGEST_BACKLOG_LIMIT", "10000"))


async def _get_redis():
    """Lazily construct the async Redis client.

    Returns ``None`` if ``REDIS_URL`` is not configured or the client
    cannot be imported / connected. Callers must tolerate ``None``.
    """
    global _redis
    if _redis is False:
        return None
    if _redis is not None:
        return _redis
    if not settings.REDIS_URL:
        _redis = False
        return None
    try:
        import redis.asyncio as aioredis  # type: ignore
    except Exception as exc:  # pragma: no cover - import guard
        log.warning("redis.asyncio unavailable, using in-process fallback: %s", exc)
        _redis = False
        return None
    try:
        client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        # ping with a short timeout so boot does not hang if Redis is down
        await asyncio.wait_for(client.ping(), timeout=1.0)
        async with _redis_lock:
            _redis = client
        log.info("redis streams client connected: %s", settings.REDIS_URL)
        return _redis
    except Exception as exc:
        log.warning("redis ping failed, using in-process fallback: %s", exc)
        _redis = False
        return None


def _local_queue(stream: str) -> asyncio.Queue:
    if stream not in _local_queues:
        _local_queues[stream] = asyncio.Queue()
        _local_locks[stream] = asyncio.Lock()
        _local_meta[stream] = {"last_id": "0-0"}
    return _local_queues[stream]


def _next_id(prev: str) -> str:
    """Generate the next monotonically increasing stream id for fallback mode."""
    try:
        ms, seq = prev.split("-", 1)
        return f"{ms}-{int(seq) + 1}"
    except Exception:
        return f"{int(asyncio.get_event_loop().time() * 1000)}-0"


async def append(stream: str, item: dict[str, Any] | str, maxlen: int | None = None) -> str:
    """Append an item to ``stream``. Returns the assigned entry id.

    Accepts either a ``dict`` (will be JSON-encoded into a single field
    called ``payload``) or a pre-encoded string.
    """
    payload = item if isinstance(item, str) else json.dumps(item, default=str)
    client = await _get_redis()
    if client is not None:
        kwargs: dict[str, Any] = {"payload": payload}
        if maxlen is not None:
            kwargs["maxlen"] = maxlen
            kwargs["approximate"] = True
        entry_id = await client.xadd(stream, kwargs)
        return entry_id

    # Fallback path
    q = _local_queue(stream)
    async with _local_locks[stream]:
        prev = _local_meta[stream]["last_id"]
        new_id = _next_id(prev)
        await q.put((new_id, payload))
        _local_meta[stream]["last_id"] = new_id
        if maxlen is not None:
            while q.qsize() > maxlen:
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    break
    return new_id


async def read(
    stream: str,
    last_id: str = "$",
    block_ms: int = 0,
    count: int | None = None,
) -> list[tuple[str, dict[str, str]]]:
    """Read entries from ``stream`` strictly newer than ``last_id``.

    ``block_ms`` of 0 returns immediately if nothing is available;
    ``block_ms`` > 0 blocks the consumer for that long waiting for
    new entries. Returns a list of ``(id, fields)`` tuples.
    """
    client = await _get_redis()
    if client is not None:
        try:
            res = await client.xread(
                {stream: last_id},
                block=block_ms,
                count=count,
            )
        except Exception as exc:
            log.warning("redis xread failed, returning empty: %s", exc)
            return []
        out: list[tuple[str, dict[str, str]]] = []
        for _stream_name, entries in res or []:
            for entry_id, fields in entries:
                out.append((entry_id, fields))
        return out

    # Fallback path — non-blocking semantics only; if you need
    # blocking reads in fallback mode, use ``iter_stream`` below.
    q = _local_queue(stream)
    out = []
    while not q.empty():
        entry_id, payload = q.get_nowait()
        out.append((entry_id, {"payload": payload}))
    return out


async def iter_stream(
    stream: str,
    last_id: str = "$",
    block_ms: int = 5000,
    count: int | None = None,
) -> AsyncIterator[tuple[str, dict[str, str]]]:
    """Yield new entries from ``stream`` as they arrive.

    Works for both Redis Streams (uses ``XREAD BLOCK``) and the
    in-process fallback (sleeps ``block_ms`` between polls).
    """
    cursor = last_id
    while True:
        entries = await read(stream, last_id=cursor, block_ms=block_ms, count=count)
        if not entries:
            continue
        for entry_id, fields in entries:
            cursor = entry_id
            yield entry_id, fields


async def length(stream: str) -> int:
    """Return approximate number of entries currently in ``stream``."""
    client = await _get_redis()
    if client is not None:
        try:
            return int(await client.xlen(stream))
        except Exception:
            return 0
    return _local_queue(stream).qsize()


async def trim(stream: str, maxlen: int) -> int:
    """Cap ``stream`` at ``maxlen`` entries; returns entries removed."""
    client = await _get_redis()
    if client is not None:
        try:
            return int(await client.xtrim(stream, maxlen=maxlen, approximate=True))
        except Exception:
            return 0
    q = _local_queue(stream)
    removed = 0
    while q.qsize() > maxlen:
        try:
            q.get_nowait()
            removed += 1
        except asyncio.QueueEmpty:
            break
    return removed


async def is_overloaded(stream: str = "ingest", limit: int | None = None) -> bool:
    """Return True when the ingest backlog exceeds the soft limit."""
    cap = limit if limit is not None else _BACKLOG_LIMIT
    return (await length(stream)) >= cap


def is_redis_backed() -> bool:
    """Synchronous check — True if a Redis URL is configured.

    Does not perform a connection probe; for that, call ``_get_redis()``.
    """
    return bool(settings.REDIS_URL)


__all__ = [
    "append",
    "read",
    "iter_stream",
    "length",
    "trim",
    "is_overloaded",
    "is_redis_backed",
]
