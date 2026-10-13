from fastapi import Request, Header, HTTPException, status
from typing import Optional
import time
from threading import Lock
from app.config import settings

try:
    import aioredis
except Exception:
    aioredis = None


class InMemoryRateLimiter:
    """Very small in-memory sliding-window rate limiter.

    Not suitable for multi-process deployments; intended for demo/dev use.
    """
    def __init__(self, per_minute: int = 60):
        self.per_minute = per_minute
        self.windows = {}  # key -> list[timestamps]
        self.lock = Lock()

    def check(self, key: str) -> bool:
        now = time.time()
        cutoff = now - 60
        with self.lock:
            lst = self.windows.get(key, [])
            # keep only timestamps within last minute
            lst = [t for t in lst if t > cutoff]
            if len(lst) >= self.per_minute:
                return False
            lst.append(now)
            self.windows[key] = lst
            return True

    def get_quota(self, key: str) -> dict:
        """Return remaining requests and seconds until reset for the provided key."""
        now = time.time()
        cutoff = now - 60
        with self.lock:
            lst = self.windows.get(key, [])
            lst = [t for t in lst if t > cutoff]
            used = len(lst)
            remaining = max(0, self.per_minute - used)
            reset_seconds = 0
            if lst:
                oldest = min(lst)
                reset_seconds = max(0, int(60 - (now - oldest)))
            else:
                reset_seconds = 60
            return {"limit": self.per_minute, "used": used, "remaining": remaining, "reset_seconds": reset_seconds}


_limiter = InMemoryRateLimiter(per_minute=getattr(settings, "RATE_LIMIT_PER_MINUTE", 60))


async def _redis_check(key: str) -> bool:
    """Use Redis INCR with TTL to implement a simple per-minute counter.

    Returns True if allowed, False if over limit.
    """
    if not aioredis or not settings.REDIS_URL:
        return _limiter.check(key)

    redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    # Use a bucket key per minute window
    window_key = f"rate:{key}:{int(time.time() // 60)}"
    limit = getattr(settings, "RATE_LIMIT_PER_MINUTE", 60)
    try:
        val = await redis.incr(window_key)
        if val == 1:
            # set TTL to 61 seconds
            await redis.expire(window_key, 61)
        await redis.close()
        return int(val) <= int(limit)
    except Exception:
        # on any redis error, fallback to in-memory
        return _limiter.check(key)


async def _redis_quota(key: str) -> dict:
    if not aioredis or not settings.REDIS_URL:
        return _limiter.get_quota(key)
    redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        current_key = f"rate:{key}:{int(time.time() // 60)}"
        val = await redis.get(current_key)
        used = int(val) if val else 0
        limit = getattr(settings, "RATE_LIMIT_PER_MINUTE", 60)
        remaining = max(0, limit - used)
        # TTL/reset calculation
        ttl = await redis.ttl(current_key)
        reset_seconds = ttl if ttl and ttl > 0 else 60
        await redis.close()
        return {"limit": limit, "used": used, "remaining": remaining, "reset_seconds": reset_seconds}
    except Exception:
        return _limiter.get_quota(key)


async def rate_limit(request: Request, x_api_key: Optional[str] = Header(None, convert_underscores=False)) -> None:
    """Dependency to enforce per-key or per-IP rate limits.

    Priority: if `X-API-Key` header provided, rate-limit by that key; otherwise by client IP.
    Uses Redis when `REDIS_URL` is set and `aioredis` available, otherwise falls back to in-memory limiter.
    """
    client_ip = None
    if request.client:
        client_ip = request.client.host
    key = x_api_key or client_ip or "unknown"
    allowed = await _redis_check(key)
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")


async def get_quota_for_key(key: str) -> dict:
    """Return quota information for a key (async wrapper)."""
    return await _redis_quota(key)
