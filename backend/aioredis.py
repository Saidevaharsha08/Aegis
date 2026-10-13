"""Compatibility shim: provide `aioredis.from_url` using `redis.asyncio`.

This lets existing code that imports `aioredis` continue to work by falling
back to `redis.asyncio`.
"""
try:
    import redis.asyncio as _redis_async

    def from_url(url, **kwargs):
        return _redis_async.from_url(url, **kwargs)

    class Redis(_redis_async.Redis):
        pass

    class StrictRedis(Redis):
        pass

    __all__ = ["from_url", "Redis", "StrictRedis"]
except Exception:
    raise ImportError(
        "neither 'redis.asyncio' nor 'aioredis' is importable; install 'redis' (>=4.0)"
    )
