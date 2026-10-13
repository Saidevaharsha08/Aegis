from fastapi import APIRouter, Request, Header, HTTPException, status, Depends
from typing import Optional
from app.api.rate_limiter import _limiter, get_quota_for_key
from app.config import settings
try:
    import aioredis
except Exception:
    aioredis = None

router = APIRouter()


@router.get("/detect/quota", status_code=status.HTTP_200_OK)
async def detect_quota(request: Request, x_api_key: Optional[str] = Header(None, convert_underscores=False)):
    """Return rate-limit quota info for the caller (by API key if provided, otherwise by client IP)."""
    client_ip = request.client.host if request.client else "unknown"
    key = x_api_key or client_ip or "unknown"
    # If API key required but not provided, return 401
    if settings.DETECT_API_KEY and not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

    info = await get_quota_for_key(key)
    return {"key": key if x_api_key else f"ip:{client_ip}", "quota": info}


@router.get("/ingest/status", status_code=status.HTTP_200_OK)
async def ingest_status():
    """Return simple ingest queue status (Redis list length) and Redis availability."""
    if not getattr(settings, "REDIS_URL", None) or not aioredis:
        return {"redis": False, "queue_length": None, "message": "Redis not configured or aioredis not installed"}
    try:
        redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        length = await redis.llen("ingest_queue")
        await redis.close()
        return {"redis": True, "queue_length": int(length)}
    except Exception as e:
        return {"redis": False, "queue_length": None, "message": str(e)}
