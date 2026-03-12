import json
import hashlib
from typing import Optional, Any, Callable
from functools import wraps
import redis.asyncio as redis

from app.config import settings

# Redis connection pool
_redis_pool: Optional[redis.Redis] = None


async def get_redis() -> redis.Redis:
    """Get Redis connection."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis_pool


async def close_redis():
    """Close Redis connection."""
    global _redis_pool
    if _redis_pool is not None:
        await _redis_pool.close()
        _redis_pool = None


def make_cache_key(prefix: str, *args, **kwargs) -> str:
    """Generate a cache key from prefix and arguments."""
    key_data = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True)
    key_hash = hashlib.md5(key_data.encode()).hexdigest()[:12]
    return f"{prefix}:{key_hash}"


async def get_cached(key: str) -> Optional[Any]:
    """Get cached value by key."""
    try:
        r = await get_redis()
        value = await r.get(key)
        if value:
            return json.loads(value)
    except Exception:
        pass
    return None


async def set_cached(key: str, value: Any, ttl: Optional[int] = None):
    """Set cached value with optional TTL."""
    try:
        r = await get_redis()
        ttl = ttl or settings.cache_ttl_seconds
        await r.set(key, json.dumps(value), ex=ttl)
    except Exception:
        pass


async def delete_cached(key: str):
    """Delete a cached key."""
    try:
        r = await get_redis()
        await r.delete(key)
    except Exception:
        pass


async def invalidate_pattern(pattern: str):
    """Invalidate all keys matching a pattern."""
    try:
        r = await get_redis()
        cursor = 0
        while True:
            cursor, keys = await r.scan(cursor, match=pattern, count=100)
            if keys:
                await r.delete(*keys)
            if cursor == 0:
                break
    except Exception:
        pass


# Cache key prefixes for different entities
CACHE_RULES = "rules"
CACHE_FINDINGS = "findings"
CACHE_ACCOUNTS = "accounts"
CACHE_SCANS = "scans"
CACHE_SUMMARY = "summary"
