"""Per-user rate limits (memory or Redis)."""

from __future__ import annotations

import logging
import os
import time
from typing import TYPE_CHECKING

from .tools_catalog import DEFAULT_RATE_LIMITS, RATE_LIMIT_BUCKETS

if TYPE_CHECKING:
    from redis import Redis

logger = logging.getLogger(__name__)

_memory_last: dict[tuple[int, str], float] = {}
_redis: Redis | None = None


def configure_redis(client: Redis | None) -> None:
    global _redis
    _redis = client


def _limit_seconds(bucket: str) -> float:
    env_key = RATE_LIMIT_BUCKETS.get(bucket)
    if not env_key:
        return 30.0
    raw = os.getenv(env_key, "").strip()
    if not raw:
        return DEFAULT_RATE_LIMITS.get(bucket, 30.0)
    try:
        return max(0.0, float(raw))
    except ValueError:
        return DEFAULT_RATE_LIMITS.get(bucket, 30.0)


def check_rate_limit(user_id: int, bucket: str) -> float | None:
    """
    Return remaining cooldown seconds if limited, else None and record the call.
    """
    if user_id <= 0:
        return None

    limit = _limit_seconds(bucket)
    if limit <= 0:
        return None

    key = f"kaneki:rl:{bucket}:{user_id}"
    now = time.monotonic()

    if _redis is not None:
        try:
            ttl = _redis.ttl(key)
            if ttl and ttl > 0:
                return float(ttl)
            _redis.setex(key, int(limit), "1")
            return None
        except Exception:
            logger.exception("Redis rate limit failed for %s", bucket)

    last = _memory_last.get((user_id, bucket), 0.0)
    elapsed = now - last
    if elapsed < limit:
        return round(limit - elapsed, 1)
    _memory_last[(user_id, bucket)] = now
    return None
