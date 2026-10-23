"""Global limit on concurrent heavy OSINT jobs."""

from __future__ import annotations

import asyncio
import os

_semaphore: asyncio.Semaphore | None = None


def get_osint_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        limit = max(1, int(os.getenv("OSINT_MAX_CONCURRENT", "2")))
        _semaphore = asyncio.Semaphore(limit)
    return _semaphore
