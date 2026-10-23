"""Optional allowlist for bot users."""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from typing import Any

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message, TelegramObject


def load_allowed_user_ids() -> set[int] | None:
    raw = os.getenv("ALLOWED_USER_IDS", "").strip()
    if not raw:
        return None
    ids: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        ids.add(int(part))
    return ids or None


def _user_id_from_event(event: TelegramObject) -> int | None:
    if isinstance(event, Message) and event.from_user:
        return event.from_user.id
    if isinstance(event, CallbackQuery) and event.from_user:
        return event.from_user.id
    return None


class AccessControlMiddleware(BaseMiddleware):
    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        allowed = load_allowed_user_ids()
        if allowed is None:
            return await handler(event, data)

        user_id = _user_id_from_event(event)
        if user_id is not None and user_id in allowed:
            return await handler(event, data)

        if isinstance(event, CallbackQuery):
            await event.answer("Access denied.", show_alert=True)
        elif isinstance(event, Message):
            await event.answer("Access denied.")
        return None
