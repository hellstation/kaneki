"""Shared Telegram flow for OSINT HTML reports."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from aiogram.fsm.context import FSMContext
from aiogram.types import BufferedInputFile, Message

from .rate_limit import check_rate_limit
from .ui import empty_keyboard, osint_result_keyboard, show_screen

logger = logging.getLogger(__name__)

USER_ERROR = "Request failed. Try again later."

T = TypeVar("T")


def safe_filename_stem(raw: str, fallback: str, extra_chars: str = "") -> str:
    allowed = set(extra_chars) | set("._@+-")
    stem = "".join(ch if ch.isalnum() or ch in allowed else "_" for ch in raw)
    return stem or fallback


async def deliver_html_osint(
    message: Message,
    state: FSMContext,
    *,
    progress: str,
    log_label: str,
    rate_bucket: str,
    analyze: Callable[[], Awaitable[T | str]],
    filename_stem: Callable[[T], str],
    semaphore: asyncio.Semaphore | None = None,
) -> None:
    user_id = message.from_user.id if message.from_user else 0
    remaining = check_rate_limit(user_id, rate_bucket) if user_id else None
    if remaining is not None:
        await show_screen(
            bot=message.bot,
            chat_id=message.chat.id,
            state=state,
            text=f"Too many requests. Wait {remaining}s before trying again.",
            keyboard=osint_result_keyboard(),
            force_new=True,
        )
        return

    await show_screen(
        bot=message.bot,
        chat_id=message.chat.id,
        state=state,
        text=progress,
        keyboard=empty_keyboard(),
        force_new=True,
    )

    try:
        if semaphore is not None:
            async with semaphore:
                report = await analyze()
        else:
            report = await analyze()
    except Exception:
        logger.exception("%s failed", log_label)
        await show_screen(
            bot=message.bot,
            chat_id=message.chat.id,
            state=state,
            text=USER_ERROR,
            keyboard=osint_result_keyboard(),
        )
        return

    if isinstance(report, str):
        await show_screen(
            bot=message.bot,
            chat_id=message.chat.id,
            state=state,
            text=report,
            keyboard=osint_result_keyboard(),
        )
        return

    stem = filename_stem(report)
    html = getattr(report, "html", None)
    if not isinstance(html, str):
        await show_screen(
            bot=message.bot,
            chat_id=message.chat.id,
            state=state,
            text=USER_ERROR,
            keyboard=osint_result_keyboard(),
        )
        return

    document = BufferedInputFile(html.encode("utf-8"), filename=f"report_{stem}.html")
    await message.answer_document(document=document)
    await show_screen(
        bot=message.bot,
        chat_id=message.chat.id,
        state=state,
        text="Choose an action:",
        keyboard=osint_result_keyboard(),
        force_new=True,
    )
