from __future__ import annotations

import logging
from pathlib import Path

from aiogram import Bot
from aiogram.exceptions import TelegramBadRequest
from aiogram.fsm.context import FSMContext
from aiogram.types import (
    FSInputFile,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

logger = logging.getLogger(__name__)

BANNER_PATH = Path(__file__).resolve().parent.parent / "assets" / "image.jpg"
CAPTION_LIMIT = 1024

_banner_file_id: str | None = None


def main_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="Functions", callback_data="functions"),
                InlineKeyboardButton(text="Profile", callback_data="profile"),
            ],
            [InlineKeyboardButton(text="About", callback_data="about")],
        ]
    )


def functions_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="ID", callback_data="id")],
            [
                InlineKeyboardButton(text="Username", callback_data="osint_tool:username"),
                InlineKeyboardButton(text="Phone", callback_data="osint_tool:phone"),
            ],
            [
                InlineKeyboardButton(text="Vehicle", callback_data="osint_tool:vehicle"),
                InlineKeyboardButton(text="Email", callback_data="osint_tool:email"),
            ],
            [InlineKeyboardButton(text="WHOIS / IP", callback_data="osint_tool:host")],
            [InlineKeyboardButton(text="Back", callback_data="main")],
        ]
    )


def info_back_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Back", callback_data="main")],
        ]
    )


def osint_prompt_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="Back", callback_data="functions"),
                InlineKeyboardButton(text="Main Menu", callback_data="main"),
            ],
        ]
    )


def osint_result_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="OSINT Again", callback_data="osint_again")],
            [
                InlineKeyboardButton(text="Back", callback_data="functions"),
                InlineKeyboardButton(text="Main Menu", callback_data="main"),
            ],
        ]
    )


def id_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Get ID", callback_data="id_get")],
            [InlineKeyboardButton(text="Back", callback_data="functions")],
        ]
    )


def id_nav_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="Back", callback_data="id"),
                InlineKeyboardButton(text="Main Menu", callback_data="main"),
            ],
        ]
    )


def id_another_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Get Another ID", callback_data="id_get")],
            [InlineKeyboardButton(text="Main Menu", callback_data="main")],
        ]
    )


def empty_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[])


def _clip_caption(text: str) -> str:
    if len(text) <= CAPTION_LIMIT:
        return text
    return text[: CAPTION_LIMIT - 1] + "…"


def _photo_source() -> str | FSInputFile | None:
    if _banner_file_id:
        return _banner_file_id
    if BANNER_PATH.is_file():
        return FSInputFile(BANNER_PATH)
    logger.warning("Banner image not found: %s", BANNER_PATH)
    return None


def _remember_file_id(message: Message) -> None:
    global _banner_file_id
    if message.photo:
        _banner_file_id = message.photo[-1].file_id


def _is_not_modified(error: TelegramBadRequest) -> bool:
    return "message is not modified" in str(error).lower()


async def _delete_menu(bot: Bot, chat_id: int, state: FSMContext) -> None:
    data = await state.get_data()
    menu_id = data.get("menu_message_id")
    if not menu_id:
        return
    try:
        await bot.delete_message(chat_id, menu_id)
    except TelegramBadRequest:
        pass
    await state.update_data(menu_message_id=None)


async def _edit_caption(
    bot: Bot,
    chat_id: int,
    message_id: int,
    text: str,
    keyboard: InlineKeyboardMarkup | None,
    parse_mode: str | None,
) -> bool:
    caption = _clip_caption(text)
    try:
        await bot.edit_message_caption(
            chat_id=chat_id,
            message_id=message_id,
            caption=caption,
            reply_markup=keyboard,
            parse_mode=parse_mode,
        )
        return True
    except TelegramBadRequest as error:
        if _is_not_modified(error):
            return True
        try:
            await bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_id,
                text=caption,
                reply_markup=keyboard,
                parse_mode=parse_mode,
            )
            return True
        except TelegramBadRequest as text_error:
            if _is_not_modified(text_error):
                return True
            return False


async def _send_screen(
    bot: Bot,
    chat_id: int,
    text: str,
    keyboard: InlineKeyboardMarkup | None,
    parse_mode: str | None,
) -> Message:
    caption = _clip_caption(text)
    photo = _photo_source()
    if photo is None:
        return await bot.send_message(
            chat_id=chat_id,
            text=caption,
            reply_markup=keyboard,
            parse_mode=parse_mode,
        )
    msg = await bot.send_photo(
        chat_id=chat_id,
        photo=photo,
        caption=caption,
        reply_markup=keyboard,
        parse_mode=parse_mode,
    )
    _remember_file_id(msg)
    return msg


async def show_screen(
    *,
    bot: Bot,
    chat_id: int,
    state: FSMContext,
    text: str,
    keyboard: InlineKeyboardMarkup | None = None,
    parse_mode: str | None = None,
    target: Message | None = None,
    force_new: bool = False,
) -> Message | None:
    """Show a branded photo screen. Edits the existing menu message unless force_new."""
    if force_new:
        await _delete_menu(bot, chat_id, state)
        msg = await _send_screen(bot, chat_id, text, keyboard, parse_mode)
        await state.update_data(menu_message_id=msg.message_id)
        return msg

    data = await state.get_data()
    edit_id = None
    if target is not None and (target.photo or target.caption is not None):
        edit_id = target.message_id
    elif data.get("menu_message_id"):
        edit_id = data["menu_message_id"]

    if edit_id:
        if await _edit_caption(bot, chat_id, edit_id, text, keyboard, parse_mode):
            await state.update_data(menu_message_id=edit_id)
            return target

    msg = await _send_screen(bot, chat_id, text, keyboard, parse_mode)
    await state.update_data(menu_message_id=msg.message_id)
    return msg
