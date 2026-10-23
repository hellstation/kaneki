import html
import logging

from aiogram import F, Router
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    CallbackQuery,
    Message,
    ReplyKeyboardRemove,
)

from .concurrency import get_osint_semaphore
from .email_osint import analyze_email
from .host_osint import analyze_host
from .osint_delivery import deliver_html_osint, safe_filename_stem
from .phone_osint import analyze_phone
from .tools_catalog import OSINT_TOOLS, TOOL_PROMPTS
from .username_osint import analyze_username
from .vehicle_osint import analyze_vehicle_plate
from .ui import (
    functions_keyboard,
    id_another_keyboard,
    id_keyboard,
    id_nav_keyboard,
    info_back_keyboard,
    main_keyboard,
    osint_prompt_keyboard,
    osint_result_keyboard,
    show_screen,
)

logger = logging.getLogger(__name__)

router = Router()

MAIN_SCREEN_TEXT = "<b>kaneki — Initial Data Analysis.</b>"
FUNCTIONS_SCREEN_TEXT = "Functions"
ABOUT_TEXT = (
    "<b>kaneki — Initial Data Analysis.</b>\n\n"
    "A toolbox for inspecting data.\n\n"
    "<b>ID</b> — extract a user/chat ID from a forwarded message.\n\n"
    "<b>OSINT</b> — look up a username, phone number, "
    "Dutch vehicle plate, email (SMTP, Google infrastructure, connections), "
    "or WHOIS / IP (domain or IP HTML report: WHOIS, DNS, SSL, CVE)."
)


class MenuStates(StatesGroup):
    main_menu = State()
    id_menu = State()
    get_id_waiting = State()
    osint_waiting = State()


def _callback_message(callback: CallbackQuery) -> Message | None:
    if isinstance(callback.message, Message):
        return callback.message
    return None


async def _preserve_menu_id(state: FSMContext) -> int | None:
    data = await state.get_data()
    return data.get("menu_message_id")


@router.message(CommandStart())
async def start(message: Message, state: FSMContext) -> None:
    await state.clear()
    dumped = await message.answer("\u2060", reply_markup=ReplyKeyboardRemove())
    try:
        await dumped.delete()
    except TelegramBadRequest:
        pass
    await show_screen(
        bot=message.bot,
        chat_id=message.chat.id,
        state=state,
        text=MAIN_SCREEN_TEXT,
        keyboard=main_keyboard(),
        parse_mode="HTML",
        force_new=True,
    )
    await state.set_state(MenuStates.main_menu)


@router.callback_query(F.data == "main")
async def main_menu_cb(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer()
    target = _callback_message(callback)
    if target is None:
        return
    await show_screen(
        bot=callback.bot,
        chat_id=target.chat.id,
        state=state,
        text=MAIN_SCREEN_TEXT,
        keyboard=main_keyboard(),
        parse_mode="HTML",
        target=target,
    )
    await state.set_state(MenuStates.main_menu)


@router.callback_query(F.data == "functions")
async def functions_menu_cb(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer()
    target = _callback_message(callback)
    if target is None:
        return
    await show_screen(
        bot=callback.bot,
        chat_id=target.chat.id,
        state=state,
        text=FUNCTIONS_SCREEN_TEXT,
        keyboard=functions_keyboard(),
        target=target,
    )
    await state.set_state(MenuStates.main_menu)


@router.callback_query(F.data == "profile")
async def profile_cb(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer()
    target = _callback_message(callback)
    if target is None or callback.from_user is None:
        return
    user_id = callback.from_user.id
    await show_screen(
        bot=callback.bot,
        chat_id=target.chat.id,
        state=state,
        text=f"<b>Your kaneki Profile</b>\n\n• ID: <code>{user_id}</code>",
        keyboard=info_back_keyboard(),
        parse_mode="HTML",
        target=target,
    )
    await state.set_state(MenuStates.main_menu)


@router.callback_query(F.data == "about")
async def about_cb(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer()
    target = _callback_message(callback)
    if target is None:
        return
    await show_screen(
        bot=callback.bot,
        chat_id=target.chat.id,
        state=state,
        text=ABOUT_TEXT,
        keyboard=info_back_keyboard(),
        parse_mode="HTML",
        target=target,
    )
    await state.set_state(MenuStates.main_menu)


@router.callback_query(F.data == "cancel")
async def cancel_cb(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer("Cancelled")
    target = _callback_message(callback)
    if target is None:
        return
    menu_id = await _preserve_menu_id(state)
    await state.clear()
    if menu_id:
        await state.update_data(menu_message_id=menu_id)
    await show_screen(
        bot=callback.bot,
        chat_id=target.chat.id,
        state=state,
        text=f"Action cancelled.\n\n{MAIN_SCREEN_TEXT}",
        keyboard=main_keyboard(),
        parse_mode="HTML",
        target=target,
    )
    await state.set_state(MenuStates.main_menu)


@router.callback_query(F.data == "id")
async def id_menu_cb(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer()
    target = _callback_message(callback)
    if target is None:
        return
    await show_screen(
        bot=callback.bot,
        chat_id=target.chat.id,
        state=state,
        text="ID Tools:",
        keyboard=id_keyboard(),
        target=target,
    )
    await state.set_state(MenuStates.id_menu)


@router.callback_query(F.data == "id_get")
async def get_id_cb(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer()
    target = _callback_message(callback)
    if target is None:
        return
    current_state = await state.get_state()
    already_waiting = bool(current_state and str(current_state).endswith("get_id_waiting"))
    await show_screen(
        bot=callback.bot,
        chat_id=target.chat.id,
        state=state,
        text="Forward a message to get the sender's ID:",
        keyboard=id_nav_keyboard(),
        target=target,
        force_new=already_waiting,
    )
    await state.set_state(MenuStates.get_id_waiting)


@router.callback_query(F.data.startswith("osint_tool:"))
async def osint_tool_cb(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer()
    target = _callback_message(callback)
    if target is None or not callback.data:
        return
    tool = callback.data.split(":", 1)[1]
    if tool not in OSINT_TOOLS:
        return
    await state.update_data(selected_osint_tool=tool)
    await show_screen(
        bot=callback.bot,
        chat_id=target.chat.id,
        state=state,
        text=TOOL_PROMPTS[tool],
        keyboard=osint_prompt_keyboard(),
        target=target,
    )
    await state.set_state(MenuStates.osint_waiting)


@router.callback_query(F.data == "osint_again")
async def osint_again_cb(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer()
    target = _callback_message(callback)
    if target is None:
        return
    data = await state.get_data()
    tool = data.get("selected_osint_tool")
    if tool in OSINT_TOOLS:
        await show_screen(
            bot=callback.bot,
            chat_id=target.chat.id,
            state=state,
            text=TOOL_PROMPTS[tool],
            keyboard=osint_prompt_keyboard(),
            target=target,
            force_new=True,
        )
        await state.set_state(MenuStates.osint_waiting)
        return
    await show_screen(
        bot=callback.bot,
        chat_id=target.chat.id,
        state=state,
        text=FUNCTIONS_SCREEN_TEXT,
        keyboard=functions_keyboard(),
        target=target,
        force_new=True,
    )
    await state.set_state(MenuStates.main_menu)


@router.message(MenuStates.osint_waiting, F.text, ~F.text.startswith("/"))
async def osint_query_message(message: Message, state: FSMContext) -> None:
    data = await state.get_data()
    tool = data.get("selected_osint_tool")
    if tool not in OSINT_TOOLS:
        await show_screen(
            bot=message.bot,
            chat_id=message.chat.id,
            state=state,
            text="OSINT session expired. Choose a tool again.",
            keyboard=functions_keyboard(),
            force_new=True,
        )
        await state.set_state(MenuStates.main_menu)
        return

    query = (message.text or "").strip()
    semaphore = get_osint_semaphore()

    if tool == "email":
        await deliver_html_osint(
            message,
            state,
            progress=(
                f"Analyzing email {query}…\n"
                "SMTP, Google infrastructure (GHunt), account connections."
            ),
            log_label="Email OSINT",
            rate_bucket="email",
            analyze=lambda: analyze_email(query),
            filename_stem=lambda report: safe_filename_stem(report.email, "email"),
            semaphore=semaphore,
        )
    elif tool == "username":
        await deliver_html_osint(
            message,
            state,
            progress=(
                f"Scanning username {query}…\n"
                "Maigret account search across public sites."
            ),
            log_label="Username OSINT",
            rate_bucket="username",
            analyze=lambda: analyze_username(query),
            filename_stem=lambda report: safe_filename_stem(
                report.username, "username", extra_chars="@"
            ),
            semaphore=semaphore,
        )
    elif tool == "phone":
        await deliver_html_osint(
            message,
            state,
            progress=f"Analyzing phone {query}…",
            log_label="Phone OSINT",
            rate_bucket="phone",
            analyze=lambda: analyze_phone(query),
            filename_stem=lambda report: safe_filename_stem(
                report.phone, "phone", extra_chars="+"
            ),
            semaphore=semaphore,
        )
    elif tool == "vehicle":
        await deliver_html_osint(
            message,
            state,
            progress=f"Looking up plate {query}…\nRDW Open Data (Netherlands).",
            log_label="Vehicle OSINT",
            rate_bucket="vehicle",
            analyze=lambda: analyze_vehicle_plate(query),
            filename_stem=lambda report: safe_filename_stem(report.plate, "vehicle"),
            semaphore=semaphore,
        )
    elif tool == "host":
        await deliver_html_osint(
            message,
            state,
            progress=(
                f"Analyzing {query}…\n"
                "WHOIS / DNS / SSL for domains, IP tracker for addresses."
            ),
            log_label="Host OSINT",
            rate_bucket="host",
            analyze=lambda: analyze_host(query),
            filename_stem=lambda report: safe_filename_stem(report.target, "host"),
            semaphore=semaphore,
        )
    else:
        await show_screen(
            bot=message.bot,
            chat_id=message.chat.id,
            state=state,
            text="Unknown tool. Choose a function again.",
            keyboard=functions_keyboard(),
            force_new=True,
        )
        await state.set_state(MenuStates.main_menu)
        return

    await state.set_state(MenuStates.osint_waiting)


@router.message(F.forward_origin, MenuStates.get_id_waiting)
async def handle_forwarded_message(message: Message, state: FSMContext) -> None:
    origin = message.forward_origin
    text = "Unable to extract ID from this message."
    parse_mode = None

    if origin is not None:
        sender_user = getattr(origin, "sender_user", None)
        origin_chat = getattr(origin, "chat", None)
        if sender_user is not None:
            user_id = sender_user.id
            username = sender_user.username or "No username"
            text = (
                f"<b>Sender ID:</b> <code>{user_id}</code>\n"
                f"<b>Username:</b> @{html.escape(username)}"
            )
            parse_mode = "HTML"
        elif origin_chat is not None:
            chat_id = origin_chat.id
            chat_title = html.escape(getattr(origin_chat, "title", None) or "Unknown chat")
            text = (
                f"<b>Chat ID:</b> <code>{chat_id}</code>\n"
                f"<b>Chat:</b> {chat_title}"
            )
            parse_mode = "HTML"

    await show_screen(
        bot=message.bot,
        chat_id=message.chat.id,
        state=state,
        text=text,
        keyboard=id_another_keyboard(),
        parse_mode=parse_mode,
        force_new=True,
    )


@router.callback_query()
async def unknown_callback(callback: CallbackQuery) -> None:
    await callback.answer("This button is no longer valid. Use /start.", show_alert=True)
