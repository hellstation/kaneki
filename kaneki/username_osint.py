"""Username search via Maigret."""

from __future__ import annotations

import importlib.resources
import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

from .email_report import render_username_html

MAIGRET_TOP_SITES = int(os.getenv("MAIGRET_TOP_SITES", "500"))
MAIGRET_TIMEOUT = int(os.getenv("MAIGRET_TIMEOUT", "20"))
MAIGRET_MAX_CONNECTIONS = int(os.getenv("MAIGRET_MAX_CONNECTIONS", "100"))
MAIGRET_PARSE_PROFILES = os.getenv("MAIGRET_PARSE_PROFILES", "0").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

logger = logging.getLogger(__name__)


@dataclass
class UsernameReport:
    username: str
    html: str


async def analyze_username(username: str) -> UsernameReport | str:
    username = username.strip().lstrip("@")
    if not username or any(ch.isspace() for ch in username):
        return "Invalid username."

    grouped, checked = await _run_maigret(username)
    html = render_username_html(
        username=username,
        checked=checked,
        found=grouped["found"],
        maybe=grouped["maybe"],
        errors=grouped["error"],
        not_found_count=len(grouped["not_found"]),
    )
    return UsernameReport(username=username, html=html)


async def _run_maigret(username: str) -> tuple[dict[str, list[dict[str, Any]]], int]:
    try:
        from maigret import search as maigret_search
        from maigret.sites import MaigretDatabase
    except ImportError as exc:
        raise RuntimeError("maigret package is not installed") from exc

    db_path = importlib.resources.files("maigret").joinpath("resources/data.json")
    db = MaigretDatabase().load_from_path(str(db_path))
    sites = db.ranked_sites_dict(top=MAIGRET_TOP_SITES)
    results = await maigret_search(
        username=username,
        site_dict=sites,
        logger=logging.getLogger("maigret"),
        timeout=MAIGRET_TIMEOUT,
        is_parsing_enabled=MAIGRET_PARSE_PROFILES,
        max_connections=MAIGRET_MAX_CONNECTIONS,
        no_progressbar=True,
    )
    return group_maigret_results(results), len(sites)


def group_maigret_results(results: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {
        "found": [],
        "maybe": [],
        "not_found": [],
        "error": [],
    }

    for site_name, result in results.items():
        if not result:
            continue
        status = result.get("status")
        group = maigret_status_group(status)
        grouped[group].append(
            {
                "site": site_name,
                "url": result.get("url_user") or result.get("url_main") or "",
                "http_status": result.get("http_status"),
                "rank": result.get("rank"),
                "ids_data": result.get("ids_data") or {},
            }
        )
    return grouped


def maigret_status_group(status: Any) -> str:
    if hasattr(status, "is_found") and status.is_found():
        return "found"

    status_text = str(status).lower()
    if any(marker in status_text for marker in ("not_found", "not found", "available")):
        return "not_found"
    if any(marker in status_text for marker in ("claimed", "found")):
        return "found"
    if any(marker in status_text for marker in ("unknown", "illegal", "blocked", "captcha")):
        return "maybe"
    return "error"


def compact_ids_data(ids_data: dict[str, Any]) -> str:
    parts = []
    for key, value in ids_data.items():
        if value in (None, "", [], {}):
            continue
        text = ", ".join(str(item) for item in value[:3]) if isinstance(value, list) else str(value)
        text = text.replace("\n", " ").strip()
        if text:
            parts.append(f"{key}={text[:120]}")
        if len(parts) >= 3:
            break
    return "; ".join(parts)
