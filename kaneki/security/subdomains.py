"""crt.sh Certificate Transparency: subdomains + certificate emails."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
from dataclasses import dataclass, field

import aiohttp

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
CRTSH_TIMEOUT = 30
CRTSH_RETRIES = 3
MAX_SUBDOMAINS = 40
MAX_EMAILS = 25
_NAME_SPLIT_RE = re.compile(r"[\n\r,]+")


@dataclass
class CrtshInfo:
    subdomains: list[str] = field(default_factory=list)
    certificate_emails: list[str] = field(default_factory=list)
    error: str = ""


def _host_from_token(raw: str, domain: str) -> str | None:
    name = raw.strip().lower().rstrip(".")
    if not name or name.startswith("@"):
        return None
    wildcard = name.startswith("*.")
    host = name[2:] if wildcard else name
    if not host:
        return None
    if host == domain:
        return f"*.{domain}" if wildcard else None
    if host.endswith("." + domain):
        return f"*.{host}" if wildcard else host
    return None


def parse_crtsh_records(data: list[object], domain: str) -> tuple[list[str], list[str]]:
    found_subs: set[str] = set()
    found_emails: set[str] = set()
    email_re = re.compile(r"[A-Za-z0-9._%+\-]+@" + re.escape(domain), re.I)

    for entry in data:
        if not isinstance(entry, dict):
            continue
        chunks = [
            str(entry.get("name_value") or ""),
            str(entry.get("common_name") or ""),
        ]
        blob = "\n".join(chunks)
        for match in email_re.findall(blob):
            found_emails.add(match.lower())
        for token in _NAME_SPLIT_RE.split(blob):
            host = _host_from_token(token, domain)
            if host:
                found_subs.add(host)

    return sorted(found_subs)[:MAX_SUBDOMAINS], sorted(found_emails)[:MAX_EMAILS]


async def _fetch_crtsh_json(domain: str, timeout: int) -> list[object]:
    params = {"q": f"%.{domain}", "output": "json"}
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    headers = {"User-Agent": "Telegram-Toolbox-Bot/1.0"}
    last_error = ""

    for attempt in range(1, CRTSH_RETRIES + 1):
        try:
            connector = aiohttp.TCPConnector(family=socket.AF_INET)
            async with aiohttp.ClientSession(
                timeout=timeout_cfg,
                headers=headers,
                connector=connector,
            ) as session:
                async with session.get(CRTSH_URL, params=params) as resp:
                    if resp.status != 200:
                        last_error = f"crt.sh returned status {resp.status}"
                        logger.warning("%s for %s (attempt %s)", last_error, domain, attempt)
                        continue
                    raw = await resp.text()
                    if not raw.strip():
                        last_error = "crt.sh returned an empty body"
                        continue
                    try:
                        data = json.loads(raw)
                    except json.JSONDecodeError:
                        last_error = "crt.sh returned invalid JSON"
                        logger.warning("%s for %s (attempt %s)", last_error, domain, attempt)
                        continue
                    if not isinstance(data, list):
                        last_error = "crt.sh returned an unexpected payload"
                        continue
                    return data
        except asyncio.TimeoutError:
            last_error = f"crt.sh timed out after {timeout}s"
            logger.warning("%s for %s (attempt %s)", last_error, domain, attempt)
        except Exception as exc:
            last_error = f"crt.sh lookup failed: {exc}"
            logger.warning("%s for %s (attempt %s)", last_error, domain, attempt)
        if attempt < CRTSH_RETRIES:
            await asyncio.sleep(min(2 * attempt, 5))

    raise RuntimeError(last_error or "crt.sh lookup failed")


async def get_crtsh_info(domain: str, timeout: int = CRTSH_TIMEOUT) -> CrtshInfo:
    """Passive CT lookup via crt.sh. On failure returns empty lists plus error."""
    fetch_timeout = max(timeout, CRTSH_TIMEOUT)
    try:
        data = await _fetch_crtsh_json(domain, fetch_timeout)
    except Exception as exc:
        return CrtshInfo(error=str(exc))

    subdomains, emails = parse_crtsh_records(data, domain)
    return CrtshInfo(subdomains=subdomains, certificate_emails=emails)


async def get_subdomains(domain: str, timeout: int = CRTSH_TIMEOUT) -> list[str]:
    """Backward-compatible helper used by older call sites."""
    info = await get_crtsh_info(domain, timeout=timeout)
    return info.subdomains
