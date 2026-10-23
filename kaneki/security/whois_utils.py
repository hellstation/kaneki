"""WHOIS lookup with full field set matching the toolbox OSINT report."""
import asyncio
import logging
from dataclasses import dataclass
from typing import Any

import whois  # python-whois

logger = logging.getLogger(__name__)


@dataclass
class WhoisInfo:
    domain: str | None = None
    registrar: str | None = None
    org: str | None = None
    country: str | None = None
    state: str | None = None
    creation_date: str | None = None
    updated_date: str | None = None
    expiration_date: str | None = None
    name_servers: list[str] | None = None
    status: str | None = None
    emails: str | None = None
    dnssec: str | None = None
    error: str | None = None


def _normalize(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        seen: set[str] = set()
        items: list[str] = []
        for item in value:
            text = str(item).strip()
            if text and text not in seen:
                seen.add(text)
                items.append(text)
        return ", ".join(items) if items else None
    text = str(value).strip()
    return text or None


def _first_or_value(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _blocking_whois_lookup(domain: str) -> WhoisInfo:
    try:
        data = whois.whois(domain)
        if not data or not getattr(data, "domain_name", None):
            return WhoisInfo(error=f"No WHOIS data found for {domain}")

        creation = _first_or_value(data.creation_date)
        updated = _first_or_value(getattr(data, "updated_date", None))
        expiration = _first_or_value(data.expiration_date)

        ns = data.name_servers
        if isinstance(ns, str):
            name_servers = [ns]
        elif ns:
            name_servers = [str(x).strip().lower().rstrip(".") for x in ns if str(x).strip()]
        else:
            name_servers = None

        return WhoisInfo(
            domain=_normalize(data.domain_name),
            registrar=_normalize(data.registrar),
            org=_normalize(getattr(data, "org", None)),
            country=_normalize(getattr(data, "country", None)),
            state=_normalize(getattr(data, "state", None)),
            creation_date=str(creation) if creation else None,
            updated_date=str(updated) if updated else None,
            expiration_date=str(expiration) if expiration else None,
            name_servers=name_servers or None,
            status=_normalize(getattr(data, "status", None)),
            emails=_normalize(getattr(data, "emails", None)),
            dnssec=_normalize(getattr(data, "dnssec", None)),
        )
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        return WhoisInfo(error=str(e))


async def get_whois_info(domain: str) -> WhoisInfo:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _blocking_whois_lookup, domain)
