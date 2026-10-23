"""IP lookup helpers for host reports."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any

import aiohttp


async def fetch_ipinfo(ip_address: str) -> dict[str, Any] | str:
    url = f"https://ipinfo.io/{ip_address}/json"
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
            if response.status != 200:
                return f"ipinfo.io returned status {response.status}"
            data = await response.json()
    if not isinstance(data, dict):
        return "ipinfo.io returned an unexpected payload"
    return data


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


async def reverse_dns(ip_address: str) -> str:
    def lookup() -> str:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
        except (OSError, socket.herror):
            return ""
        return hostname

    return await asyncio.to_thread(lookup)
