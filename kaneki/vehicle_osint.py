from __future__ import annotations

from dataclasses import dataclass

import aiohttp

from .email_report import render_vehicle_html
from .vehicle_data import analyze_vehicle


@dataclass
class VehicleReport:
    plate: str
    html: str


def normalize_plate(raw: str) -> str:
    return raw.replace("-", "").replace(" ", "").upper()


def overview_rows(data: dict[str, str]) -> list[tuple[str, str]]:
    return [(key.upper(), value) for key, value in data.items()]


async def analyze_vehicle_plate(raw: str) -> VehicleReport | str:
    normalized = normalize_plate(raw)
    if not normalized:
        return "Empty license plate."

    url = f"https://opendata.rdw.nl/resource/m9d7-ebf2.json?kenteken={normalized}"
    headers = {"User-Agent": "Telegram-Toolbox-Bot/1.0"}

    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
            if response.status != 200:
                return f"RDW API returned status {response.status}"
            payload = await response.json()

    if not payload:
        return f"Vehicle not found for plate {normalized}"

    car = payload[0]
    data = analyze_vehicle(car)
    html = render_vehicle_html(
        plate=normalized,
        overview=overview_rows(data),
    )
    return VehicleReport(plate=normalized, html=html)
