from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumberType, carrier, geocoder, timezone

from .email_report import render_phone_html

PHONE_TYPE_MAP = {
    PhoneNumberType.MOBILE: "Mobile",
    PhoneNumberType.FIXED_LINE: "Fixed Line",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
    PhoneNumberType.TOLL_FREE: "Toll Free",
    PhoneNumberType.PREMIUM_RATE: "Premium Rate",
    PhoneNumberType.SHARED_COST: "Shared Cost",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
    PhoneNumberType.PAGER: "Pager",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.VOICEMAIL: "Voicemail",
    PhoneNumberType.UNKNOWN: "Unknown",
}

_PHONE_STRIP_RE = re.compile(r"[\s\-().]")
_RU_LOCAL_RE = re.compile(r"^8\d{10}$")


@dataclass
class PhoneReport:
    phone: str
    html: str


def parse_phone(raw: str) -> phonenumbers.PhoneNumber:
    compact = _PHONE_STRIP_RE.sub("", (raw or "").strip())
    if not compact:
        raise NumberParseException(
            NumberParseException.NOT_A_NUMBER,
            "Empty phone number.",
        )

    candidates = [compact]
    if not compact.startswith("+"):
        candidates.append(f"+{compact}")
    if _RU_LOCAL_RE.fullmatch(compact):
        candidates.append(f"+7{compact[1:]}")

    last_exc: NumberParseException | None = None
    fallback: phonenumbers.PhoneNumber | None = None
    for candidate in candidates:
        try:
            parsed = phonenumbers.parse(candidate, None)
        except NumberParseException as exc:
            last_exc = exc
            continue
        if phonenumbers.is_possible_number(parsed):
            return parsed
        if fallback is None:
            fallback = parsed

    if fallback is not None:
        return fallback
    if last_exc is not None:
        raise last_exc
    raise NumberParseException(
        NumberParseException.NOT_A_NUMBER,
        "Cannot parse phone number.",
    )


def phone_formats(parsed: phonenumbers.PhoneNumber) -> dict[str, str]:
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    international = phonenumbers.format_number(
        parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
    )
    national = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    country_code = str(parsed.country_code or "")
    national_number = str(parsed.national_number or "")
    return {
        "e164": e164,
        "international": international,
        "national": national,
        "country_code": country_code,
        "national_number": national_number,
        "digits": f"{country_code}{national_number}",
        "region": phonenumbers.region_code_for_number(parsed) or "",
    }


def build_phone_info(parsed: phonenumbers.PhoneNumber) -> dict[str, Any]:
    formats = phone_formats(parsed)
    zones = list(timezone.time_zones_for_number(parsed) or [])
    return {
        "e164": formats["e164"],
        "international": formats["international"],
        "national": formats["national"],
        "region": formats["region"] or "Unknown",
        "location": geocoder.description_for_number(parsed, "en") or "Unknown",
        "carrier": carrier.name_for_number(parsed, "en") or "Unknown",
        "type": PHONE_TYPE_MAP.get(phonenumbers.number_type(parsed), "Unknown"),
        "timezones": zones,
        "valid": bool(phonenumbers.is_valid_number(parsed)),
        "possible": bool(phonenumbers.is_possible_number(parsed)),
        "digits": formats["digits"],
        "national_number": formats["national_number"],
    }


def overview_rows(info: dict[str, Any]) -> list[tuple[str, str]]:
    timezones = info.get("timezones") or []
    tz_text = ", ".join(str(item) for item in timezones) if timezones else "Unknown"
    return [
        ("NUMBER (E.164)", str(info.get("e164") or "")),
        ("INTERNATIONAL", str(info.get("international") or "")),
        ("NATIONAL", str(info.get("national") or "")),
        ("LOCATION", str(info.get("location") or "Unknown")),
        ("REGION", str(info.get("region") or "Unknown")),
        ("TIMEZONE(S)", tz_text),
        ("CARRIER", str(info.get("carrier") or "Unknown")),
        ("TYPE", str(info.get("type") or "Unknown")),
        ("VALID", "true" if info.get("valid") else "false"),
        ("POSSIBLE", "true" if info.get("possible") else "false"),
    ]


def build_messengers(info: dict[str, Any]) -> list[tuple[str, str]]:
    digits = str(info.get("digits") or "")
    region = str(info.get("region") or "ru").lower()
    national = str(info.get("national_number") or "")
    return [
        ("WhatsApp", f"https://wa.me/{digits}"),
        ("Viber", f"https://viber.click/{digits}"),
        ("Truecaller", f"https://www.truecaller.com/search/{region}/{national}"),
    ]


async def analyze_phone(raw: str) -> PhoneReport | str:
    try:
        parsed = parse_phone(raw)
    except NumberParseException as exc:
        return f"Cannot parse phone number: {exc}"

    info = build_phone_info(parsed)
    html = render_phone_html(
        phone=info["e164"],
        overview=overview_rows(info),
        messengers=build_messengers(info),
    )
    return PhoneReport(
        phone=info["e164"],
        html=html,
    )
