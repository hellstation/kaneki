from __future__ import annotations

import asyncio
import logging
import os
import smtplib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .email_report import render_email_html
from .email_enrichment import (
    EMAIL_RE,
    check_github_commits,
    check_gravatar,
    check_hibp,
    resolve_mx,
    run_blackbird,
)

logger = logging.getLogger(__name__)

GHUNT_TIMEOUT = 45
HOLEHE_TIMEOUT = int(os.getenv("HOLEHE_TIMEOUT", "90"))
HOLEHE_DOMAINS = {
    "aboutme": "about.me",
    "adobe": "adobe.com",
    "amazon": "amazon.com",
    "amocrm": "amocrm.com",
    "anydo": "any.do",
    "archive": "archive.org",
    "armurerieauxerre": "armurerie-auxerre.com",
    "atlassian": "atlassian.com",
    "axonaut": "axonaut.com",
    "bitmoji": "bitmoji.com",
    "blablacar": "blablacar.com",
    "buymeacoffee": "buymeacoffee.com",
    "codecademy": "codecademy.com",
    "codepen": "codepen.io",
    "deliveroo": "deliveroo.com",
    "discord": "discord.com",
    "docker": "docker.com",
    "ebay": "ebay.com",
    "envato": "envato.com",
    "eventbrite": "eventbrite.com",
    "evernote": "evernote.com",
    "firefox": "firefox.com",
    "flickr": "flickr.com",
    "freelancer": "freelancer.com",
    "garmin": "garmin.com",
    "github": "github.com",
    "google": "google.com",
    "gravatar": "gravatar.com",
    "hubspot": "hubspot.com",
    "imgur": "imgur.com",
    "insightly": "insightly.com",
    "instagram": "instagram.com",
    "komoot": "komoot.com",
    "lastfm": "last.fm",
    "lastpass": "lastpass.com",
    "mail_ru": "mail.ru",
    "nike": "nike.com",
    "odnoklassniki": "ok.ru",
    "office365": "office365.com",
    "patreon": "patreon.com",
    "pinterest": "pinterest.com",
    "pipedrive": "pipedrive.com",
    "plurk": "plurk.com",
    "protonmail": "protonmail.ch",
    "quora": "quora.com",
    "replit": "replit.com",
    "samsung": "samsung.com",
    "snapchat": "snapchat.com",
    "soundcloud": "soundcloud.com",
    "spotify": "spotify.com",
    "strava": "strava.com",
    "tumblr": "tumblr.com",
    "twitter": "twitter.com",
    "venmo": "venmo.com",
    "vrbo": "vrbo.com",
    "vsco": "vsco.co",
    "wattpad": "wattpad.com",
    "wordpress": "wordpress.com",
    "xing": "xing.com",
    "yahoo": "yahoo.com",
    "zoho": "zoho.com",
}


@dataclass
class EmailReport:
    email: str
    smtp: dict[str, Any]
    smtp_display: str
    google: dict[str, Any]
    connections: list[dict[str, str]]
    html: str


def format_smtp_json_display(data: dict[str, Any]) -> str:
    """Render the SMTP block in the example's JSON-with-comment style."""
    mx_block = _indent_json(data.get("mx_records") or [], 2)
    steps_block = _indent_json(data.get("steps") or [], 2)
    smtp_code = data.get("smtp_code")
    smtp_code_text = "null" if smtp_code is None else str(smtp_code)
    valid_format = "true" if data.get("valid_format") else "false"
    email = data.get("email", "")
    final_status = data.get("final_status") or "unknown"
    return (
        "{\n"
        f'  "email": {_json_str(email)},\n'
        "  \n"
        "  # --- SMTP RESULTS ---\n"
        f'  "valid_format": {valid_format},\n'
        f'  "mx_records": {mx_block},\n'
        f'  "steps": {steps_block},\n'
        f'  "final_status": {_json_str(final_status)},\n'
        f'  "smtp_code": {smtp_code_text}\n'
        "}"
    )


def _json_str(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )
    return f'"{escaped}"'


def _indent_json(value: Any, spaces: int) -> str:
    import json

    dumped = json.dumps(value, indent=2, ensure_ascii=False)
    pad = " " * spaces
    lines = dumped.splitlines()
    if len(lines) == 1:
        return dumped
    return lines[0] + "\n" + "\n".join(pad + line for line in lines[1:])


def smtp_probe_host(email: str, mail_host: str) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    server = smtplib.SMTP(timeout=10)
    try:
        code, _ = server.connect(mail_host, 25)
        steps.append({"connect": {"code": int(code)}})
        code, _ = server.ehlo()
        if not (200 <= int(code) <= 299):
            code, _ = server.helo()
        steps.append({"ehlo": {"code": int(code)}})
        code, _ = server.mail("validator@localhost")
        steps.append({"mail_from": {"code": int(code)}})
        code, _ = server.rcpt(email)
        steps.append({"rcpt_to": {"email": email, "code": int(code)}})
    finally:
        try:
            server.close()
        except Exception:
            pass

    rcpt_code = None
    for step in reversed(steps):
        if "rcpt_to" in step:
            rcpt_code = step["rcpt_to"]["code"]
            break

    if rcpt_code in (250, 251):
        status = "valid"
    elif rcpt_code in (550, 551, 552, 553):
        status = "invalid"
    else:
        status = "unknown"

    return {"steps": steps, "final_status": status, "smtp_code": rcpt_code}


def smtp_probe(email: str, mx_hosts: list[str]) -> dict[str, Any]:
    for host in mx_hosts:
        try:
            return smtp_probe_host(email, host)
        except (OSError, smtplib.SMTPException) as exc:
            logger.info("SMTP probe failed for %s via %s: %s", email, host, exc)
            continue
    return {"steps": [], "final_status": "unknown", "smtp_code": None}


async def build_smtp_result(email: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "email": email,
        "valid_format": bool(EMAIL_RE.match(email)),
        "mx_records": [],
        "steps": [],
        "final_status": "unknown",
        "smtp_code": None,
    }
    if not result["valid_format"]:
        result["final_status"] = "invalid"
        return result

    domain = email.split("@", 1)[1].lower()
    mx_hosts = await resolve_mx(domain)
    result["mx_records"] = mx_hosts
    if not mx_hosts:
        return result

    probe = await asyncio.to_thread(smtp_probe, email, mx_hosts)
    result["steps"] = probe["steps"]
    result["final_status"] = probe["final_status"]
    result["smtp_code"] = probe["smtp_code"]
    return result


def _empty_google(error: str = "") -> dict[str, Any]:
    return {
        "found": False,
        "gaia_id": "",
        "last_update": "",
        "avatar_url": "",
        "maps_url": "",
        "calendar_url": "",
        "gplus_url": "",
        "error": error,
    }


def _container_name(data: dict[str, Any] | None) -> str:
    if not isinstance(data, dict):
        return ""
    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    return str(
        meta.get("container")
        or meta.get("containerType")
        or data.get("container")
        or data.get("containerType")
        or ""
    )


def parse_google_person(person_data: dict[str, Any], email: str = "") -> dict[str, Any]:
    """Extract Gaia / avatar / timestamps from a People API person payload.

    GHunt 2.3.4 crashes with KeyError 'container' when Google omits
    metadata.container. This parser never assumes that key exists.
    """
    gaia_id = str(person_data.get("personId") or "")
    last_update = ""
    avatar_url = ""

    sources = (
        (person_data.get("metadata") or {}).get("identityInfo", {}).get("sourceIds") or []
    )
    profile_source = None
    for source in sources:
        if not isinstance(source, dict):
            continue
        name = _container_name(source)
        if not gaia_id:
            gaia_id = str(source.get("id") or "")
        if name == "PROFILE" or profile_source is None:
            profile_source = source
            if name == "PROFILE":
                break
    if profile_source:
        ts = profile_source.get("lastUpdatedMicros") or ""
        if ts:
            last_update = datetime.fromtimestamp(
                float(str(ts)[:10]),
                tz=timezone.utc,
            ).strftime("%Y/%m/%d %H:%M:%S (UTC)")
        elif profile_source.get("lastUpdated"):
            last_update = str(profile_source.get("lastUpdated"))

    photos = person_data.get("photo") or []
    for photo in photos:
        if not isinstance(photo, dict):
            continue
        url = str(photo.get("url") or "")
        if url:
            avatar_url = url
            name = _container_name(photo)
            if name in {"", "PROFILE"}:
                break

    if not gaia_id:
        return _empty_google("No public Google account for this email")

    return {
        "found": True,
        "gaia_id": gaia_id,
        "last_update": last_update,
        "avatar_url": avatar_url,
        "maps_url": f"https://www.google.com/maps/contrib/{gaia_id}",
        "calendar_url": f"https://calendar.google.com/calendar/u/0/embed?src={email}" if email else "",
        "gplus_url": f"https://web.archive.org/web/*/plus.google.com/{gaia_id}*",
        "error": "",
    }


def _install_ghunt_people_patch() -> None:
    """Stop GHunt's People parser from crashing on missing metadata.container."""
    from ghunt.parsers.people import Person, PersonPhoto, PersonSourceIds

    async def _safe_scrape(self, as_client, person_data):
        parsed = parse_google_person(person_data if isinstance(person_data, dict) else {})
        self.personId = parsed.get("gaia_id") or person_data.get("personId") or ""

        for source_ids_data in (
            (person_data.get("metadata") or {}).get("identityInfo", {}).get("sourceIds") or []
        ):
            if not isinstance(source_ids_data, dict):
                continue
            container = _container_name(source_ids_data)
            if not container:
                continue
            person_source_ids = PersonSourceIds()
            person_source_ids._scrape(source_ids_data)
            self.sourceIds[container] = person_source_ids

        if parsed.get("gaia_id") and "PROFILE" not in self.sourceIds:
            self.sourceIds["PROFILE"] = PersonSourceIds()

        if parsed.get("avatar_url"):
            photo = PersonPhoto()
            photo.url = parsed["avatar_url"]
            self.profilePhotos["PROFILE"] = photo

    Person._scrape = _safe_scrape


async def ghunt_lookup(email: str) -> dict[str, Any]:
    try:
        return await asyncio.wait_for(_ghunt_lookup_inner(email), timeout=GHUNT_TIMEOUT)
    except asyncio.TimeoutError:
        return _empty_google("GHunt timed out")
    except Exception as exc:
        logger.exception("GHunt lookup failed")
        return _empty_google(str(exc)[:300])


async def _ghunt_lookup_inner(email: str) -> dict[str, Any]:
    try:
        import httpx
        from ghunt.apis.peoplepa import PeoplePaHttp
        from ghunt.objects.base import GHuntCreds
    except ImportError:
        return _empty_google("GHunt is not installed")

    creds_path = os.getenv("GHUNT_CREDS_PATH", "").strip() or None
    ghunt_creds = GHuntCreds(creds_path=creds_path) if creds_path else GHuntCreds()
    try:
        ghunt_creds.load_creds(silent=True)
    except Exception as exc:
        path = Path(ghunt_creds.creds_path)
        return _empty_google(
            "GHunt has no Google session. "
            f"Expected file: {path}. "
            "On the host run: pip install ghunt && ghunt login "
            "(Companion extension or cookies), then restart the bot. "
            f"Details: {exc}"
        )

    as_client = httpx.AsyncClient()
    try:
        _install_ghunt_people_patch()
        people_api = PeoplePaHttp(ghunt_creds)
        found, person = await people_api.people_lookup(
            as_client,
            email,
            params_template="max_details",
        )
    except KeyError as exc:
        missing = str(exc).strip("'\"")
        if missing in {"people", "container"}:
            return _empty_google("No public Google account for this email")
        return _empty_google(f"GHunt lookup failed: {exc}")
    except Exception as exc:
        return _empty_google(f"GHunt lookup failed: {exc}")
    finally:
        await as_client.aclose()

    source_ids = getattr(person, "sourceIds", None) or {}
    gaia_id = str(getattr(person, "personId", "") or "")
    if not found or not gaia_id:
        return _empty_google("No public Google account for this email")

    last_update = ""
    profile_meta = source_ids.get("PROFILE") or next(iter(source_ids.values()), None)
    last_dt = getattr(profile_meta, "lastUpdated", None) if profile_meta else None
    if last_dt:
        last_update = last_dt.strftime("%Y/%m/%d %H:%M:%S (UTC)")

    avatar_url = ""
    photos = getattr(person, "profilePhotos", None) or {}
    photo = photos.get("PROFILE") or next(iter(photos.values()), None)
    if photo is not None:
        avatar_url = str(getattr(photo, "url", "") or "")

    return {
        "found": True,
        "gaia_id": gaia_id,
        "last_update": last_update,
        "avatar_url": avatar_url,
        "maps_url": f"https://www.google.com/maps/contrib/{gaia_id}",
        "calendar_url": f"https://calendar.google.com/calendar/u/0/embed?src={email}",
        "gplus_url": f"https://web.archive.org/web/*/plus.google.com/{gaia_id}*",
        "error": "",
    }


def _pretty_site_name(name: str) -> str:
    cleaned = (name or "Unknown").replace("_", " ").strip()
    if not cleaned:
        return "Unknown"
    if cleaned.lower() in {"github", "adobe", "discord", "spotify", "instagram", "twitter"}:
        return cleaned.title()
    return cleaned[:1].upper() + cleaned[1:]


def _service_url(name: str, domain: str = "", explicit: str = "") -> str:
    if explicit.startswith("http"):
        return explicit
    host = domain or HOLEHE_DOMAINS.get(name.lower(), "")
    if host.startswith("http"):
        return host
    if host:
        return f"https://{host}"
    return explicit


def merge_connection_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    merged: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        site = str(row.get("site") or "").strip()
        url = str(row.get("url") or "").strip()
        if not site:
            continue
        key = site.lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append({"site": site, "url": url})
    return merged


def holehe_hits_to_rows(results: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows = []
    for item in results:
        if not item.get("exists"):
            continue
        name = str(item.get("name") or "")
        domain = str(item.get("domain") or HOLEHE_DOMAINS.get(name, ""))
        rows.append(
            {
                "site": _pretty_site_name(name),
                "url": _service_url(name, domain),
            }
        )
    return rows


def _load_holehe_modules() -> dict[str, Any]:
    import importlib
    import pkgutil

    import holehe.modules

    loaded: dict[str, Any] = {}
    for _finder, name, _is_pkg in pkgutil.walk_packages(
        holehe.modules.__path__,
        "holehe.modules.",
    ):
        if name.endswith(".__main__"):
            continue
        try:
            loaded[name] = importlib.import_module(name)
        except Exception:
            logger.debug("Skipping holehe module %s", name, exc_info=True)
    return loaded


def run_holehe(email: str) -> list[dict[str, str]]:
    """Return sites where the email is registered (exists=True)."""
    try:
        import httpx
        import trio
        from holehe.core import get_functions, launch_module
    except ImportError:
        logger.info("holehe is not installed")
        return []

    async def scan() -> list[dict[str, Any]]:
        modules = _load_holehe_modules()
        websites = get_functions(modules)
        if not websites:
            return []
        out: list[dict[str, Any]] = []
        client = httpx.AsyncClient(timeout=10)
        try:
            with trio.move_on_after(HOLEHE_TIMEOUT):
                async with trio.open_nursery() as nursery:
                    for website in websites:
                        nursery.start_soon(launch_module, website, email, client, out)
        finally:
            await client.aclose()
        return out

    try:
        results = trio.run(scan)
    except Exception:
        logger.exception("holehe scan failed")
        return []
    return holehe_hits_to_rows(results)


def _blackbird_rows(email: str) -> list[dict[str, str]]:
    services, _note = run_blackbird(email)
    rows = []
    for service in services[:80]:
        site = str(service.get("site") or "").strip()
        url = str(service.get("url") or "").strip()
        if site:
            rows.append({"site": site, "url": url})
    return rows


async def _public_confirmed_rows(email: str) -> list[dict[str, str]]:
    import aiohttp

    async with aiohttp.ClientSession() as session:
        findings = await asyncio.gather(
            check_gravatar(session, email),
            check_github_commits(session, email),
            check_hibp(session, email),
        )
    rows = []
    for item in findings:
        if item.get("status") != "confirmed":
            continue
        site = str(item.get("source") or "").strip()
        url = str(item.get("url") or "").strip()
        if site:
            rows.append({"site": site, "url": url})
    return rows


async def collect_connections(email: str) -> list[dict[str, str]]:
    holehe_rows, blackbird_rows, public_rows = await asyncio.gather(
        asyncio.to_thread(run_holehe, email),
        asyncio.to_thread(_blackbird_rows, email),
        _public_confirmed_rows(email),
    )
    return merge_connection_rows(holehe_rows + blackbird_rows + public_rows)


async def analyze_email(email: str) -> EmailReport | str:
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        return "Invalid email format."

    smtp_data, google, connections = await asyncio.gather(
        build_smtp_result(email),
        ghunt_lookup(email),
        collect_connections(email),
    )
    smtp_display = format_smtp_json_display(smtp_data)
    html = render_email_html(
        email=email,
        smtp_display=smtp_display,
        google=google,
        connections=connections,
    )
    return EmailReport(
        email=email,
        smtp=smtp_data,
        smtp_display=smtp_display,
        google=google,
        connections=connections,
        html=html,
    )
