"""Email OSINT helpers (DNS, blackbird, public checks)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import smtplib
import subprocess
from typing import Any, Optional, Union

import aiohttp

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

async def resolve_mx(domain: str) -> list[str]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://dns.google/resolve?name={domain}&type=MX",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status != 200:
                    return []
                data = await response.json()
    except Exception:
        return []

    hosts = []
    for answer in data.get("Answer", []):
        raw = str(answer.get("data", "")).strip()
        parts = raw.split()
        host = parts[-1].rstrip(".") if parts else ""
        if host:
            hosts.append(host)
    return hosts


def smtp_check(email: str, mail_host: str) -> tuple[str, str]:
    try:
        with smtplib.SMTP(mail_host, 25, timeout=10) as server:
            server.ehlo_or_helo_if_needed()
            server.mail("validator@localhost")
            code, message = server.rcpt(email)
    except (OSError, smtplib.SMTPException) as exc:
        return "Unknown", f"SMTP connection failed: {exc}"

    text = message.decode(errors="ignore") if isinstance(message, bytes) else str(message)
    if code in (250, 251):
        return "Valid", f"SMTP accepted recipient ({code}: {text})"
    if code in (550, 551, 553):
        return "Invalid", f"SMTP rejected recipient ({code}: {text})"
    return "Unknown", f"SMTP response {code}: {text}"


async def resolve_a(domain: str) -> list[str]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://dns.google/resolve?name={domain}&type=A",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if response.status != 200:
                    return []
                data = await response.json()
    except Exception:
        return []
    return [answer["data"] for answer in data.get("Answer", []) if answer.get("data")]


async def resolve_dns_records(domain: str) -> dict[str, list[str]]:
    record_types = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
    async with aiohttp.ClientSession() as session:
        tasks = [resolve_dns_record(session, domain, record_type) for record_type in record_types]
        results = await asyncio.gather(*tasks)
    return dict(zip(record_types, results))


async def resolve_dns_record(
    session: aiohttp.ClientSession,
    domain: str,
    record_type: str,
) -> list[str]:
    try:
        async with session.get(
            f"https://dns.google/resolve?name={domain}&type={record_type}",
            timeout=aiohttp.ClientTimeout(total=10),
        ) as response:
            if response.status != 200:
                return []
            data = await response.json()
    except Exception:
        return []

    values = []
    seen = set()
    for answer in data.get("Answer", []):
        raw = str(answer.get("data", "")).strip()
        if not raw:
            continue
        value = normalize_dns_value(record_type, raw)
        if value and value not in seen:
            seen.add(value)
            values.append(value)
    return values


def normalize_dns_value(record_type: str, value: str) -> str:
    value = value.strip()
    if record_type in {"NS", "CAA"}:
        return value.rstrip(".")
    if record_type == "MX":
        parts = value.split()
        if len(parts) >= 2:
            return f"{parts[0]} {parts[-1].rstrip('.')}"
        return value.rstrip(".")
    if record_type == "TXT":
        return value.replace('" "', "").strip('"')
    return value


def extract_certificate_emails(domain: str, entries: list[dict[str, Any]]) -> list[str]:
    emails: set[str] = set()
    for entry in entries:
        found = re.findall(
            r"[A-Za-z0-9._%+\-]+@" + re.escape(domain),
            entry.get("name_value", ""),
        )
        emails.update(found)
    return sorted(emails)


def extract_certificate_subdomains(domain: str, entries: list[dict[str, Any]]) -> list[str]:
    subdomains: set[str] = set()
    for entry in entries:
        names = str(entry.get("name_value", "")).splitlines()
        for name in names:
            clean_name = name.strip().lower().lstrip("*.").rstrip(".")
            if clean_name and clean_name.endswith(domain) and clean_name != domain:
                subdomains.add(clean_name)
    return sorted(subdomains)


async def fetch_crtsh_entries(domain: str) -> list[dict[str, Any]]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=aiohttp.ClientTimeout(total=15),
            ) as response:
                if response.status != 200:
                    return []
                entries = await response.json(content_type=None)
    except Exception:
        return []
    return entries if isinstance(entries, list) else []


async def fetch_http_intel(domain: str) -> dict[str, Any]:
    for scheme in ("https", "http"):
        result = await fetch_single_http_intel(f"{scheme}://{domain}")
        if result.get("ok"):
            return result
    return {
        "ok": False,
        "url": f"https://{domain}",
        "error": "HTTP/HTTPS request failed",
        "headers": {},
        "cookies": [],
        "technologies": [],
    }


async def fetch_single_http_intel(url: str) -> dict[str, Any]:
    headers = {"User-Agent": "Telegram-Toolbox-Bot/1.0"}
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(
                url,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=12),
            ) as response:
                body = await response.text(errors="ignore")
                response_headers = {key: value for key, value in response.headers.items()}
                cookies = [cookie.key for cookie in response.cookies.values()]
                return {
                    "ok": True,
                    "url": str(response.url),
                    "status": response.status,
                    "headers": response_headers,
                    "cookies": cookies,
                    "technologies": detect_technologies(response_headers, cookies, body[:200000]),
                }
    except Exception as exc:
        return {
            "ok": False,
            "url": url,
            "error": str(exc),
            "headers": {},
            "cookies": [],
            "technologies": [],
        }


def detect_technologies(headers: dict[str, str], cookies: list[str], body: str) -> list[str]:
    found: set[str] = set()
    header_text = "\n".join(f"{key}: {value}" for key, value in headers.items()).lower()
    cookie_text = " ".join(cookies).lower()
    body_text = body.lower()

    signatures = {
        "Cloudflare": ["cloudflare", "__cf_bm", "cf-ray"],
        "nginx": ["server: nginx"],
        "Apache": ["server: apache"],
        "LiteSpeed": ["litespeed"],
        "Vercel": ["vercel", "_vercel"],
        "Netlify": ["netlify", "x-nf-request-id"],
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "WooCommerce": ["woocommerce"],
        "Shopify": ["shopify", "x-shopid", "_shopify"],
        "Next.js": ["_next/static", "next-router", "x-nextjs"],
        "Nuxt": ["__nuxt", "nuxt"],
        "React": ["react", "react-dom"],
        "Vue": ["vue.js", "__vue", "data-v-"],
        "Angular": ["ng-version", "angular"],
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap"],
        "Google Analytics": ["google-analytics", "gtag(", "googletagmanager"],
        "Yandex Metrica": ["mc.yandex.ru", "ym("],
        "PHP": ["x-powered-by: php", "phpsessid"],
        "ASP.NET": ["asp.net", "aspxauth"],
    }

    haystack = f"{header_text}\n{cookie_text}\n{body_text}"
    for technology, markers in signatures.items():
        if any(marker in haystack for marker in markers):
            found.add(technology)
    return sorted(found)


def format_http_intel(data: dict[str, Any]) -> str:
    if not data.get("ok"):
        return f"HTTP intel:\nStatus: request failed\nError: {data.get('error', 'Unknown')}"

    interesting_headers = [
        "server",
        "x-powered-by",
        "content-type",
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "cf-ray",
        "x-vercel-id",
        "x-cache",
    ]
    headers = data.get("headers", {})
    normalized_headers = {key.lower(): value for key, value in headers.items()}

    lines = [
        "HTTP intel:",
        f"URL: {data.get('url', 'Unknown')}",
        f"Status: {data.get('status', 'Unknown')}",
    ]
    lines.append("Headers:")
    added = False
    for header in interesting_headers:
        value = normalized_headers.get(header)
        if value:
            lines.append(f"• {header}: {value}")
            added = True
    if not added:
        lines.append("• No selected headers found")

    cookies = data.get("cookies", [])
    lines.append("Cookies:")
    lines.extend(f"• {cookie}" for cookie in cookies[:10]) if cookies else lines.append("• Not set")
    if len(cookies) > 10:
        lines.append(f"• ... and {len(cookies) - 10} more")

    technologies = data.get("technologies", [])
    lines.append("Tech stack:")
    lines.extend(f"• {technology}" for technology in technologies) if technologies else lines.append("• Not detected")
    return "\n".join(lines)


def run_blackbird(email: str) -> tuple[list[dict[str, str]], str]:
    if not shutil.which("blackbird"):
        return [], "Blackbird CLI not found in PATH"

    commands = [
        ["blackbird", "--email", email, "--json"],
        ["blackbird", "-e", email, "--json"],
        ["blackbird", email, "--json"],
        ["blackbird", "--email", email],
        ["blackbird", "-e", email],
        ["blackbird", email],
    ]
    last_error = ""

    for command in commands:
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
        except Exception as exc:
            last_error = str(exc)
            continue

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        blob = extract_json_blob(stdout)
        if blob is not None:
            return normalize_blackbird_services(blob), f"Blackbird mode: {' '.join(command)}"

        services = parse_blackbird_text(f"{stdout}\n{stderr}".strip())
        if services:
            return services, f"Blackbird mode: {' '.join(command)}"
        if proc.returncode != 0 and stderr:
            last_error = stderr.strip()

    return [], f"Blackbird run failed: {last_error or 'no parseable results'}"


def extract_json_blob(raw: str) -> Optional[Union[dict[str, Any], list[Any]]]:
    raw = raw.strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        pass

    candidates = []
    first_obj = raw.find("{")
    last_obj = raw.rfind("}")
    if first_obj != -1 and last_obj != -1 and last_obj > first_obj:
        candidates.append(raw[first_obj : last_obj + 1])
    first_arr = raw.find("[")
    last_arr = raw.rfind("]")
    if first_arr != -1 and last_arr != -1 and last_arr > first_arr:
        candidates.append(raw[first_arr : last_arr + 1])

    for chunk in candidates:
        try:
            return json.loads(chunk)
        except Exception:
            continue
    return None


def normalize_blackbird_services(payload: Union[dict[str, Any], list[Any]]) -> list[dict[str, str]]:
    services = []
    items = payload.items() if isinstance(payload, dict) else enumerate(payload)

    for key, value in items:
        if not isinstance(value, dict):
            continue
        site = str(value.get("site") or value.get("name") or value.get("service") or key)
        url = str(value.get("url") or value.get("link") or "")
        status_text = str(value.get("status", "")).lower()
        found = value.get("found")

        is_found = bool(found) if isinstance(found, bool) else False
        if not is_found and status_text:
            is_found = status_text in {"found", "exists", "valid", "hit", "true"}
        if not is_found and url:
            is_found = True
        if is_found:
            services.append({"site": site, "url": url})
    return services


def parse_blackbird_text(stdout: str) -> list[dict[str, str]]:
    services = []
    pattern = re.compile(
        r"(?i)([A-Za-z0-9 _.-]{2,})\s*[:\-]\s*(found|exists|valid|yes).*(https?://\S+)?"
    )
    for line in stdout.splitlines():
        match = pattern.search(line.strip())
        if not match:
            continue
        services.append(
            {
                "site": match.group(1).strip(),
                "url": (match.group(3) or "").strip().rstrip(").,;"),
            }
        )
    return services


async def check_gravatar(session: aiohttp.ClientSession, email: str) -> dict[str, str]:
    email_hash = hashlib.md5(email.encode("utf-8")).hexdigest()
    url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
            if response.status == 200:
                return public_finding("Gravatar", "confirmed", "high", "Avatar exists for exact email hash", url)
            if response.status == 404:
                return public_finding("Gravatar", "not_found", "high", "No avatar for exact email hash", url)
            return public_finding("Gravatar", "unknown", "low", f"Unexpected HTTP status: {response.status}", url)
    except Exception as exc:
        return public_finding("Gravatar", "unknown", "low", f"Request failed: {exc}", url)


async def check_github_commits(session: aiohttp.ClientSession, email: str) -> dict[str, str]:
    url = f"https://api.github.com/search/commits?q={email}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "Telegram-Toolbox-Bot"}
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
            if response.status != 200:
                return public_finding("GitHub Commits", "unknown", "low", f"GitHub API status: {response.status}", url)
            data = await response.json()
    except Exception as exc:
        return public_finding("GitHub Commits", "unknown", "low", f"Request failed: {exc}", url)

    total = int(data.get("total_count", 0))
    if total > 0:
        return public_finding("GitHub Commits", "confirmed", "high", f"Email found in {total} indexed commit record(s)", url)
    return public_finding("GitHub Commits", "not_found", "high", "No indexed commits with this email", url)


async def check_hibp(session: aiohttp.ClientSession, email: str) -> dict[str, str]:
    api_key = os.getenv("HIBP_API_KEY", "").strip()
    if not api_key:
        return public_finding(
            "Have I Been Pwned",
            "unknown",
            "high",
            "Skipped: set HIBP_API_KEY to enable this check",
            "https://haveibeenpwned.com/API/v3",
        )

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {"hibp-api-key": api_key, "user-agent": "Telegram-Toolbox-Bot"}
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
            if response.status == 404:
                return public_finding("Have I Been Pwned", "not_found", "high", "No breaches found for this email", "https://haveibeenpwned.com/")
            if response.status != 200:
                return public_finding("Have I Been Pwned", "unknown", "low", f"HIBP API status: {response.status}", "https://haveibeenpwned.com/API/v3")
            breaches = await response.json()
    except Exception as exc:
        return public_finding("Have I Been Pwned", "unknown", "low", f"Request failed: {exc}", "https://haveibeenpwned.com/API/v3")

    names = [breach.get("Name", "") for breach in breaches if breach.get("Name")]
    suffix = "..." if len(names) > 8 else ""
    return public_finding(
        "Have I Been Pwned",
        "confirmed",
        "high",
        f"Found in breaches: {', '.join(names[:8])}{suffix}",
        "https://haveibeenpwned.com/",
    )


def public_finding(source: str, status: str, confidence: str, evidence: str, url: str) -> dict[str, str]:
    return {
        "source": source,
        "status": status,
        "confidence": confidence,
        "evidence": evidence,
        "url": url,
    }


def format_mapping(title: str, data: dict[str, Any]) -> str:
    lines = [title, ""]
    for key, value in data.items():
        lines.append(f"{key}: {value}")
    return "\n".join(lines)
