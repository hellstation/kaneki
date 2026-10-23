"""Merged WHOIS / Domain + IP tracker HTML reports."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .email_report import render_domain_html, render_ip_html
from .network_intel import fetch_ipinfo, is_ip_address, reverse_dns
from .security.service import analyze_domain_report

logger = logging.getLogger(__name__)

IP_FIELD_ORDER = (
    "hostname",
    "org",
    "asn",
    "city",
    "region",
    "country",
    "postal",
    "loc",
    "timezone",
    "anycast",
)


@dataclass
class HostReport:
    target: str
    kind: str
    html: str


def parse_host_target(raw: str) -> tuple[str, str] | None:
    raw = raw.strip()
    if raw.startswith("[") and "]" in raw:
        raw = raw[1 : raw.index("]")]
    if is_ip_address(raw):
        return "ip", raw

    host = raw
    if "://" in raw:
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
        host = parsed.hostname or raw
    elif "/" in raw:
        host = raw.split("/", 1)[0]

    if host and is_ip_address(host):
        return "ip", host

    from .security.validators import normalize_domain

    domain = normalize_domain(raw)
    if domain:
        return "domain", domain
    return None


async def analyze_host(raw: str) -> HostReport | str:
    parsed = parse_host_target(raw)
    if not parsed:
        return "Send a domain (example.com) or an IP address."
    kind, target = parsed
    if kind == "ip":
        return await _analyze_ip(target)
    return await _analyze_domain(target)


async def _analyze_ip(ip: str) -> HostReport | str:
    info, hostname = await asyncio.gather(fetch_ipinfo(ip), reverse_dns(ip))
    if isinstance(info, str):
        return info

    fields: dict[str, str] = {}
    for key in IP_FIELD_ORDER:
        value = info.get(key)
        if value in (None, "", False):
            continue
        fields[key] = str(value)
    for key, value in info.items():
        if key in {"ip", "readme"} or key in fields:
            continue
        if value in (None, "", False):
            continue
        fields[str(key)] = str(value)

    loc = str(info.get("loc") or "")
    map_url = f"https://maps.google.com/?q={loc}" if loc else ""
    html = render_ip_html(
        ip=ip,
        reverse_dns=hostname or str(info.get("hostname") or ""),
        fields=fields,
        map_url=map_url,
    )
    return HostReport(
        target=ip,
        kind="ip",
        html=html,
    )


async def _analyze_domain(domain: str) -> HostReport | str:
    report = await analyze_domain_report(domain)
    if isinstance(report, str):
        return report

    result = report.result
    risk = result.risk
    tech_names = [result.tech_info.display_name(name) for name, _cat in result.tech_info.detected]
    total_cves = sum(len(r.entries) for r in result.cve_results)

    summary = [
        ("RISK", f"{risk.level} (score {risk.score})"),
        ("TECH", ", ".join(tech_names) if tech_names else "Not detected"),
        ("SUBDOMAINS", str(len(result.subdomains))),
        ("CVEs", str(total_cves)),
        ("ATTACK PATHS", str(len(result.attack_paths))),
    ]

    whois_error = result.whois_info.error or ""
    whois_rows: list[tuple[str, str]] = []
    if not whois_error:
        w = result.whois_info
        whois_map = [
            ("Domain", w.domain or domain),
            ("Registrar", w.registrar),
            ("Organization", w.org),
            ("Country", w.country),
            ("State", w.state),
            ("Created", w.creation_date),
            ("Updated", w.updated_date),
            ("Expires", w.expiration_date),
            ("Name servers", ", ".join(w.name_servers or [])),
            ("Status", w.status),
            ("Emails", w.emails),
            ("DNSSEC", w.dnssec),
        ]
        whois_rows = [(label, value) for label, value in whois_map if value]

    dns_rows = []
    for record_type, values in result.dns_info.records.items():
        dns_rows.append({"site": record_type, "url": ", ".join(values)})
    if result.dns_info.errors.get("general"):
        dns_rows.append({"site": "ERROR", "url": result.dns_info.errors["general"]})

    t = result.tech_info
    http_rows: list[tuple[str, str]] = []
    if t.error:
        http_rows.append(("ERROR", t.error))
    else:
        if t.final_url:
            http_rows.append(("URL", t.final_url))
        if t.status_code is not None:
            http_rows.append(("Status", str(t.status_code)))
        if t.web_server:
            http_rows.append(("Server", t.web_server))
        if t.powered_by:
            http_rows.append(("X-Powered-By", t.powered_by))
        if tech_names:
            http_rows.append(("Tech", ", ".join(tech_names)))
        if t.cookies:
            http_rows.append(("Cookies", ", ".join(t.cookies[:12])))
        for header, value in (t.selected_headers or {}).items():
            http_rows.append((header, value))

    ssl_rows: list[tuple[str, str]] = []
    ssl = result.ssl_info
    if ssl.error:
        ssl_rows.append(("ERROR", ssl.error))
    elif ssl.has_ssl:
        ssl_rows = [
            ("Issuer", ssl.issuer or "Unknown"),
            ("Subject", ssl.subject or "Unknown"),
            ("Valid from", ssl.not_before or "Unknown"),
            ("Valid until", ssl.not_after or "Unknown"),
            ("Protocol", ssl.protocol_version or "Unknown"),
            ("Self-signed", "yes" if ssl.is_self_signed else "no"),
            ("Expired", "yes" if ssl.is_expired else "no"),
        ]
        if ssl.days_until_expiry is not None:
            ssl_rows.append(("Days left", str(ssl.days_until_expiry)))
    else:
        ssl_rows.append(("SSL", "Not found"))

    subdomains = [
        {"site": name, "url": f"https://{name.removeprefix('*.')}"}
        for name in result.subdomains[:40]
    ]

    cves: list[dict[str, Any]] = []
    for block in result.cve_results:
        for entry in block.entries[:8]:
            cves.append(
                {
                    "site": f"{entry.cve_id} ({entry.severity or 'n/a'})",
                    "url": f"https://nvd.nist.gov/vuln/detail/{entry.cve_id}",
                }
            )
            if len(cves) >= 30:
                break
        if len(cves) >= 30:
            break

    html = render_domain_html(
        domain=domain,
        summary=summary,
        whois_rows=whois_rows,
        dns_rows=dns_rows,
        http_rows=http_rows,
        ssl_rows=ssl_rows,
        subdomains=subdomains,
        cves=cves,
        whois_error=whois_error,
        subdomains_error=result.crtsh_error,
    )
    return HostReport(
        target=domain,
        kind="domain",
        html=html,
    )
