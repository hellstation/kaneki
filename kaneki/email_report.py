from __future__ import annotations

from html import escape
from typing import Any

from datetime import datetime, timezone


def _e(value: Any) -> str:
    return escape(str(value), quote=True) if value is not None else ""


def _js_str(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\n")
        .replace("\r", "")
    )


def render_report_page(*, title: str, subtitle: str, body: str) -> str:
    year = datetime.now(timezone.utc).year
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Report: {_e(title)}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #0f0d0c;
            --card-bg: rgba(26, 23, 21, 0.75);
            --card-border: rgba(92, 82, 77, 0.4);
            --accent-cream: #d4c5b9;
            --accent-glow: rgba(212, 197, 185, 0.08);
            --text-color: #e4deda;
            --text-muted: #8c7e75;
        }}
        body {{
            background-color: var(--bg-dark);
            color: var(--text-color);
            font-family: 'JetBrains Mono', monospace;
            overflow-x: hidden;
        }}
        .tactical-card {{
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            backdrop-filter: blur(8px);
            position: relative;
            transition: all 0.4s cubic-bezier(0.25, 1, 0.5, 1);
        }}
        .tactical-card::before {{
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            width: 0;
            background-color: var(--accent-cream);
            transition: width 0.2s ease;
        }}
        .tactical-card:hover {{
            border-color: var(--accent-cream);
            box-shadow: 0 12px 30px var(--accent-glow);
            transform: translateY(-2px);
        }}
        .tactical-card:hover::before {{
            width: 4px;
        }}
        .messenger-btn {{
            display: block;
            text-align: center;
            border: 1px solid var(--card-border);
            background: rgba(26, 23, 21, 0.4);
            color: var(--text-color);
            text-decoration: none;
            font-size: 13px;
            font-weight: 500;
            transition: all 0.3s ease;
        }}
        .messenger-btn:hover {{
            border-color: var(--accent-cream);
            color: #ffffff;
            background: var(--card-bg);
            box-shadow: 0 4px 15px var(--accent-glow);
        }}
        .copy-btn {{
            background: transparent;
            border: 1px solid var(--card-border);
            color: var(--text-muted);
            padding: 4px 10px;
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
            cursor: pointer;
            transition: all 0.3s ease;
        }}
        .copy-btn:hover {{
            border-color: var(--accent-cream);
            color: var(--accent-cream);
            box-shadow: 0 0 15px var(--accent-glow);
        }}
        @keyframes TerminalBoot {{
            from {{ opacity: 0; transform: translateY(15px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        .boot-animate {{
            animation: TerminalBoot 0.6s cubic-bezier(0.25, 1, 0.5, 1) forwards;
        }}
        pre {{
            background: #171413;
            border: 1px solid var(--card-border);
            padding: 15px;
            overflow-x: auto;
            margin: 0;
            font-size: 13px !important;
        }}
        code {{
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 13px !important;
            line-height: 1.4 !important;
            color: var(--accent-cream);
        }}
        .tactical-text {{
            font-size: 13px !important;
            line-height: 1.4 !important;
        }}
    </style>
</head>
<body class="min-h-screen flex flex-col items-center p-4 sm:p-8">
    <main class="max-w-2xl w-full flex flex-col boot-animate py-8">
        <h1 class="text-3xl font-medium tracking-tight mb-2 text-white">OSINT Report: {_e(title)}</h1>
        <p class="text-xs text-[#a8998f] mb-8 tracking-widest font-light">{_e(subtitle)}</p>
        {body}
        <footer class="w-full flex flex-col items-center mt-12">
            <p class="text-[9px] text-[#4d443f] tracking-widest pt-2">&copy; {year} sqwrtick • kaneki</p>
        </footer>
    </main>
    <script>
        function copyToClipboard(text, btn) {{
            navigator.clipboard.writeText(text).then(function() {{
                const oldText = btn.innerText;
                btn.innerText = 'COPIED!';
                if (btn.tagName !== 'BUTTON') {{
                    btn.style.color = '#d4c5b9';
                }}
                setTimeout(function() {{
                    btn.innerText = oldText;
                    if (btn.tagName !== 'BUTTON') {{
                        btn.style.color = '';
                    }}
                }}, 500);
            }});
        }}
    </script>
</body>
</html>
"""


def render_email_html(
    *,
    email: str,
    smtp_display: str,
    google: dict[str, Any],
    connections: list[dict[str, str]],
) -> str:
    body = _smtp_block(smtp_display) + _google_block(google) + _table_block(
        "CONNECTIONS",
        connections,
        "No connections found.",
    )
    return render_report_page(
        title=email,
        subtitle="EMAIL ANALYSIS • kaneki",
        body=body,
    )


def render_username_html(
    *,
    username: str,
    checked: int,
    found: list[dict[str, Any]],
    maybe: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    not_found_count: int,
) -> str:
    body = (
        _summary_block(
            "MAIGRET",
            [
                ("CHECKED", str(checked)),
                ("FOUND", str(len(found))),
                ("MAYBE / BLOCKED", str(len(maybe))),
                ("ERROR", str(len(errors))),
                ("NOT FOUND", str(not_found_count)),
            ],
        )
        + _table_block("ACCOUNTS FOUND", found, "No accounts found.")
        + _table_block("MAYBE / BLOCKED", maybe, "None.")
        + _table_block("ERRORS", errors, "None.")
    )
    return render_report_page(
        title=username,
        subtitle="USERNAME ANALYSIS • kaneki",
        body=body,
    )


def render_ip_html(
    *,
    ip: str,
    reverse_dns: str,
    fields: dict[str, str],
    map_url: str = "",
) -> str:
    rows = [("IP", ip), ("REVERSE DNS", reverse_dns or "Not found")]
    rows.extend((key.upper(), value) for key, value in fields.items() if value)
    body = _summary_block("IP TRACKER", rows)
    if map_url:
        body += f"""
                <div class="tactical-card p-5 rounded-none mb-6">
                    <span class="text-[10px] text-[#a8998f] tracking-wider block mb-4 font-semibold">MAP</span>
                    {_service_link("Open map", map_url)}
                </div>
"""
    return render_report_page(
        title=ip,
        subtitle="IP ANALYSIS • kaneki",
        body=body,
    )


def render_phone_html(
    *,
    phone: str,
    overview: list[tuple[str, str]],
    messengers: list[tuple[str, str]],
) -> str:
    body = _summary_block("OVERVIEW", overview) + _buttons_block("MESSENGERS", messengers)
    return render_report_page(
        title=phone,
        subtitle="PHONE ANALYSIS • kaneki",
        body=body,
    )


def render_vehicle_html(
    *,
    plate: str,
    overview: list[tuple[str, str]],
) -> str:
    body = _summary_block("OVERVIEW", overview)
    return render_report_page(
        title=plate,
        subtitle="VEHICLE ANALYSIS • kaneki",
        body=body,
    )


def render_domain_html(
    *,
    domain: str,
    summary: list[tuple[str, str]],
    whois_rows: list[tuple[str, str]],
    dns_rows: list[dict[str, Any]],
    http_rows: list[tuple[str, str]],
    ssl_rows: list[tuple[str, str]],
    subdomains: list[dict[str, Any]],
    cves: list[dict[str, Any]],
    whois_error: str = "",
    subdomains_error: str = "",
) -> str:
    body = _summary_block("OVERVIEW", summary)
    if whois_error:
        body += _summary_block("WHOIS", [("ERROR", whois_error)])
    elif whois_rows:
        body += _summary_block("WHOIS", whois_rows)
    body += _table_block("DNS", dns_rows, "No DNS records found.")
    if http_rows:
        body += _summary_block("HTTP / TECH", http_rows)
    if ssl_rows:
        body += _summary_block("SSL / TLS", ssl_rows)
    body += _table_block(
        "SUBDOMAINS",
        subdomains,
        subdomains_error or "No subdomains found.",
    )
    body += _table_block("CVE", cves, "No CVEs found.")
    return render_report_page(
        title=domain,
        subtitle="DOMAIN ANALYSIS • kaneki",
        body=body,
    )


def _summary_block(title: str, rows: list[tuple[str, str]]) -> str:
    items = "".join(
        f"""
                            <span class="text-[#a8998f] whitespace-nowrap tactical-text">{_e(label)}:</span>
                            <span class="col-span-2 text-white tactical-text">{_e(value)}</span>
"""
        for label, value in rows
    )
    return f"""
                <div class="tactical-card p-5 rounded-none mb-6">
                    <span class="text-[10px] text-[#a8998f] tracking-wider block mb-4 font-semibold">{_e(title)}</span>
                    <div class="grid grid-cols-3 gap-y-3 gap-x-2 text-sm font-light">
                        {items}
                    </div>
                </div>
"""


def _code_block(title: str, code: str, element_id: str) -> str:
    return f"""
                <div class="tactical-card p-5 rounded-none mb-6">
                    <div class="flex justify-between items-center mb-4">
                        <span class="text-[10px] text-[#a8998f] tracking-wider font-semibold">{_e(title)}</span>
                        <button class="copy-btn" onclick="copyToClipboard(document.getElementById('{_e(element_id)}').innerText, this)">COPY</button>
                    </div>
                    <pre><code id="{_e(element_id)}">{_e(code)}</code></pre>
                </div>
"""


def _smtp_block(smtp_display: str) -> str:
    return _code_block(
        "SMTP (Simple Mail Transfer Protocol)",
        smtp_display,
        "smtp-raw-code",
    )


def _buttons_block(title: str, buttons: list[tuple[str, str]]) -> str:
    links = "".join(_service_link(label, url) for label, url in buttons if url)
    if not links:
        return ""
    return f"""
                <div class="tactical-card p-6 rounded-none mb-6">
                    <span class="text-[10px] text-[#a8998f] tracking-wider block mb-5 font-semibold">{_e(title)}</span>
                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-6">
                        {links}
                    </div>
                </div>
"""


def _google_block(google: dict[str, Any]) -> str:
    if not google.get("found"):
        message = google.get("error") or "No public Google account for this email"
        return f"""
                <div class="tactical-card p-6 rounded-none mb-6">
                    <span class="text-[10px] text-[#a8998f] tracking-wider block mb-5 font-semibold">GOOGLE INFRASTRUCTURE</span>
                    <p class="tactical-text text-[#8c7e75]">{_e(message)}</p>
                </div>
"""

    avatar_url = str(google.get("avatar_url") or "")
    gaia_id = str(google.get("gaia_id") or "")
    last_update = str(google.get("last_update") or "Not found")
    maps_url = str(google.get("maps_url") or "")
    calendar_url = str(google.get("calendar_url") or "")
    gplus_url = str(google.get("gplus_url") or "")

    avatar_html = ""
    if avatar_url:
        avatar_html = f"""
                            <div class="w-32 h-32 border border-[var(--card-border)] p-1 bg-[#171413] flex-shrink-0">
                                <img src="{_e(avatar_url)}" alt="Google Avatar" class="w-full h-full object-cover">
                            </div>
"""

    avatar_copy = ""
    if avatar_url:
        avatar_copy = f"""
                            <span class="text-[#a8998f] whitespace-nowrap tactical-text">AVATAR URL:</span>
                            <span class="col-span-2 truncate cursor-pointer text-[#8c7e75] hover:text-[var(--accent-cream)] hover:underline transition-all duration-200 tactical-text block" onclick="copyToClipboard('{_js_str(avatar_url)}', this)" title="Click to copy Avatar URL">
                                {_e(avatar_url)}
                            </span>
"""

    return f"""
                <div class="tactical-card p-6 rounded-none mb-6">
                    <span class="text-[10px] text-[#a8998f] tracking-wider block mb-5 font-semibold">GOOGLE INFRASTRUCTURE</span>
                    <div class="flex flex-col sm:flex-row gap-6 items-center sm:items-start mb-6 pb-6 border-b border-dashed border-[#5c524d]/30">
                        {avatar_html}
                        <div class="grid grid-cols-3 gap-y-3 gap-x-2 text-sm font-light flex-1 w-full min-w-0">
                            <span class="text-[#a8998f] whitespace-nowrap tactical-text">GOOGLE ID:</span>
                            <code class="col-span-2 text-white select-all break-all tactical-text">{_e(gaia_id)}</code>
                            <span class="text-[#a8998f] whitespace-nowrap tactical-text">LAST UPDATE:</span>
                            <span class="col-span-2 text-white tactical-text">{_e(last_update)}</span>
                            {avatar_copy}
                        </div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-6">
                        {_service_link("Google Maps", maps_url)}
                        {_service_link("Google Calendar", calendar_url)}
                        {_service_link("GPlus Archive", gplus_url)}
                    </div>
                </div>
"""


def _service_link(label: str, url: str) -> str:
    if not url:
        return ""
    return f"""
                            <div class="flex flex-col items-center gap-2 min-w-0">
                                <a href="{_e(url)}" target="_blank" class="messenger-btn w-full py-3">{_e(label)}</a>
                                <span class="text-[9px] text-[#6e635c] tracking-wider truncate w-full text-center" title="{_e(url)}">
                                    {_e(url)} ↗
                                </span>
                            </div>
"""


def _table_block(
    title: str,
    connections: list[dict[str, Any]],
    empty_text: str,
) -> str:
    if not connections:
        rows = f"""
                            <div class="border-b border-[#5c524d]/15 pb-2 last:border-b-0">
                                <div class="tactical-text text-[#8c7e75]">{_e(empty_text)}</div>
                            </div>
"""
    else:
        parts = []
        for item in connections:
            site = item.get("site") or "Unknown"
            url = item.get("url") or ""
            url_cell = (
                f"""<div class="col-span-3 truncate cursor-pointer text-[#8c7e75] hover:text-[var(--accent-cream)] border border-dashed border-transparent hover:border-[var(--card-border)] px-2 py-1 transition-all duration-200 tactical-text" onclick="copyToClipboard('{_js_str(url)}', this)" title="Click to copy URL">{_e(url)}</div>"""
                if url
                else """<div class="col-span-3 tactical-text text-[#8c7e75]">—</div>"""
            )
            parts.append(
                f"""
                            <div class="border-b border-[#5c524d]/15 pb-2 last:border-b-0">
                                <div class="grid grid-cols-5 gap-2 items-center">
                                    <div class="col-span-2 font-bold text-white pr-2 border-r border-[#5c524d]/40 truncate tactical-text">
                                        {_e(site)}
                                    </div>
                                    {url_cell}
                                </div>
                            </div>
"""
            )
        rows = "".join(parts)

    return f"""
                <div class="tactical-card p-5 rounded-none mb-6">
                    <span class="text-[10px] text-[#a8998f] tracking-wider block mb-4 font-semibold">
                        {_e(title)}
                    </span>
                    <div class="space-y-3">
                        <div class="grid grid-cols-5 gap-2 border-b border-[#5c524d]/40 pb-2 text-[10px] text-[#8c7e75] tracking-widest font-semibold">
                            <div class="col-span-2">SERVICE</div>
                            <div class="col-span-3">LINK</div>
                        </div>
                        {rows}
                    </div>
                </div>
"""
