"""
modules/report_html.py — рендеринг результатов анализа в единый
самодостаточный HTML-документ (тёмная техническая тема, инлайн CSS,
без внешних зависимостей кроме шрифтов Google Fonts).

Документ полностью автономен: открывается в любом браузере,
корректно отображается на мобильных устройствах.
"""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from .analyzer import FullAnalysisResult

# ---- дизайн-токены -------------------------------------------------------

SEVERITY_COLORS = {
    "Low": "#34D399",
    "Medium": "#FBBF24",
    "High": "#FB923C",
    "Critical": "#F87171",
}

CVE_SEVERITY_COLORS = {
    "CRITICAL": "#F87171",
    "HIGH": "#FB923C",
    "MEDIUM": "#FBBF24",
    "LOW": "#34D399",
}

RISK_GAUGE_MAX = 40  # верхняя граница шкалы для визуализации score


def _e(value) -> str:
    """Короткий алиас для html.escape с приведением к строке."""
    return escape(str(value)) if value is not None else ""


def _gauge_arc(score: int, level: str) -> str:
    """
    Строит SVG-дугу риска (полукруг) — единственный по-настоящему
    сигнатурный визуальный элемент отчёта, который кодирует реальное
    значение risk score, а не является чистой декорацией.
    """
    clamped = max(0, min(score, RISK_GAUGE_MAX))
    fraction = clamped / RISK_GAUGE_MAX

    radius = 90
    circumference = 3.14159265 * radius
    dash = circumference * fraction
    color = SEVERITY_COLORS.get(level, "#8D96AC")

    return f'''
    <svg viewBox="0 0 200 120" class="gauge" role="img" aria-label="Risk score {clamped} of {RISK_GAUGE_MAX}">
      <path d="M 10 100 A {radius} {radius} 0 0 1 190 100"
            fill="none" stroke="#232B40" stroke-width="14" stroke-linecap="round"/>
      <path d="M 10 100 A {radius} {radius} 0 0 1 190 100"
            fill="none" stroke="{color}" stroke-width="14" stroke-linecap="round"
            stroke-dasharray="{dash:.1f} {circumference:.1f}"/>
      <text x="100" y="92" text-anchor="middle" class="gauge-score">{clamped}</text>
      <text x="100" y="112" text-anchor="middle" class="gauge-max">/ {RISK_GAUGE_MAX}</text>
    </svg>
    '''


def _section_whois(result: FullAnalysisResult) -> str:
    w = result.whois_info
    if w.error:
        return f'<p class="muted">Не удалось получить WHOIS-данные: {_e(w.error)}</p>'

    rows = []
    fields = [
        ("Domain", w.domain or result.domain),
        ("Registrar", w.registrar),
        ("Organization", w.org),
        ("Country", w.country),
        ("State", w.state),
        ("Created", w.creation_date),
        ("Updated", w.updated_date),
        ("Expires", w.expiration_date),
        ("Status", w.status),
        ("Emails", w.emails),
        ("DNSSEC", w.dnssec),
    ]
    for label, value in fields:
        shown = value if value else "Unknown"
        rows.append(
            f'<div class="kv"><span class="k">{_e(label)}</span>'
            f'<span class="v">{_e(shown)}</span></div>'
        )

    if w.name_servers:
        ns = ", ".join(w.name_servers[:12])
        rows.append(
            f'<div class="kv"><span class="k">Name Servers</span>'
            f'<span class="v mono">{_e(ns)}</span></div>'
        )
    else:
        rows.append(
            '<div class="kv"><span class="k">Name Servers</span>'
            '<span class="v">Unknown</span></div>'
        )

    return "\n".join(rows)


def _section_dns(result: FullAnalysisResult) -> str:
    from .dns_utils import PRIMARY_RECORD_TYPES

    d = result.dns_info
    if d.errors.get("general") and not d.records:
        return f'<p class="muted">{_e(d.errors["general"])}</p>'

    rows = []
    # Always show primary types (including empty as Not found), then extras if present
    shown_types = list(PRIMARY_RECORD_TYPES)
    for rtype in d.records:
        if rtype not in shown_types:
            shown_types.append(rtype)

    for rtype in shown_types:
        values = d.records.get(rtype) or []
        if values:
            items = "".join(f'<div class="mono">• {_e(v)}</div>' for v in values[:12])
            if len(values) > 12:
                items += f'<div class="muted">• ... and {len(values) - 12} more</div>'
            rows.append(
                f'<div class="kv dns-block"><span class="k">{_e(rtype)}</span>'
                f'<span class="v">{items}</span></div>'
            )
        else:
            rows.append(
                f'<div class="kv"><span class="k">{_e(rtype)}</span>'
                f'<span class="v muted">Not found</span></div>'
            )
    return "\n".join(rows)


def _section_http_intel(result: FullAnalysisResult) -> str:
    t = result.tech_info
    if t.error and not t.status_code:
        return f'<p class="muted">HTTP intel unavailable: {_e(t.error)}</p>'

    parts: list[str] = []
    if t.final_url:
        parts.append(
            f'<div class="kv"><span class="k">URL</span>'
            f'<span class="v mono">{_e(t.final_url)}</span></div>'
        )
    if t.status_code is not None:
        parts.append(
            f'<div class="kv"><span class="k">Status</span>'
            f'<span class="v mono">{t.status_code}</span></div>'
        )

    if t.selected_headers:
        header_items = "".join(
            f'<div class="mono">• {_e(k)}: {_e(v if len(v) <= 120 else v[:120] + "…")}</div>'
            for k, v in t.selected_headers.items()
        )
        parts.append(
            f'<div class="kv dns-block"><span class="k">Headers</span>'
            f'<span class="v">{header_items}</span></div>'
        )
    else:
        parts.append(
            '<div class="kv"><span class="k">Headers</span>'
            '<span class="v muted">No selected headers found</span></div>'
        )

    if t.cookies:
        cookie_items = "".join(f'<div class="mono">• {_e(c)}</div>' for c in t.cookies[:20])
        if len(t.cookies) > 20:
            cookie_items += f'<div class="muted">• ... and {len(t.cookies) - 20} more</div>'
        parts.append(
            f'<div class="kv dns-block"><span class="k">Cookies</span>'
            f'<span class="v">{cookie_items}</span></div>'
        )
    else:
        parts.append(
            '<div class="kv"><span class="k">Cookies</span>'
            '<span class="v muted">Not set</span></div>'
        )

    if t.detected:
        chips = "".join(
            f'<span class="chip">{_e(t.display_name(name))}'
            f'<span class="chip-cat">{_e(cat)}</span></span>'
            for name, cat in t.detected
        )
        parts.append(
            f'<p class="muted" style="margin:14px 0 8px">Tech stack</p>'
            f'<div class="chips">{chips}</div>'
        )
    else:
        parts.append('<p class="muted" style="margin-top:14px">Tech stack: not detected.</p>')

    return "\n".join(parts)


def _section_tech(result: FullAnalysisResult) -> str:
    t = result.tech_info
    if t.error and not t.detected:
        return f'<p class="muted">Не удалось определить технологии: {_e(t.error)}</p>'

    rows = []
    if t.status_code:
        rows.append(
            f'<div class="kv"><span class="k">HTTP статус</span>'
            f'<span class="v mono">{t.status_code}</span></div>'
        )
    if t.web_server:
        rows.append(
            f'<div class="kv"><span class="k">Веб-сервер</span>'
            f'<span class="v mono">{_e(t.web_server)}</span></div>'
        )
    if t.powered_by:
        rows.append(
            f'<div class="kv"><span class="k">X-Powered-By</span>'
            f'<span class="v mono">{_e(t.powered_by)}</span></div>'
        )

    html_out = "\n".join(rows)

    if t.detected:
        chips = "".join(
            f'<span class="chip">{_e(t.display_name(name))}<span class="chip-cat">{_e(cat)}</span></span>'
            for name, cat in t.detected
        )
        html_out += f'<div class="chips">{chips}</div>'
    else:
        html_out += '<p class="muted">Явных CMS/фреймворков не обнаружено.</p>'

    return html_out


def _section_certificate_emails(result: FullAnalysisResult) -> str:
    emails = result.certificate_emails
    if not emails:
        return '<p class="muted">No emails found in crt.sh.</p>'
    chips = "".join(f'<span class="chip mono">{_e(e)}</span>' for e in emails)
    count_note = f'<p class="muted" style="margin-bottom:10px">Found: {len(emails)}</p>'
    return count_note + f'<div class="chips">{chips}</div>'


def _section_cves(result: FullAnalysisResult) -> str:
    if not result.cve_results:
        return '<p class="muted">Технологии не определены — поиск CVE не выполнялся.</p>'

    blocks = []
    any_found = False

    for r in result.cve_results:
        match_badge = (
            '<span class="match-badge match-cpe">точно по версии</span>'
            if r.matched_by == "cpe"
            else '<span class="match-badge match-keyword">по ключевым словам</span>'
        )

        if r.error:
            blocks.append(
                f'<div class="cve-group"><h4>{_e(r.technology)} {match_badge}</h4>'
                f'<p class="muted">{_e(r.error)}</p></div>'
            )
            continue
        if not r.entries:
            blocks.append(
                f'<div class="cve-group"><h4>{_e(r.technology)} {match_badge}</h4>'
                f'<p class="muted">CVE не найдены</p></div>'
            )
            continue

        any_found = True
        items = []
        for e in r.entries:
            sev = (e.severity or "N/A").upper()
            color = CVE_SEVERITY_COLORS.get(sev, "#8D96AC")
            score_html = f'<span class="cve-score">CVSS {e.score}</span>' if e.score is not None else ""
            epss_html = (
                f'<span class="cve-epss">EPSS {e.epss * 100:.1f}%</span>'
                if e.epss is not None else ""
            )
            items.append(f'''
              <div class="cve-item">
                <div class="cve-head">
                  <span class="cve-id mono">{_e(e.cve_id)}</span>
                  <span class="sev-badge" style="--sev-color:{color}">{_e(sev)}</span>
                  {score_html}
                  {epss_html}
                </div>
                <p class="cve-summary">{_e(e.summary)}</p>
              </div>
            ''')
        blocks.append(
            f'<div class="cve-group"><h4>{_e(r.technology)} {match_badge}</h4>{"".join(items)}</div>'
        )

    if not any_found:
        blocks.append('<p class="muted">Актуальных CVE для обнаруженных технологий не найдено.</p>')

    return "\n".join(blocks)


def _section_subdomains(result: FullAnalysisResult) -> str:
    subs = result.subdomains
    if not subs:
        message = result.crtsh_error or (
            "Поддомены не найдены в публичных Certificate Transparency логах (crt.sh)."
        )
        return f'<p class="muted">{_e(message)}</p>'

    chips = "".join(f'<span class="chip">{_e(s)}</span>' for s in subs)
    count_note = f'<p class="muted" style="margin-bottom:10px">Найдено: {len(subs)}</p>'
    return count_note + f'<div class="chips">{chips}</div>'


def _section_ssl(result: FullAnalysisResult) -> str:
    s = result.ssl_info
    if s.error and not s.has_ssl:
        return f'<p class="muted">{_e(s.error)}</p>'
    if not s.has_ssl:
        return '<p class="muted">HTTPS недоступен или сертификат не получен.</p>'

    rows = [
        f'<div class="kv"><span class="k">Издатель</span><span class="v">{_e(s.issuer)}</span></div>',
        f'<div class="kv"><span class="k">Кому выдан</span><span class="v">{_e(s.subject)}</span></div>',
        f'<div class="kv"><span class="k">Действителен</span><span class="v mono">{_e(s.not_before)} — {_e(s.not_after)}</span></div>',
        f'<div class="kv"><span class="k">Протокол</span><span class="v mono">{_e(s.protocol_version)}</span></div>',
    ]

    badges = []
    if s.is_expired:
        badges.append('<span class="match-badge" style="color:#F87171;background:rgba(248,113,113,0.12);border:1px solid rgba(248,113,113,0.3)">Сертификат просрочен</span>')
    elif s.is_expiring_soon:
        badges.append(f'<span class="match-badge" style="color:#FBBF24;background:rgba(251,191,36,0.12);border:1px solid rgba(251,191,36,0.3)">Истекает через {s.days_until_expiry} дн.</span>')
    else:
        badges.append(f'<span class="match-badge match-cpe">Действителен ещё {s.days_until_expiry} дн.</span>')

    if s.is_self_signed:
        badges.append('<span class="match-badge" style="color:#FBBF24;background:rgba(251,191,36,0.12);border:1px solid rgba(251,191,36,0.3)">Самоподписанный</span>')
    if s.is_weak_protocol:
        badges.append('<span class="match-badge" style="color:#FB923C;background:rgba(251,146,60,0.12);border:1px solid rgba(251,146,60,0.3)">Устаревший протокол</span>')

    badges_html = f'<div class="chips" style="margin-bottom:14px">{"".join(badges)}</div>'
    return badges_html + "\n".join(rows)


def _section_security_headers(result: FullAnalysisResult) -> str:
    h = result.security_headers
    rows = []
    for display, value in h.present.items():
        shown = value if len(value) <= 60 else value[:60] + "…"
        rows.append(
            f'<div class="kv"><span class="k">{_e(display)}</span>'
            f'<span class="v mono">{_e(shown)}</span></div>'
        )
    for display in h.missing:
        rows.append(
            f'<div class="kv"><span class="k">{_e(display)}</span>'
            f'<span class="v muted">отсутствует</span></div>'
        )

    score_note = f'<p class="muted" style="margin-bottom:10px">Полнота защитных заголовков: {h.score}%</p>'
    return score_note + "\n".join(rows)


def _section_port_scan(result: FullAnalysisResult) -> str:
    p = result.port_scan_info

    if p.not_configured:
        return (
            '<p class="muted">Shodan/Censys не сконфигурированы — эта секция пропущена. '
            'Добавьте SHODAN_API_KEY или CENSYS_API_ID/CENSYS_API_SECRET в .env, '
            'чтобы включить проверку открытых портов и сервисов.</p>'
        )
    if p.error:
        return f'<p class="muted">{_e(p.error)}</p>'
    if not p.open_ports:
        return '<p class="muted">Открытых портов не найдено в базе.</p>'

    rows = [
        f'<div class="kv"><span class="k">Источник</span><span class="v mono">{_e(p.source)}</span></div>',
        f'<div class="kv"><span class="k">IP</span><span class="v mono">{_e(p.ip)}</span></div>',
    ]
    if p.org:
        rows.append(f'<div class="kv"><span class="k">Организация</span><span class="v">{_e(p.org)}</span></div>')

    services_html = ""
    if p.services:
        chips = "".join(f'<span class="chip">{_e(s)}</span>' for s in p.services[:20])
        services_html = f'<div class="chips" style="margin-top:14px">{chips}</div>'

    vulns_html = ""
    if p.known_vulns:
        vulns_chips = "".join(
            f'<span class="match-badge" style="color:#F87171;background:rgba(248,113,113,0.12);'
            f'border:1px solid rgba(248,113,113,0.3)">{_e(v)}</span>'
            for v in p.known_vulns[:15]
        )
        vulns_html = (
            f'<p class="muted" style="margin:14px 0 8px">CVE, связанные с хостом по данным {_e(p.source)}:</p>'
            f'<div class="chips">{vulns_chips}</div>'
        )

    return "\n".join(rows) + services_html + vulns_html


def _section_attack_paths(result: FullAnalysisResult) -> str:
    items = []
    for p in result.attack_paths:
        color = SEVERITY_COLORS.get(p.severity, "#8D96AC")
        items.append(f'''
          <div class="path-item" style="--path-color:{color}">
            <div class="path-head">
              <span class="path-title">{_e(p.title)}</span>
              <span class="sev-badge" style="--sev-color:{color}">{_e(p.severity)}</span>
            </div>
            <p class="path-desc">{_e(p.description)}</p>
          </div>
        ''')
    return "\n".join(items)


def render_html_report(result: FullAnalysisResult) -> str:
    """Возвращает полностью готовый HTML-документ отчёта в виде строки."""
    risk = result.risk
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    risk_color = SEVERITY_COLORS.get(risk.level, "#8D96AC")

    return f'''<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report — {_e(result.domain)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #0F1420;
    --surface: #171D2C;
    --surface-2: #1F273A;
    --border: #262E44;
    --text: #E7EAF2;
    --text-muted: #8D96AC;
    --accent: #FFB020;
    --accent-soft: rgba(255, 176, 32, 0.12);
    --risk-color: {risk_color};
    --font-display: 'JetBrains Mono', monospace;
    --font-body: 'Inter', sans-serif;
  }}

  * {{ box-sizing: border-box; }}

  body {{
    margin: 0;
    background:
      radial-gradient(circle at 15% 0%, rgba(255,176,32,0.06), transparent 40%),
      radial-gradient(circle at 85% 15%, rgba(94,234,212,0.05), transparent 35%),
      var(--bg);
    color: var(--text);
    font-family: var(--font-body);
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
  }}

  .wrap {{
    max-width: 880px;
    margin: 0 auto;
    padding: 32px 20px 64px;
  }}

  /* ---- HERO --------------------------------------------------------- */
  .hero {{
    background: linear-gradient(160deg, var(--surface) 0%, var(--surface-2) 100%);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 32px 28px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
    flex-wrap: wrap;
    position: relative;
    overflow: hidden;
  }}
  .hero::before {{
    content: "";
    position: absolute;
    inset: 0;
    background-image:
      linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px);
    background-size: 28px 28px;
    pointer-events: none;
  }}
  .hero-left {{ position: relative; z-index: 1; min-width: 240px; }}
  .eyebrow {{
    font-family: var(--font-display);
    font-size: 12px;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--accent);
    margin: 0 0 10px;
  }}
  .domain {{
    font-family: var(--font-display);
    font-weight: 700;
    font-size: 30px;
    margin: 0 0 6px;
    word-break: break-all;
    color: var(--text);
  }}
  .timestamp {{
    color: var(--text-muted);
    font-size: 13px;
    margin: 0;
  }}
  .risk-block {{
    position: relative;
    z-index: 1;
    text-align: center;
  }}
  .gauge {{ width: 200px; height: 120px; display: block; }}
  .gauge-score {{
    font-family: var(--font-display);
    font-size: 34px;
    font-weight: 700;
    fill: var(--text);
  }}
  .gauge-max {{
    font-family: var(--font-display);
    font-size: 12px;
    fill: var(--text-muted);
  }}
  .risk-label {{
    font-family: var(--font-display);
    font-weight: 700;
    font-size: 16px;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--risk-color);
    margin-top: -6px;
  }}
  .risk-reason {{
    font-size: 12px;
    color: var(--text-muted);
    max-width: 200px;
    margin: 4px auto 0;
  }}

  /* ---- SECTIONS ------------------------------------------------------ */
  .section {{
    margin-top: 24px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px 26px;
  }}
  .section-head {{
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 16px;
  }}
  .section-icon {{ font-size: 18px; }}
  .section-title {{
    font-family: var(--font-display);
    font-size: 13px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin: 0;
  }}

  .kv {{
    display: flex;
    justify-content: space-between;
    gap: 16px;
    padding: 9px 0;
    border-bottom: 1px solid var(--border);
    font-size: 14px;
  }}
  .kv:last-child {{ border-bottom: none; }}
  .k {{ color: var(--text-muted); flex-shrink: 0; }}
  .v {{ text-align: right; word-break: break-word; }}
  .mono {{ font-family: var(--font-display); font-size: 13px; }}
  .muted {{ color: var(--text-muted); font-size: 14px; margin: 4px 0; }}

  .chips {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }}
  .chip {{
    background: var(--accent-soft);
    border: 1px solid rgba(255,176,32,0.3);
    color: var(--accent);
    font-family: var(--font-display);
    font-size: 12px;
    padding: 6px 10px;
    border-radius: 8px;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }}
  .chip-cat {{ color: var(--text-muted); font-size: 10px; }}

  .cve-group {{ margin-bottom: 18px; }}
  .cve-group:last-child {{ margin-bottom: 0; }}
  .cve-group h4 {{
    font-family: var(--font-display);
    font-size: 14px;
    color: var(--text);
    margin: 0 0 10px;
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }}
  .match-badge {{
    font-family: var(--font-display);
    font-size: 10px;
    padding: 2px 8px;
    border-radius: 999px;
    font-weight: 500;
  }}
  .match-cpe {{ color: #34D399; background: rgba(52,211,153,0.12); border: 1px solid rgba(52,211,153,0.3); }}
  .match-keyword {{ color: #8D96AC; background: rgba(141,150,172,0.12); border: 1px solid rgba(141,150,172,0.3); }}
  .cve-epss {{
    font-family: var(--font-display);
    font-size: 11px;
    color: var(--accent);
    background: var(--accent-soft);
    padding: 2px 7px;
    border-radius: 6px;
  }}
  .cve-item {{
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px 14px;
    margin-bottom: 8px;
  }}
  .cve-head {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
  .cve-id {{ font-size: 13px; font-weight: 600; color: var(--text); }}
  .cve-score {{ font-family: var(--font-display); font-size: 12px; color: var(--text-muted); }}
  .cve-summary {{ margin: 8px 0 0; font-size: 13px; color: var(--text-muted); }}

  .sev-badge {{
    font-family: var(--font-display);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.05em;
    padding: 3px 8px;
    border-radius: 999px;
    color: var(--sev-color);
    background: color-mix(in srgb, var(--sev-color) 15%, transparent);
    border: 1px solid color-mix(in srgb, var(--sev-color) 40%, transparent);
  }}

  .path-item {{
    border-left: 3px solid var(--path-color);
    background: var(--surface-2);
    border-radius: 0 10px 10px 0;
    padding: 14px 16px;
    margin-bottom: 10px;
  }}
  .path-item:last-child {{ margin-bottom: 0; }}
  .path-head {{ display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .path-title {{ font-weight: 600; font-size: 14px; }}
  .path-desc {{ margin: 8px 0 0; font-size: 13px; color: var(--text-muted); }}

  .footer {{
    margin-top: 28px;
    text-align: center;
    color: var(--text-muted);
    font-size: 12px;
    line-height: 1.7;
  }}
  .footer strong {{ color: var(--text); }}

  @media (max-width: 600px) {{
    .hero {{ flex-direction: column; text-align: center; }}
    .hero-left {{ text-align: center; }}
    .domain {{ font-size: 24px; }}
  }}
</style>
</head>
<body>
<div class="wrap">

  <div class="hero">
    <div class="hero-left">
      <p class="eyebrow">// Security Report</p>
      <h1 class="domain">{_e(result.domain)}</h1>
      <p class="timestamp">Сформирован {generated_at}</p>
    </div>
    <div class="risk-block">
      {_gauge_arc(risk.score, risk.level)}
      <div class="risk-label">{_e(risk.level)}</div>
      <p class="risk-reason">{_e(risk.reasoning)}</p>
    </div>
  </div>

  <div class="section">
    <div class="section-head">
      <p class="section-title">WHOIS</p>
    </div>
    {_section_whois(result)}
  </div>

  <div class="section">
    <div class="section-head">
      <p class="section-title">DNS-записи</p>
    </div>
    {_section_dns(result)}
  </div>

  <div class="section">
    <div class="section-head">
      <p class="section-title">HTTP intel</p>
    </div>
    {_section_http_intel(result)}
  </div>

  <div class="section">
    <div class="section-head">
      <p class="section-title">Технологии сайта</p>
    </div>
    {_section_tech(result)}
  </div>

  <div class="section">
    <div class="section-head">
      <p class="section-title">Поддомены (crt.sh)</p>
    </div>
    {_section_subdomains(result)}
  </div>

  <div class="section">
    <div class="section-head">
      <p class="section-title">Certificate emails (crt.sh)</p>
    </div>
    {_section_certificate_emails(result)}
  </div>

  <div class="section">
    <div class="section-head">
      <p class="section-title">SSL/TLS сертификат</p>
    </div>
    {_section_ssl(result)}
  </div>

  <div class="section">
    <div class="section-head">
      <p class="section-title">Security-заголовки</p>
    </div>
    {_section_security_headers(result)}
  </div>

  <div class="section">
    <div class="section-head">
      <p class="section-title">Открытые порты и сервисы</p>
    </div>
    {_section_port_scan(result)}
  </div>

  <div class="section">
    <div class="section-head">
      <p class="section-title">CVE по обнаруженным технологиям</p>
    </div>
    {_section_cves(result)}
  </div>

  <div class="section">
    <div class="section-head">
      <p class="section-title">Возможные attack paths</p>
    </div>
    {_section_attack_paths(result)}
  </div>

  <p class="footer">
    Отчёт основан только на <strong>публично доступных данных</strong> (WHOIS, DNS, HTTP-заголовки, база NVD).<br>
    Не является результатом реального пентеста и не эксплуатирует уязвимости.<br>
    Сгенерировано Telegram Toolbox Bot · Domain Security.
  </p>

</div>
</body>
</html>'''
