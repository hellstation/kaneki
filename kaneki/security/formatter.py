"""
modules/formatter.py — форматирование результатов анализа в
красивые сообщения Telegram (HTML parse mode)
"""
from html import escape

from .whois_utils import WhoisInfo
from .dns_utils import DnsInfo
from .tech_detect import TechInfo
from .cve_lookup import CveResult
from .attack_paths import AttackPath
from .risk_score import RiskAssessment

MAX_MESSAGE_LEN = 4000  # запас от лимита Telegram в 4096


def format_whois(domain: str, whois_info: WhoisInfo) -> str:
    lines = [f"<b>WHOIS: {escape(domain)}</b>"]
    if whois_info.error:
        lines.append(f"Не удалось получить WHOIS: {escape(whois_info.error)}")
        return "\n".join(lines)

    if whois_info.registrar:
        lines.append(f"Регистратор: {escape(str(whois_info.registrar))}")
    if whois_info.org:
        lines.append(f"Организация: {escape(str(whois_info.org))}")
    if whois_info.country:
        lines.append(f"Страна: {escape(str(whois_info.country))}")
    if whois_info.creation_date:
        lines.append(f"Создан: {escape(whois_info.creation_date)}")
    if whois_info.expiration_date:
        lines.append(f"Истекает: {escape(whois_info.expiration_date)}")
    if whois_info.name_servers:
        ns = ", ".join(whois_info.name_servers[:4])
        lines.append(f"NS-серверы: {escape(ns)}")

    if len(lines) == 1:
        lines.append("Данные WHOIS недоступны для этого домена.")

    return "\n".join(lines)


def format_dns(dns_info: DnsInfo) -> str:
    lines = ["<b>DNS-записи</b>"]
    if not dns_info.records:
        lines.append("Записи не найдены")
        if dns_info.errors.get("general"):
            lines.append(escape(dns_info.errors["general"]))
        return "\n".join(lines)

    for rtype, values in dns_info.records.items():
        shown = ", ".join(values[:3])
        if len(values) > 3:
            shown += f" … (+{len(values) - 3})"
        lines.append(f"• <b>{rtype}</b>: {escape(shown)}")

    return "\n".join(lines)


def format_tech(tech_info: TechInfo) -> str:
    lines = ["<b>Технологии сайта</b>"]
    if tech_info.error:
        lines.append(f"Не удалось определить: {escape(tech_info.error)}")
        return "\n".join(lines)

    if tech_info.status_code:
        lines.append(f"HTTP статус: {tech_info.status_code}")
    if tech_info.web_server:
        lines.append(f"Веб-сервер: {escape(tech_info.web_server)}")
    if tech_info.powered_by:
        lines.append(f"X-Powered-By: {escape(tech_info.powered_by)}")

    if tech_info.detected:
        lines.append("Обнаружено:")
        for name, category in tech_info.detected:
            display = tech_info.display_name(name)
            lines.append(f"   • {escape(display)} <i>({escape(category)})</i>")
    else:
        lines.append("Явных CMS/фреймворков не обнаружено")

    return "\n".join(lines)


def format_cves(cve_results: list[CveResult]) -> str:
    lines = ["<b>CVE по обнаруженным технологиям</b>"]
    if not cve_results:
        lines.append("Технологии не определены — поиск CVE не выполнялся")
        return "\n".join(lines)

    any_found = False
    for result in cve_results:
        if result.error:
            lines.append(f"\n<b>{escape(result.technology)}</b>: {escape(result.error)}")
            continue
        if not result.entries:
            lines.append(f"\n<b>{escape(result.technology)}</b>: CVE не найдены")
            continue

        any_found = True
        lines.append(f"\n<b>{escape(result.technology)}</b>:")
        for e in result.entries:
            score_str = f" ({e.score})" if e.score is not None else ""
            lines.append(
                f"  <code>{escape(e.cve_id)}</code>"
                f" [{escape(e.severity or 'N/A')}{score_str}]"
            )
            lines.append(f"     {escape(e.summary)}")

    if not any_found:
        lines.append("\nАктуальных CVE для обнаруженных технологий не найдено.")

    return "\n".join(lines)


def format_attack_paths(paths: list[AttackPath]) -> str:
    lines = ["<b>Возможные attack paths</b>"]

    for p in paths:
        lines.append(f"\n<b>{escape(p.title)}</b> [{escape(p.severity)}]")
        lines.append(f"   {escape(p.description)}")

    return "\n".join(lines)


def format_risk(risk: RiskAssessment) -> str:
    return (
        f"<b>ОБЩАЯ ОЦЕНКА РИСКА: {escape(risk.level.upper())}</b>\n"
        f"Score: {risk.score}\n"
        f"Основание: {escape(risk.reasoning)}"
    )


def split_long_message(text: str, max_len: int = MAX_MESSAGE_LEN) -> list[str]:
    """Разбивает длинное сообщение на части, не рвя строки посередине."""
    if len(text) <= max_len:
        return [text]

    parts = []
    current = ""
    for line in text.split("\n"):
        if len(current) + len(line) + 1 > max_len:
            parts.append(current)
            current = line
        else:
            current = f"{current}\n{line}" if current else line
    if current:
        parts.append(current)
    return parts
