"""
modules/attack_paths.py — упрощённый эвристический анализ возможных
цепочек атак (attack paths) на основе собранных данных.

ВАЖНО: это не инструмент эксплуатации, а инструмент осведомлённости —
он лишь описывает ОБЩИЕ классы рисков на основе публичных индикаторов
(версии ПО, заголовки, сертификаты, открытые порты, наличие CVE),
без попыток реальной атаки.
"""
from dataclasses import dataclass

from .cve_lookup import CveResult
from .tech_detect import TechInfo
from .dns_utils import DnsInfo
from .ssl_utils import SslInfo
from .security_headers import SecurityHeadersInfo
from .port_scan import PortScanInfo

HIGH_EPSS_THRESHOLD = 0.5  # >=50% вероятность эксплуатации в течение 30 дней


@dataclass
class AttackPath:
    title: str
    description: str
    severity: str  # Low / Medium / High / Critical


def analyze_attack_paths(
    tech_info: TechInfo,
    cve_results: list[CveResult],
    dns_info: DnsInfo,
    ssl_info: SslInfo | None = None,
    security_headers: SecurityHeadersInfo | None = None,
    port_scan_info: PortScanInfo | None = None,
) -> list[AttackPath]:
    paths: list[AttackPath] = []

    all_entries = [e for r in cve_results for e in r.entries]

    # 1. Известные CVE в обнаруженных технологиях
    critical_cves = [e for e in all_entries if (e.severity or "").upper() in ("CRITICAL", "HIGH")]
    high_epss_cves = [e for e in all_entries if (e.epss or 0) >= HIGH_EPSS_THRESHOLD]

    if critical_cves:
        epss_note = ""
        if high_epss_cves:
            epss_note = (
                f" Из них {len(high_epss_cves)} имеют высокую вероятность реальной "
                f"эксплуатации по EPSS (≥{int(HIGH_EPSS_THRESHOLD * 100)}%) — это не "
                f"теоретический, а статистически вероятный вектор атаки."
            )
        paths.append(AttackPath(
            title="Эксплуатация известной уязвимости (N-day)",
            description=(
                f"Обнаружено {len(critical_cves)} CVE с высокой/критической severity "
                f"для используемых технологий. Потенциальная цепочка: разведка версии → "
                f"поиск публичного PoC/эксплойта → компрометация приложения.{epss_note}"
            ),
            severity="Critical" if (
                any((e.severity or "").upper() == "CRITICAL" for e in critical_cves) or high_epss_cves
            ) else "High",
        ))

    # 2. Раскрытие версии ПО через заголовки
    if tech_info.web_server or tech_info.powered_by:
        exposed = ", ".join(filter(None, [tech_info.web_server, tech_info.powered_by]))
        paths.append(AttackPath(
            title="Раскрытие информации о стеке (Information Disclosure)",
            description=(
                f"Сервер раскрывает информацию о используемом ПО в заголовках ответа "
                f"({exposed}). Это упрощает разведку и подбор релевантных эксплойтов."
            ),
            severity="Low",
        ))

    # 3. Устаревшая/популярная CMS без явных признаков защиты
    cms_found = [
        tech_info.display_name(name) for name, category in tech_info.detected if category == "CMS"
    ]
    if cms_found:
        paths.append(AttackPath(
            title="Атака на CMS через известные плагины/уязвимости ядра",
            description=(
                f"Обнаружена CMS: {', '.join(cms_found)}. Типичная цепочка атаки: "
                f"сканирование установленных плагинов/тем → поиск CVE для конкретных "
                f"версий → эксплуатация уязвимого компонента → загрузка веб-шелла."
            ),
            severity="Medium",
        ))

    # 4. Отсутствие/аномалии в DNS (например, отсутствие SPF/DMARC в TXT)
    txt_records = " ".join(dns_info.records.get("TXT", []))
    has_spf = "v=spf1" in txt_records.lower()
    has_dmarc = any("dmarc" in r.lower() for r in dns_info.records.get("TXT", []))
    if dns_info.records.get("MX") and (not has_spf or not has_dmarc):
        missing = []
        if not has_spf:
            missing.append("SPF")
        if not has_dmarc:
            missing.append("DMARC")
        paths.append(AttackPath(
            title="Фишинг/спуфинг через отсутствие email-защиты",
            description=(
                f"У домена настроен MX, но отсутствуют записи: {', '.join(missing)}. "
                f"Это позволяет злоумышленникам подделывать письма от имени домена "
                f"для фишинговых атак на сотрудников или клиентов."
            ),
            severity="Medium",
        ))

    # 5. Проблемы с SSL/TLS сертификатом
    if ssl_info and ssl_info.has_ssl:
        if ssl_info.is_expired:
            paths.append(AttackPath(
                title="Просроченный SSL-сертификат",
                description=(
                    f"Сертификат истёк {ssl_info.not_after}. Помимо предупреждений "
                    f"браузера, это часто указывает на заброшенную инфраструктуру "
                    f"и общее отставание в обслуживании — маркер повышенного риска "
                    f"для остальных найденных проблем."
                ),
                severity="Critical",
            ))
        elif ssl_info.is_expiring_soon:
            paths.append(AttackPath(
                title="Истекающий SSL-сертификат",
                description=(
                    f"Сертификат истекает через {ssl_info.days_until_expiry} дн. "
                    f"({ssl_info.not_after}). Риск простоя/недоверия при автопродлении "
                    f"с ошибкой."
                ),
                severity="Medium",
            ))

        if ssl_info.is_self_signed:
            paths.append(AttackPath(
                title="Самоподписанный сертификат",
                description=(
                    "Сертификат самоподписан (издатель совпадает с получателем). "
                    "Это либо тестовое окружение, случайно доступное извне, либо "
                    "признак MITM-подмены — оба варианта требуют внимания."
                ),
                severity="Medium",
            ))

        if ssl_info.is_weak_protocol:
            paths.append(AttackPath(
                title="Устаревший протокол TLS",
                description=(
                    f"Сервер согласовал устаревший протокол ({ssl_info.protocol_version}). "
                    f"Такие версии уязвимы к атакам вроде POODLE/BEAST и не поддерживают "
                    f"современные шифры."
                ),
                severity="High",
            ))
    elif ssl_info and not ssl_info.has_ssl and ssl_info.error:
        pass  # HTTPS недоступен — не считаем это отдельным attack path, просто нет данных

    # 6. Отсутствие критичных security-заголовков
    if security_headers and security_headers.missing_critical:
        paths.append(AttackPath(
            title="Слабая защита от XSS/Clickjacking на уровне заголовков",
            description=(
                f"Отсутствуют заголовки: {', '.join(security_headers.missing_critical)}. "
                f"Без CSP эксплуатация найденной XSS становится значительно проще, "
                f"без HSTS возможен downgrade-атака с HTTPS на HTTP."
            ),
            severity="Medium",
        ))

    # 7. Открытые рискованные порты/сервисы (Shodan/Censys)
    if port_scan_info and port_scan_info.risky_ports:
        risky_str = ", ".join(f"{port}/{name}" for port, name in port_scan_info.risky_ports)
        paths.append(AttackPath(
            title="Потенциально опасные сервисы, открытые наружу",
            description=(
                f"По данным {port_scan_info.source}, наружу открыты сервисы, которые "
                f"обычно не должны быть публично доступны: {risky_str}. Это прямой "
                f"вектор для брутфорса или эксплуатации уязвимостей самого сервиса "
                f"(например, БД без аутентификации)."
            ),
            severity="Critical",
        ))

    # 8. CVE, уже связанные с хостом сервисом Shodan (наиболее конкретный сигнал)
    if port_scan_info and port_scan_info.known_vulns:
        shown = ", ".join(port_scan_info.known_vulns[:8])
        paths.append(AttackPath(
            title="Уязвимости, напрямую связанные с хостом (Shodan)",
            description=(
                f"Shodan уже связал с этим IP конкретные CVE на основе баннеров "
                f"сервисов: {shown}. Это самый конкретный из всех найденных индикаторов "
                f"— рекомендуется проверить в первую очередь."
            ),
            severity="Critical",
        ))

    # 9. Если явных находок нет
    if not paths:
        paths.append(AttackPath(
            title="Явных цепочек атак не выявлено",
            description=(
                "По собранным публичным данным очевидных векторов атаки не обнаружено. "
                "Это не означает отсутствие уязвимостей — требуется углублённый аудит "
                "(например, ручное пентестирование с разрешения владельца)."
            ),
            severity="Low",
        ))

    return paths
