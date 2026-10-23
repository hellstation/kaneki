"""
modules/cve_lookup.py — поиск актуальных CVE по обнаруженным технологиям
через официальный NVD REST API (https://nvd.nist.gov/developers/vulnerabilities)

Публичный API, не требует аутентификации, но имеет rate-limit
(5 запросов / 30 сек без ключа, 50 / 30 сек с ключом).

ВАЖНО про точность поиска — два принципиально разных режима:

1. cpeName (точный режим) — структурное сопоставление с базой CPE
   (Common Platform Enumeration), где для каждого CVE явно перечислены
   диапазоны версий, которые он затрагивает. Это единственный способ
   реально узнать, затрагивает ли конкретный CVE именно вашу версию.

2. keywordSearch (нечёткий режим, fallback) — обычный полнотекстовый
   поиск по описанию CVE. Он находит CVE, где встречаются заданные
   слова, но НЕ проверяет, что уязвимость действительно затрагивает
   указанную версию — совпадение чисто текстовое. Плюс результаты не
   отсортированы по релевантности/severity, просто первые N по
   внутреннему порядку NVD. Используется только когда мы не знаем
   правильное имя CPE для технологии или не смогли извлечь версию.

Каждый CveResult помечен полем matched_by ("cpe" или "keyword"), чтобы
в отчёте было явно видно, насколько можно доверять конкретному блоку.
"""
import asyncio
import logging
from dataclasses import dataclass, field

import aiohttp

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Известные соответствия "имя технологии, как мы её называем" -> (vendor, product)
# в официальном словаре CPE NVD. Список сознательно ограничен теми
# технологиями, для которых мы уверены в правильном написании — иначе
# запрос по cpeName просто не найдёт совпадений и мы ничего не потеряем,
# но лучше сразу использовать keyword fallback, чем гадать.
#
# Важно: эти имена не высечены в камне. Например, официальный vendor
# для nginx сменился с "nginx"/"igor_sysoev" на "f5" после того как
# компанию купила F5 — такие вещи нужно периодически перепроверять
# на https://nvd.nist.gov/products/cpe/search
TECH_CPE_MAP: dict[str, tuple[str, str]] = {
    "WordPress": ("wordpress", "wordpress"),
    "Joomla": ("joomla", "joomla\\!"),
    "Drupal": ("drupal", "drupal"),
    "nginx": ("f5", "nginx"),
    "Apache": ("apache", "http_server"),
    "PHP": ("php", "php"),
}


@dataclass
class TechQuery:
    """Технология для поиска CVE: имя + версия (версия может быть None)."""
    name: str
    version: str | None = None


@dataclass
class CveEntry:
    cve_id: str
    severity: str | None
    score: float | None
    summary: str
    epss: float | None = None              # вероятность эксплуатации 0.0-1.0 (FIRST.org)
    epss_percentile: float | None = None    # перцентиль относительно всех CVE


@dataclass
class CveResult:
    technology: str
    entries: list[CveEntry] = field(default_factory=list)
    error: str | None = None
    matched_by: str = "keyword"  # "cpe" (точное совпадение по версии) | "keyword" (нечёткий поиск)


def _extract_severity(metrics: dict) -> tuple[str | None, float | None]:
    """Достаём severity и score из CVSS v3.1 / v3.0 / v2, в порядке приоритета."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            severity = m.get("baseSeverity") or cvss_data.get("baseSeverity")
            score = cvss_data.get("baseScore")
            return severity, score
    return None, None


def _resolve_query(tq: TechQuery) -> tuple[dict, str, str]:
    """
    Решает, каким способом искать CVE для данной технологии.
    Возвращает (query_params, label_для_отчёта, matched_by).
    """
    mapping = TECH_CPE_MAP.get(tq.name)

    if mapping and tq.version:
        vendor, product = mapping
        cpe_name = f"cpe:2.3:a:{vendor}:{product}:{tq.version}:*:*:*:*:*:*:*"
        label = f"{tq.name} {tq.version}"
        return {"cpeName": cpe_name}, label, "cpe"

    keyword = f"{tq.name} {tq.version}" if tq.version else tq.name
    return {"keywordSearch": keyword}, keyword, "keyword"


async def _query_nvd(
    session: aiohttp.ClientSession,
    query_params: dict,
    label: str,
    matched_by: str,
    max_results: int,
    api_key: str | None,
) -> CveResult:
    params = {**query_params, "resultsPerPage": str(max_results)}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    result = CveResult(technology=label, matched_by=matched_by)

    try:
        async with session.get(NVD_API_URL, params=params, headers=headers) as resp:
            if resp.status == 429:
                result.error = "Превышен лимит запросов к NVD API, попробуйте позже"
                return result
            if resp.status == 404 and matched_by == "cpe":
                # cpeName не найден в словаре CPE — версия слишком новая/старая
                # или не задокументирована. Не считаем это ошибкой запроса.
                result.error = "Точная версия не найдена в базе CPE NVD"
                return result
            if resp.status != 200:
                result.error = f"NVD API вернул статус {resp.status}"
                return result

            data = await resp.json()
            vulnerabilities = data.get("vulnerabilities", [])

            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "UNKNOWN")

                descriptions = cve.get("descriptions", [])
                summary = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    "Описание недоступно",
                )
                # Ограничим длину описания для читабельности в Telegram
                if len(summary) > 200:
                    summary = summary[:200].rsplit(" ", 1)[0] + "…"

                metrics = cve.get("metrics", {})
                severity, score = _extract_severity(metrics)

                result.entries.append(
                    CveEntry(cve_id=cve_id, severity=severity, score=score, summary=summary)
                )

    except asyncio.TimeoutError:
        result.error = "Таймаут запроса к NVD API"
    except Exception as e:
        result.error = str(e)
        logger.warning(f"NVD lookup failed for '{label}': {e}")

    return result


async def search_cves_for_technologies(
    technologies: list[TechQuery],
    max_results_per_tech: int = 5,
    api_key: str | None = None,
    timeout: int = 15,
) -> list[CveResult]:
    """
    Ищет CVE для списка технологий. Для каждой технологии выбирает
    точный (CPE) или нечёткий (keyword) режим поиска в зависимости
    от того, знаем ли мы её CPE-имя и известна ли версия.
    Запросы выполняются последовательно с паузой — NVD рейт-лимитит.
    """
    if not technologies:
        return []

    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    results: list[CveResult] = []

    async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
        for tq in technologies:
            query_params, label, matched_by = _resolve_query(tq)
            res = await _query_nvd(session, query_params, label, matched_by, max_results_per_tech, api_key)
            results.append(res)
            # NVD без ключа: не более 5 запросов / 30 сек -> пауза между запросами
            await asyncio.sleep(1.2 if not api_key else 0.2)

    return results
