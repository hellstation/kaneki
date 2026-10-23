"""
modules/epss.py — обогащение найденных CVE данными EPSS
(Exploit Prediction Scoring System) через публичный API FIRST.org.

EPSS показывает вероятность (0.0–1.0) того, что уязвимость будет
реально проэксплуатирована в дикой природе в течение ближайших
30 дней. Это дополняет CVSS: CVSS оценивает потенциальную тяжесть
уязвимости, а EPSS — вероятность того, что её вообще станут
эксплуатировать. CVE с высоким CVSS, но почти нулевым EPSS, на
практике редко атакуют; и наоборот.

Публичный API, не требует ключа: https://api.first.org/data/v1/epss
"""
import logging

import aiohttp

from .cve_lookup import CveResult

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
BATCH_SIZE = 100  # практическое ограничение на длину query-параметра


async def enrich_with_epss(cve_results: list[CveResult], timeout: int = 15) -> None:
    """
    Мутирует переданные CveEntry «на месте», проставляя epss и
    epss_percentile там, где они есть в базе FIRST.org. Работает
    батчами, чтобы не собирать по одному запросу на каждый CVE.
    """
    all_ids = list(dict.fromkeys(e.cve_id for r in cve_results for e in r.entries))
    if not all_ids:
        return

    epss_map: dict[str, tuple[float, float]] = {}
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)

    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            for i in range(0, len(all_ids), BATCH_SIZE):
                batch = all_ids[i:i + BATCH_SIZE]
                params = {"cve": ",".join(batch)}
                try:
                    async with session.get(EPSS_API_URL, params=params) as resp:
                        if resp.status != 200:
                            logger.warning(f"EPSS API вернул статус {resp.status}")
                            continue
                        data = await resp.json()
                        for item in data.get("data", []):
                            cve_id = item.get("cve")
                            try:
                                epss_map[cve_id] = (
                                    float(item["epss"]),
                                    float(item["percentile"]),
                                )
                            except (KeyError, ValueError, TypeError):
                                continue
                except Exception as e:
                    logger.warning(f"EPSS batch lookup failed: {e}")
                    continue
    except Exception as e:
        logger.warning(f"EPSS lookup failed entirely: {e}")
        return

    for r in cve_results:
        for e in r.entries:
            if e.cve_id in epss_map:
                e.epss, e.epss_percentile = epss_map[e.cve_id]
