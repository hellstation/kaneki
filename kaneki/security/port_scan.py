"""
modules/port_scan.py — получение сведений об открытых портах и
сервисах хоста через публичные базы Shodan и Censys.

Важно: мы НЕ сканируем целевой хост самостоятельно — это было бы
активным вторжением и в некоторых юрисдикциях требует отдельного
разрешения. Вместо этого мы читаем уже собранные результаты
интернет-сканирования, которые эти сервисы публикуют по официальному
API. Это стандартная и безопасная практика в OSINT.

Используется тот сервис, чей API-ключ сконфигурирован (приоритет —
Shodan, затем Censys). Если ни один не сконфигурирован, секция
просто помечается как недоступная — это не блокирует остальной анализ.
"""
import logging
from dataclasses import dataclass, field

import aiohttp

logger = logging.getLogger(__name__)

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
CENSYS_HOST_URL = "https://search.censys.io/api/v2/hosts/{ip}"

# Порты, открытость которых наружу обычно считается повышенным риском
RISKY_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


@dataclass
class PortScanInfo:
    source: str | None = None  # "shodan" | "censys" | None
    ip: str | None = None
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)  # "port/product"
    org: str | None = None
    known_vulns: list[str] = field(default_factory=list)  # CVE, уже связанные с хостом сервисом
    risky_ports: list[tuple[int, str]] = field(default_factory=list)  # (port, name)
    error: str | None = None
    not_configured: bool = False


async def _shodan_lookup(ip: str, api_key: str, timeout: int) -> PortScanInfo:
    info = PortScanInfo(source="shodan", ip=ip)
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    params = {"key": api_key}

    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            async with session.get(SHODAN_HOST_URL.format(ip=ip), params=params) as resp:
                if resp.status == 404:
                    info.error = "Хост не найден в базе Shodan (нет данных сканирования)"
                    return info
                if resp.status == 401:
                    info.error = "Неверный Shodan API-ключ"
                    return info
                if resp.status != 200:
                    info.error = f"Shodan API вернул статус {resp.status}"
                    return info

                data = await resp.json()
                info.org = data.get("org")
                ports = sorted(set(data.get("ports", []) or []))
                info.open_ports = ports
                info.risky_ports = [(p, RISKY_PORTS[p]) for p in ports if p in RISKY_PORTS]

                services = []
                for item in data.get("data", []) or []:
                    port = item.get("port")
                    product = item.get("product") or (item.get("_shodan") or {}).get("module") or "unknown"
                    services.append(f"{port}/{product}")
                info.services = services

                info.known_vulns = sorted((data.get("vulns") or []))

    except Exception as e:
        info.error = str(e)
        logger.warning(f"Shodan lookup failed for {ip}: {e}")

    return info


async def _censys_lookup(ip: str, api_id: str, api_secret: str, timeout: int) -> PortScanInfo:
    info = PortScanInfo(source="censys", ip=ip)
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    auth = aiohttp.BasicAuth(api_id, api_secret)

    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg, auth=auth) as session:
            async with session.get(CENSYS_HOST_URL.format(ip=ip)) as resp:
                if resp.status == 404:
                    info.error = "Хост не найден в базе Censys"
                    return info
                if resp.status in (401, 403):
                    info.error = "Неверные Censys API-ключи"
                    return info
                if resp.status != 200:
                    info.error = f"Censys API вернул статус {resp.status}"
                    return info

                payload = await resp.json()
                result = payload.get("result", {})
                services = result.get("services", []) or []

                ports = sorted({s.get("port") for s in services if s.get("port")})
                info.open_ports = ports
                info.risky_ports = [(p, RISKY_PORTS[p]) for p in ports if p in RISKY_PORTS]
                info.services = [
                    f"{s.get('port')}/{s.get('service_name', 'unknown')}" for s in services
                ]

    except Exception as e:
        info.error = str(e)
        logger.warning(f"Censys lookup failed for {ip}: {e}")

    return info


async def get_port_scan_info(
    ip: str | None,
    shodan_api_key: str | None,
    censys_api_id: str | None,
    censys_api_secret: str | None,
    timeout: int = 15,
) -> PortScanInfo:
    if not ip:
        info = PortScanInfo()
        info.error = "IP-адрес не определён (нет A-записи в DNS)"
        return info

    if shodan_api_key:
        return await _shodan_lookup(ip, shodan_api_key, timeout)

    if censys_api_id and censys_api_secret:
        return await _censys_lookup(ip, censys_api_id, censys_api_secret, timeout)

    info = PortScanInfo(ip=ip)
    info.not_configured = True
    return info
