"""Orchestrator: run all domain analysis modules and build one result."""
import asyncio
import logging
from dataclasses import dataclass

from .whois_utils import get_whois_info, WhoisInfo
from .dns_utils import get_dns_info, DnsInfo
from .tech_detect import detect_technologies, TechInfo
from .cve_lookup import search_cves_for_technologies, CveResult, TechQuery
from .epss import enrich_with_epss
from .subdomains import get_crtsh_info
from .ssl_utils import get_ssl_info, SslInfo
from .security_headers import analyze_security_headers, SecurityHeadersInfo
from .port_scan import get_port_scan_info, PortScanInfo
from .attack_paths import analyze_attack_paths, AttackPath
from .risk_score import calculate_risk, RiskAssessment

logger = logging.getLogger(__name__)


@dataclass
class FullAnalysisResult:
    domain: str
    whois_info: WhoisInfo
    dns_info: DnsInfo
    tech_info: TechInfo
    cve_results: list[CveResult]
    attack_paths: list[AttackPath]
    risk: RiskAssessment
    subdomains: list[str]
    certificate_emails: list[str]
    crtsh_error: str
    ssl_info: SslInfo
    security_headers: SecurityHeadersInfo
    port_scan_info: PortScanInfo


async def run_full_analysis(
    domain: str,
    nvd_api_key: str | None,
    max_cve_results: int,
    timeout: int,
    shodan_api_key: str | None = None,
    censys_api_id: str | None = None,
    censys_api_secret: str | None = None,
) -> FullAnalysisResult:
    whois_info, dns_info, tech_info, crtsh_info, ssl_info = await asyncio.gather(
        get_whois_info(domain),
        get_dns_info(domain, timeout=timeout),
        detect_technologies(domain, timeout=timeout),
        get_crtsh_info(domain, timeout=max(timeout, 15)),
        get_ssl_info(domain, timeout=timeout),
        return_exceptions=False,
    )

    security_headers = analyze_security_headers(tech_info.raw_headers)

    ip = None
    a_records = dns_info.records.get("A")
    if a_records:
        ip = a_records[0]

    port_scan_info = await get_port_scan_info(
        ip=ip,
        shodan_api_key=shodan_api_key,
        censys_api_id=censys_api_id,
        censys_api_secret=censys_api_secret,
        timeout=timeout,
    )

    tech_queries: list[TechQuery] = []
    seen: set[tuple[str, str | None]] = set()

    for name, _category in tech_info.detected:
        version = tech_info.versions.get(name)
        key = (name, version)
        if key not in seen:
            seen.add(key)
            tech_queries.append(TechQuery(name=name, version=version))

    if tech_info.web_server:
        server_product = tech_info.web_server.split("/")[0]
        server_version = tech_info.versions.get(server_product)
        key = (server_product, server_version)
        if key not in seen:
            seen.add(key)
            tech_queries.append(TechQuery(name=server_product, version=server_version))

    cve_results = await search_cves_for_technologies(
        tech_queries,
        max_results_per_tech=max_cve_results,
        api_key=nvd_api_key,
        timeout=timeout,
    )

    await enrich_with_epss(cve_results, timeout=timeout)

    paths = analyze_attack_paths(
        tech_info, cve_results, dns_info, ssl_info, security_headers, port_scan_info
    )
    risk = calculate_risk(paths, cve_results)

    return FullAnalysisResult(
        domain=domain,
        whois_info=whois_info,
        dns_info=dns_info,
        tech_info=tech_info,
        cve_results=cve_results,
        attack_paths=paths,
        risk=risk,
        subdomains=crtsh_info.subdomains,
        certificate_emails=crtsh_info.certificate_emails,
        crtsh_error=crtsh_info.error,
        ssl_info=ssl_info,
        security_headers=security_headers,
        port_scan_info=port_scan_info,
    )
