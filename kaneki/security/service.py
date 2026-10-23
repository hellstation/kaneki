"""High-level domain security report service for bot handlers."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from .analyzer import FullAnalysisResult, run_full_analysis
from .config import SecurityConfig, load_security_config
from .report_html import render_html_report
from .validators import normalize_domain

logger = logging.getLogger(__name__)


@dataclass
class DomainReport:
    domain: str
    html: str
    result: FullAnalysisResult


async def analyze_domain_report(
    raw_input: str,
    config: SecurityConfig | None = None,
) -> DomainReport | str:
    """
    Analyze a domain and return DomainReport, or an error string.
    Caller should send HTML as a document.
    """
    domain = normalize_domain(raw_input)
    if not domain:
        return (
            "Could not parse domain. Send e.g. example.com or https://example.com"
        )

    cfg = config or load_security_config()
    logger.info("Starting domain security analysis for %s", domain)

    result = await run_full_analysis(
        domain=domain,
        nvd_api_key=cfg.nvd_api_key,
        max_cve_results=cfg.max_cve_results,
        timeout=cfg.request_timeout,
        shodan_api_key=cfg.shodan_api_key,
        censys_api_id=cfg.censys_api_id,
        censys_api_secret=cfg.censys_api_secret,
    )
    html = render_html_report(result)
    return DomainReport(
        domain=domain,
        html=html,
        result=result,
    )
