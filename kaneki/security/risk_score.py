"""
modules/risk_score.py — сведение всех собранных данных к единой
оценке риска: Low / Medium / High / Critical
"""
from dataclasses import dataclass

from .attack_paths import AttackPath
from .cve_lookup import CveResult

SEVERITY_WEIGHTS = {
    "Low": 1,
    "Medium": 3,
    "High": 6,
    "Critical": 10,
}

SEVERITY_EMOJI = {
    "Low": "",
    "Medium": "",
    "High": "",
    "Critical": "",
}


@dataclass
class RiskAssessment:
    level: str
    score: int
    emoji: str
    reasoning: str


def calculate_risk(
    attack_paths: list[AttackPath],
    cve_results: list[CveResult],
) -> RiskAssessment:
    score = 0

    # Attack paths уже включают штрафы за SSL-проблемы, отсутствующие
    # security-заголовки и опасные открытые порты — они попадают сюда
    # через severity каждого пути.
    for path in attack_paths:
        score += SEVERITY_WEIGHTS.get(path.severity, 0)

    all_entries = [e for r in cve_results for e in r.entries]

    critical_cve_count = sum(1 for e in all_entries if (e.severity or "").upper() == "CRITICAL")
    high_cve_count = sum(1 for e in all_entries if (e.severity or "").upper() == "HIGH")

    score += critical_cve_count * 4
    score += high_cve_count * 2

    # EPSS: бонус к score за CVE с высокой вероятностью реальной
    # эксплуатации — такой CVE опаснее на практике, даже если его
    # CVSS не самый высокий.
    high_epss_count = sum(1 for e in all_entries if (e.epss or 0) >= 0.5)
    medium_epss_count = sum(1 for e in all_entries if 0.1 <= (e.epss or 0) < 0.5)
    score += high_epss_count * 3
    score += medium_epss_count * 1

    if score >= 20:
        level = "Critical"
    elif score >= 10:
        level = "High"
    elif score >= 4:
        level = "Medium"
    else:
        level = "Low"

    reasoning_parts = []
    if critical_cve_count:
        reasoning_parts.append(f"{critical_cve_count} critical CVE")
    if high_cve_count:
        reasoning_parts.append(f"{high_cve_count} high CVE")
    if high_epss_count:
        reasoning_parts.append(f"{high_epss_count} CVE с высоким EPSS")
    non_trivial_paths = [p for p in attack_paths if p.severity != "Low"]
    if non_trivial_paths:
        reasoning_parts.append(f"{len(non_trivial_paths)} значимых attack path")

    reasoning = (
        ", ".join(reasoning_parts)
        if reasoning_parts
        else "критичных находок не выявлено"
    )

    return RiskAssessment(
        level=level,
        score=score,
        emoji=SEVERITY_EMOJI[level],
        reasoning=reasoning,
    )
