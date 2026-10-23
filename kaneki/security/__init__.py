"""Domain security analysis package (ported from Domain Security Analyzer)."""

from .analyzer import FullAnalysisResult, run_full_analysis
from .report_html import render_html_report
from .validators import normalize_domain

__all__ = [
    "FullAnalysisResult",
    "run_full_analysis",
    "render_html_report",
    "normalize_domain",
]
