"""
modules/security_headers.py — анализ security-related HTTP-заголовков
ответа сайта: CSP, HSTS, X-Frame-Options и другие.

Не делает отдельного HTTP-запроса — переиспользует заголовки,
которые уже были получены модулем tech_detect при определении
технологий (см. TechInfo.raw_headers).
"""
from dataclasses import dataclass, field

# ключ заголовка (lowercase) -> человекочитаемое название
CHECKED_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security (HSTS)",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

# Отсутствие этих двух заголовков считается наиболее значимым риском
CRITICAL_HEADERS = {"content-security-policy", "strict-transport-security"}


@dataclass
class SecurityHeadersInfo:
    present: dict[str, str] = field(default_factory=dict)      # display_name -> значение
    missing: list[str] = field(default_factory=list)            # display_name
    missing_critical: list[str] = field(default_factory=list)   # display_name
    score: int = 0  # 0-100, простая метрика полноты защитных заголовков


def analyze_security_headers(headers: dict[str, str]) -> SecurityHeadersInfo:
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    info = SecurityHeadersInfo()

    for key, display in CHECKED_HEADERS.items():
        value = lowered.get(key)
        if value:
            info.present[display] = value
        else:
            info.missing.append(display)
            if key in CRITICAL_HEADERS:
                info.missing_critical.append(display)

    total = len(CHECKED_HEADERS)
    info.score = round(len(info.present) / total * 100) if total else 0

    return info
