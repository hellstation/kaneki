"""Security analyzer settings from environment."""
import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class SecurityConfig:
    nvd_api_key: str | None
    shodan_api_key: str | None
    censys_api_id: str | None
    censys_api_secret: str | None
    request_timeout: int
    max_cve_results: int
    rate_limit_seconds: float


def _optional_secret(name: str) -> str | None:
    """Treat missing / empty / whitespace-only values as unset."""
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def load_security_config() -> SecurityConfig:
    return SecurityConfig(
        nvd_api_key=_optional_secret("NVD_API_KEY"),
        shodan_api_key=_optional_secret("SHODAN_API_KEY"),
        censys_api_id=_optional_secret("CENSYS_API_ID"),
        censys_api_secret=_optional_secret("CENSYS_API_SECRET"),
        request_timeout=int(os.getenv("REQUEST_TIMEOUT", "10") or "10"),
        max_cve_results=int(os.getenv("MAX_CVE_RESULTS", "5") or "5"),
        rate_limit_seconds=float(os.getenv("DOMAIN_RATE_LIMIT_SECONDS", "10") or "10"),
    )
