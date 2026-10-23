"""
modules/validators.py — валидация и нормализация пользовательского ввода
"""
import re
from urllib.parse import urlparse

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def normalize_domain(raw: str) -> str | None:
    """
    Принимает строку вида 'example.com', 'https://example.com/path',
    'www.example.com' и возвращает чистый домен либо None, если
    строка не похожа на домен.
    """
    raw = raw.strip()

    if "://" not in raw:
        raw = "http://" + raw

    try:
        parsed = urlparse(raw)
        host = parsed.netloc or parsed.path
    except Exception:
        return None

    host = host.split("/")[0].split(":")[0].strip().lower()

    if host.startswith("www."):
        host = host[4:]

    if not DOMAIN_REGEX.match(host):
        return None

    return host
