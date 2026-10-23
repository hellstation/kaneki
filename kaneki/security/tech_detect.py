"""Heuristic tech detection + HTTP intel (URL, headers, cookies)."""
import logging
import re
from dataclasses import dataclass, field

import aiohttp

logger = logging.getLogger(__name__)

SIGNATURES = [
    ("WordPress", "CMS", "html", re.compile(r"wp-content|wp-includes", re.I)),
    ("Joomla", "CMS", "html", re.compile(r"joomla", re.I)),
    ("Drupal", "CMS", "html", re.compile(r"drupal", re.I)),
    ("Bitrix", "CMS", "html", re.compile(r"bitrix", re.I)),
    ("Magento", "CMS", "html", re.compile(r"magento|Mage\.Cookies", re.I)),
    ("Shopify", "CMS", "html", re.compile(r"cdn\.shopify\.com", re.I)),
    ("WooCommerce", "CMS", "html", re.compile(r"woocommerce", re.I)),
    ("React", "Framework", "html", re.compile(r"react(?:-dom)?\.production|__reactContainer", re.I)),
    ("Vue.js", "Framework", "html", re.compile(r"vue\.js|__vue__|data-v-", re.I)),
    ("Angular", "Framework", "html", re.compile(r"ng-version|angular\.js", re.I)),
    ("Next.js", "Framework", "html", re.compile(r"__next|_next/static", re.I)),
    ("Nuxt", "Framework", "html", re.compile(r"__nuxt|nuxt", re.I)),
    ("Laravel", "Framework", "html", re.compile(r"laravel_session", re.I)),
    ("Django", "Framework", "header", re.compile(r"csrftoken", re.I)),
    ("jQuery", "Library", "html", re.compile(r"jquery", re.I)),
    ("Bootstrap", "Library", "html", re.compile(r"bootstrap", re.I)),
    ("Google Analytics", "Analytics", "html", re.compile(r"google-analytics|gtag\(|googletagmanager", re.I)),
    ("Yandex Metrica", "Analytics", "html", re.compile(r"mc\.yandex\.ru|ym\(", re.I)),
    ("Cloudflare", "CDN", "header", re.compile(r"cloudflare|cf-ray", re.I)),
    ("Vercel", "CDN", "header", re.compile(r"vercel", re.I)),
    ("Netlify", "CDN", "header", re.compile(r"netlify|x-nf-request-id", re.I)),
]

VERSION_PATTERNS = {
    "WordPress": [
        re.compile(r'content=["\']WordPress\s+([\d.]+)["\']', re.I),
        re.compile(r"wp-includes/js/wp-emoji-release\.min\.js\?ver=([\d.]+)", re.I),
        re.compile(r"[?&]ver=([\d.]+)['\"].*?wp-(?:content|includes)", re.I),
    ],
    "Joomla": [
        re.compile(r'content=["\']Joomla!\s*([\d.]+)', re.I),
    ],
    "Drupal": [
        re.compile(r'content=["\']Drupal\s+([\d.]+)', re.I),
    ],
    "Angular": [
        re.compile(r'ng-version=["\']([\d.]+)["\']', re.I),
    ],
    "Magento": [
        re.compile(r"Magento/([\d.]+)", re.I),
    ],
}

GENERATOR_META_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I
)
GENERIC_NAME_VERSION_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 .!_-]*?)\s+v?([\d]+(?:\.[\d]+){1,3})")
HEADER_PRODUCT_VERSION_RE = re.compile(r"^([A-Za-z][A-Za-z0-9._-]*)/([\d][\d.]*)")

INTERESTING_HEADERS = [
    "server",
    "x-powered-by",
    "content-type",
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "cf-ray",
    "x-vercel-id",
    "x-cache",
]


@dataclass
class TechInfo:
    web_server: str | None = None
    powered_by: str | None = None
    detected: list[tuple[str, str]] = field(default_factory=list)
    versions: dict[str, str] = field(default_factory=dict)
    raw_headers: dict[str, str] = field(default_factory=dict)
    status_code: int | None = None
    final_url: str | None = None
    cookies: list[str] = field(default_factory=list)
    selected_headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    def display_name(self, name: str) -> str:
        version = self.versions.get(name)
        return f"{name} {version}" if version else name


def _parse_header_product_version(value: str | None) -> tuple[str, str] | None:
    if not value:
        return None
    match = HEADER_PRODUCT_VERSION_RE.match(value.strip())
    if match:
        return match.group(1), match.group(2)
    return None


def _extract_generator_version(html: str) -> tuple[str, str] | None:
    match = GENERATOR_META_RE.search(html)
    if not match:
        return None
    content = match.group(1).strip()
    ver_match = GENERIC_NAME_VERSION_RE.match(content)
    if ver_match:
        return ver_match.group(1).strip(), ver_match.group(2)
    return None


def _extract_versions(html: str, resp_headers: dict[str, str]) -> dict[str, str]:
    versions: dict[str, str] = {}

    for tech_name, patterns in VERSION_PATTERNS.items():
        for pattern in patterns:
            m = pattern.search(html)
            if m:
                versions[tech_name] = m.group(1)
                break

    generator_result = _extract_generator_version(html)
    if generator_result:
        product, version = generator_result
        normalized = product.rstrip("!").strip()
        for known in VERSION_PATTERNS.keys():
            if known.lower() == normalized.lower():
                normalized = known
                break
        versions.setdefault(normalized, version)

    server_pv = _parse_header_product_version(resp_headers.get("server"))
    if server_pv:
        versions[server_pv[0]] = server_pv[1]

    powered_pv = _parse_header_product_version(resp_headers.get("x-powered-by"))
    if powered_pv:
        versions[powered_pv[0]] = powered_pv[1]

    return versions


async def detect_technologies(domain: str, timeout: int = 10) -> TechInfo:
    info = TechInfo()
    urls_to_try = [f"https://{domain}", f"http://{domain}"]

    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; TelegramToolboxBot/1.0; +domain-analyzer)"
    }

    async with aiohttp.ClientSession(timeout=timeout_cfg, headers=headers) as session:
        last_error = None
        for url in urls_to_try:
            try:
                async with session.get(url, ssl=False, allow_redirects=True) as resp:
                    info.status_code = resp.status
                    info.final_url = str(resp.url)
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                    info.web_server = resp_headers.get("server")
                    info.powered_by = resp_headers.get("x-powered-by")
                    info.raw_headers = resp_headers
                    info.selected_headers = {
                        h: resp_headers[h] for h in INTERESTING_HEADERS if h in resp_headers
                    }
                    info.cookies = sorted({cookie.key for cookie in resp.cookies.values()})

                    html = await resp.text(errors="ignore")

                    found = set()
                    for name, category, where, pattern in SIGNATURES:
                        haystack = html if where == "html" else "\n".join(resp_headers.values())
                        if pattern.search(haystack):
                            found.add((name, category))

                    # Cookie-based signals (Cloudflare, Shopify, etc.)
                    cookie_hay = " ".join(info.cookies).lower()
                    if any(c.startswith("__cf") or c == "__cf_bm" for c in info.cookies):
                        found.add(("Cloudflare", "CDN"))
                    if "_shopify" in cookie_hay or "shopify" in cookie_hay:
                        found.add(("Shopify", "CMS"))

                    info.detected = sorted(found)
                    info.versions = _extract_versions(html, resp_headers)

                    detected_names = {name for name, _ in info.detected}
                    for tech_name in list(info.versions.keys()):
                        if tech_name not in detected_names and tech_name in (
                            "nginx", "Apache", "PHP", "Express", "Microsoft-IIS"
                        ):
                            info.detected.append((tech_name, "Server/Runtime"))

                    info.detected = sorted(set(info.detected))
                    return info
            except Exception as e:
                last_error = str(e)
                logger.debug(f"Tech detect failed for {url}: {e}")
                continue

        info.error = last_error or "Could not connect to the site"

    return info
