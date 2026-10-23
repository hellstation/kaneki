"""
modules/ssl_utils.py — проверка SSL/TLS сертификата домена: срок
действия, издатель, самоподписанность, версия согласованного
протокола.

Используем стандартный модуль ssl + cryptography для разбора
сертификата без валидации цепочки доверия (нам нужно увидеть даже
просроченный/самоподписанный сертификат, а не только доверенный).
"""
import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
EXPIRY_WARNING_DAYS = 14


@dataclass
class SslInfo:
    has_ssl: bool = False
    issuer: str | None = None
    subject: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    is_expired: bool = False
    is_expiring_soon: bool = False
    is_self_signed: bool = False
    protocol_version: str | None = None
    is_weak_protocol: bool = False
    error: str | None = None


def _common_name(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        return attrs[0].value
    try:
        return name.rfc4514_string()
    except Exception:
        return None


def _blocking_ssl_check(domain: str, port: int, timeout: int) -> SslInfo:
    info = SslInfo()
    context = ssl.create_default_context()
    # Проверку цепочки доверия отключаем намеренно: нам важно увидеть
    # сертификат целиком (включая просроченный/самоподписанный), а не
    # только тот случай, когда он прошёл валидацию.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                info.protocol_version = ssock.version()
                info.is_weak_protocol = info.protocol_version in WEAK_PROTOCOLS
                der_cert = ssock.getpeercert(binary_form=True)

        if not der_cert:
            info.error = "Сертификат не получен от сервера"
            return info

        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        info.has_ssl = True
        info.issuer = _common_name(cert.issuer)
        info.subject = _common_name(cert.subject)
        info.is_self_signed = cert.issuer == cert.subject

        not_after = getattr(cert, "not_valid_after_utc", None)
        if not_after is None:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        not_before = getattr(cert, "not_valid_before_utc", None)
        if not_before is None:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

        info.not_before = not_before.strftime("%Y-%m-%d")
        info.not_after = not_after.strftime("%Y-%m-%d")

        now = datetime.now(timezone.utc)
        info.days_until_expiry = (not_after - now).days
        info.is_expired = not_after < now
        info.is_expiring_soon = (
            not info.is_expired and info.days_until_expiry <= EXPIRY_WARNING_DAYS
        )

    except socket.timeout:
        info.error = "Таймаут подключения по SSL"
    except ssl.SSLError as e:
        info.error = f"SSL-ошибка: {e}"
    except (socket.gaierror, ConnectionRefusedError, OSError) as e:
        info.error = f"Не удалось подключиться по HTTPS: {e}"
    except Exception as e:
        info.error = str(e)
        logger.warning(f"SSL check failed for {domain}: {e}")

    return info


async def get_ssl_info(domain: str, port: int = 443, timeout: int = 10) -> SslInfo:
    """Асинхронная обёртка над блокирующей socket/ssl проверкой."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _blocking_ssl_check, domain, port, timeout)
