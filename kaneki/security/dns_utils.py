"""DNS records for domain security reports (includes CAA)."""
import logging
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.resolver

logger = logging.getLogger(__name__)

# Order matches previous OSINT output; CNAME/SOA kept as extras.
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CAA", "CNAME", "SOA"]
PRIMARY_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CAA"]


@dataclass
class DnsInfo:
    records: dict[str, list[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


async def get_dns_info(domain: str, timeout: int = 5) -> DnsInfo:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    info = DnsInfo()

    for record_type in RECORD_TYPES:
        try:
            answer = await resolver.resolve(domain, record_type)
            values = [rdata.to_text().rstrip(".") for rdata in answer]
            if values:
                info.records[record_type] = values
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            info.errors["general"] = "Domain does not exist (NXDOMAIN)"
            break
        except Exception as e:
            info.errors[record_type] = str(e)
            logger.debug(f"DNS {record_type} lookup failed for {domain}: {e}")

    return info
