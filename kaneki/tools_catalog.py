"""OSINT tool labels and keyboard routing."""

OSINT_TOOLS = frozenset(
    {
        "username",
        "host",
        "phone",
        "vehicle",
        "email",
    }
)

TOOL_PROMPTS = {
    "username": "Send username to scan:",
    "host": "Send a domain (example.com) or an IP address:",
    "phone": "Send phone number with country code, e.g. +31612345678:",
    "vehicle": "Send Dutch license plate, e.g. AB-12-CD:",
    "email": "Send email address:",
}

RATE_LIMIT_BUCKETS = {
    "username": "RATE_LIMIT_USERNAME_SECONDS",
    "email": "RATE_LIMIT_EMAIL_SECONDS",
    "phone": "RATE_LIMIT_PHONE_SECONDS",
    "vehicle": "RATE_LIMIT_VEHICLE_SECONDS",
    "host": "DOMAIN_RATE_LIMIT_SECONDS",
}

DEFAULT_RATE_LIMITS = {
    "username": 60.0,
    "email": 45.0,
    "phone": 20.0,
    "vehicle": 20.0,
    "host": 10.0,
}
