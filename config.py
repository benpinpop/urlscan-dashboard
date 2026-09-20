"""Configuration loaded from environment variables.

Nothing in here is ever logged. The optional server-side API key is held in
memory only and is never returned to the browser.
"""

import os


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str | None, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


class Config:
    # --- Network binding -------------------------------------------------
    HOST = os.environ.get("HOST", "127.0.0.1")
    PORT = _as_int(os.environ.get("PORT"), 8000)
    DEBUG = _as_bool(os.environ.get("DEBUG"), False)

    # --- urlscan.io ------------------------------------------------------
    URLSCAN_BASE_URL = os.environ.get("URLSCAN_BASE_URL", "https://urlscan.io/api/v1")

    # The stored DOM is served from the site root rather than the API, so it is
    # configured separately instead of being derived from a response field.
    URLSCAN_SITE_URL = os.environ.get("URLSCAN_SITE_URL", "https://urlscan.io")

    # Optional fallback key. If set, users do not have to paste their own.
    # Leave unset for multi-user deployments so each analyst uses their own quota.
    URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY") or None

    # If true, the browser may not override the server key. Useful when you
    # want every request billed to one team account.
    FORCE_SERVER_KEY = _as_bool(os.environ.get("FORCE_SERVER_KEY"), False)

    REQUEST_TIMEOUT = _as_int(os.environ.get("REQUEST_TIMEOUT"), 30)
    DNS_CACHE_MAX_ENTRIES = max(1, _as_int(os.environ.get("DNS_CACHE_MAX_ENTRIES"), 10000))

    # --- Result analyzer -------------------------------------------------
    # Where the risk-word database and the domain classification table live.
    KEYWORD_DB_PATH = os.environ.get("KEYWORD_DB_PATH") or None
    DOMAIN_TABLE_PATH = os.environ.get("DOMAIN_TABLE_PATH") or None

    # Ceiling on a fetched DOM. Page content is attacker-controlled, so this is
    # a memory guard, not a tuning knob: raise it only if you need to.
    MAX_DOM_BYTES = max(64 * 1024, _as_int(os.environ.get("MAX_DOM_BYTES"), 4 * 1024 * 1024))

    # Characters of extracted text that are scored and returned to the browser.
    MAX_TEXT_CHARS = max(10_000, _as_int(os.environ.get("MAX_TEXT_CHARS"), 400_000))

    # Short-lived server-side cache so repeated opens of the same scan, and the
    # analyze step that follows a pull, do not each spend a search credit.
    RESULT_CACHE_TTL = max(0, _as_int(os.environ.get("RESULT_CACHE_TTL"), 600))
    RESULT_CACHE_MAX_ENTRIES = max(1, _as_int(os.environ.get("RESULT_CACHE_MAX_ENTRIES"), 64))

    # --- Abuse controls --------------------------------------------------
    RATE_LIMIT_PER_MINUTE = _as_int(os.environ.get("RATE_LIMIT_PER_MINUTE"), 30)
    RATE_LIMIT_PER_HOUR = _as_int(os.environ.get("RATE_LIMIT_PER_HOUR"), 400)

    # Content analysis fetches and parses a whole DOM, so it gets its own,
    # tighter budget on top of the shared per-minute limit.
    ANALYZE_LIMIT_PER_MINUTE = _as_int(os.environ.get("ANALYZE_LIMIT_PER_MINUTE"), 10)
    ANALYZE_LIMIT_PER_HOUR = _as_int(os.environ.get("ANALYZE_LIMIT_PER_HOUR"), 120)

    # Honour X-Forwarded-For. Only enable this behind a reverse proxy you
    # control, otherwise clients can spoof their own address and evade limits.
    TRUST_PROXY = _as_bool(os.environ.get("TRUST_PROXY"), False)

    # --- Query validation ------------------------------------------------
    # urlscan caps a single search at 10,000 results.
    ALLOWED_SIZES = (10, 25, 50, 100, 250, 500, 1000, 5000, 10000)
    MAX_QUERY_LENGTH = 1024
    MAX_CURSOR_PARTS = 8

    @classmethod
    def summary(cls) -> dict:
        """Non-sensitive startup summary, safe to log."""
        return {
            "host": cls.HOST,
            "port": cls.PORT,
            "debug": cls.DEBUG,
            "server_key_configured": bool(cls.URLSCAN_API_KEY),
            "force_server_key": cls.FORCE_SERVER_KEY,
            "dns_cache_max_entries": cls.DNS_CACHE_MAX_ENTRIES,
            "trust_proxy": cls.TRUST_PROXY,
            "rate_limit_per_minute": cls.RATE_LIMIT_PER_MINUTE,
            "rate_limit_per_hour": cls.RATE_LIMIT_PER_HOUR,
            "analyze_limit_per_minute": cls.ANALYZE_LIMIT_PER_MINUTE,
            "max_dom_bytes": cls.MAX_DOM_BYTES,
            "result_cache_ttl": cls.RESULT_CACHE_TTL,
        }
