"""On-chain lookups for wallet nodes (TitanEye phase 3).

Basic information only: balance, address type, first and last activity and a few
provider-specific extras. Deeper analysis is deliberately not here; a provider
exposes ``summary`` and ``capabilities`` so more methods can be added later.

Keys arrive per request from the browser and are used for that one call. Nothing
in this package stores, logs or returns a key, and error messages are fixed text:
``requests`` exceptions embed the request URL (which carries Etherscan's key), so
their text is never passed on.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone


class ProviderError(Exception):
    """A lookup failure with a stable code the frontend can act on."""

    def __init__(self, message: str, status: int = 502, code: str = "provider_error",
                 retry_after: int | None = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code
        self.retry_after = retry_after


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def clean_text(value, limit: int = 60) -> str:
    """Provider strings (token names, contract names) are third-party text."""
    text = _CONTROL.sub("", str(value if value is not None else "")).strip()
    return text[:limit]


def iso_from_unix(value) -> str | None:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def decimal_string(raw: int, decimals: int) -> str:
    """``raw`` base units as a plain decimal string, without float rounding."""
    negative = raw < 0
    raw = abs(raw)
    whole, frac = divmod(raw, 10 ** decimals)
    text = str(whole)
    if frac:
        text += "." + str(frac).rjust(decimals, "0").rstrip("0")
    return ("-" if negative else "") + text
