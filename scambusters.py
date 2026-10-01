"""Pass-through client for the Scambusters API (POST /api/submit, GET /api/check).

The browser cannot call Scambusters directly without loosening this app's
Content-Security-Policy (``connect-src 'self'``), so the reporter sends its
requests here with the key in the ``X-Scambusters-Key`` header. This module
re-validates the submission with the same wallet rules the form uses, then
forwards it with ``Authorization: Bearer``. Scambusters' status code and JSON
body go back to the browser unchanged, so the UI reacts to exactly what
Scambusters said. The key is never logged, stored or echoed.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import requests

from wallet_validation import CHAINS, validate_wallet, validate_xrp_dest_tag

# "sb_" + the rest of a 35-character key; accept a range so a format change
# does not lock everyone out.
KEY_SHAPE = re.compile(r"^sb_[A-Za-z0-9_\-]{8,128}$")
MAX_WALLETS = 30
MAX_SITE_URL_LENGTH = 2048
# Scambusters refuses addresses starting with these (spreadsheet formula injection).
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_CONTROL_OR_SPACE = re.compile(r"[\s\x00-\x1f\x7f]")


class ScambustersNetworkError(Exception):
    """Scambusters could not be reached or did not answer in time."""

    status = 504

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def site_hostname(site_url: str) -> str | None:
    """The hostname Scambusters would parse, or None. https:// is assumed if absent."""
    text = (site_url or "").strip()
    if not text or len(text) > MAX_SITE_URL_LENGTH or _CONTROL_OR_SPACE.search(text):
        return None
    try:
        parts = urlsplit(text if "://" in text else "https://" + text)
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https"):
        return None
    host = (parts.hostname or "").rstrip(".")
    labels = host.split(".")
    if len(labels) < 2 or len(host) > 253 or any(not 0 < len(label) <= 63 for label in labels):
        return None
    if any(ch in host for ch in "/\\?#@:[]%"):
        return None
    return host


def build_submission(data: object) -> tuple[dict | None, list[str]]:
    """Validate the reporter's JSON and build the exact Scambusters payload.

    Errors use Scambusters' own wording style (``wallets[0].chain …``) so the
    browser maps local and upstream validation errors to fields the same way.
    """
    if not isinstance(data, dict):
        return None, ["The request body must be a JSON object."]
    errors: list[str] = []

    site_url = str(data.get("site_url") or "").strip()
    if not site_url:
        errors.append("site_url is required.")
    elif site_hostname(site_url) is None:
        errors.append(f"site_url has no parseable hostname: {site_url[:120]!r}")

    raw_wallets = data.get("wallets")
    if raw_wallets is None:
        raw_wallets = []
    if not isinstance(raw_wallets, list):
        return None, errors + ["wallets must be a list."]
    if len(raw_wallets) > MAX_WALLETS:
        return None, errors + [f"wallets has {len(raw_wallets)} entries; the maximum is {MAX_WALLETS}."]

    wallets = []
    for i, item in enumerate(raw_wallets):
        where = f"wallets[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{where} must be an object with address and chain.")
            continue
        address = str(item.get("address") or "").strip()
        chain = str(item.get("chain") or "").strip().lower()
        raw_tag = item.get("xrp_dest_tag")
        tag_text = "" if raw_tag is None else str(raw_tag).strip()
        if not address:
            errors.append(f"{where}.address is required.")
        if not chain:
            errors.append(f"{where}.chain is required.")
        elif chain not in CHAINS:
            errors.append(f"{where}.chain {chain!r} is not recognized.")
        if not address or chain not in CHAINS:
            continue
        if address.startswith(FORMULA_PREFIXES):
            errors.append(f"{where}.address cannot start with =, +, -, @, tab or carriage return.")
            continue
        check = validate_wallet(chain, address)
        if not check.valid:
            errors.append(f"{where}.address {check.errors[0] if check.errors else 'is not valid.'}")
            continue
        wallet = {"address": check.canonical, "chain": chain}
        if chain == "xrp":
            tag, tag_error = validate_xrp_dest_tag(tag_text)
            if tag_error:
                errors.append(f"{where}.xrp_dest_tag {tag_error}")
                continue
            wallet["xrp_dest_tag"] = tag
        elif tag_text:
            errors.append(f"{where}.xrp_dest_tag is only used for XRP wallets.")
            continue
        wallets.append(wallet)

    if errors:
        return None, errors
    payload: dict = {"site_url": site_url}
    if wallets:
        payload["wallets"] = wallets  # omitted entirely for site-only submissions
    return payload, []


class ScambustersClient:
    def __init__(self, base_url: str, timeout: int = 20):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {"User-Agent": "urlscan-dashboard/1.0 (Scambusters reporter)", "Accept": "application/json"}
        )

    def submit(self, api_key: str, payload: dict) -> tuple[int, dict, str | None]:
        return self._send("POST", "/api/submit", api_key, json=payload)

    def check(self, api_key: str, site_url: str) -> tuple[int, dict, str | None]:
        return self._send("GET", "/api/check", api_key, params={"site_url": site_url})

    def _send(self, method: str, path: str, api_key: str, **kwargs) -> tuple[int, dict, str | None]:
        """Returns (status, JSON body, Retry-After header) exactly as Scambusters sent them."""
        try:
            response = self._session.request(
                method,
                f"{self.base_url}{path}",
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=self.timeout,
                allow_redirects=False,
                **kwargs,
            )
        except requests.Timeout as exc:
            raise ScambustersNetworkError("Scambusters did not answer in time. Please retry.") from exc
        except requests.RequestException as exc:
            raise ScambustersNetworkError("Could not reach Scambusters. Please retry.") from exc

        status = response.status_code
        try:
            body = response.json()
        except ValueError:
            body = None
        if not isinstance(body, dict):
            body = {"error": f"Scambusters returned a response this page could not read (HTTP {status})."}
            if 200 <= status < 300:
                status = 502
        return status, body, response.headers.get("Retry-After")
