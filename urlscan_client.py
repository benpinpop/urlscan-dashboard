"""Thin client for the urlscan.io v1 API.

Authentication is done with the ``API-Key`` request header. urlscan does not
accept the key as a query parameter, so it never appears in a URL, a proxy log
or a referrer.
"""

from __future__ import annotations

import requests


class UrlscanError(Exception):
    """Base error. ``status`` is the HTTP status to hand back to the browser."""

    status = 502
    code = "upstream_error"

    def __init__(self, message: str, *, retry_after: int | None = None):
        super().__init__(message)
        self.message = message
        self.retry_after = retry_after


class UrlscanAuthError(UrlscanError):
    status = 401
    code = "invalid_api_key"


class UrlscanQueryError(UrlscanError):
    status = 400
    code = "invalid_query"


class UrlscanRateLimitError(UrlscanError):
    status = 429
    code = "rate_limited"


class UrlscanNetworkError(UrlscanError):
    status = 504
    code = "network_error"


class UrlscanClient:
    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {
                "User-Agent": "urlscan-dashboard/1.0 (+https://urlscan.io/docs/api/)",
                "Accept": "application/json",
            }
        )

    # -- internals --------------------------------------------------------

    def _get(self, path: str, api_key: str, params: dict | None = None) -> dict:
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            response = self._session.get(
                url,
                params=params or {},
                headers={"API-Key": api_key},
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout as exc:
            raise UrlscanNetworkError("urlscan.io did not respond in time.") from exc
        except requests.exceptions.RequestException as exc:
            raise UrlscanNetworkError("Could not reach urlscan.io.") from exc

        return self._interpret(response)

    @staticmethod
    def _interpret(response: requests.Response) -> dict:
        try:
            payload = response.json()
        except ValueError:
            payload = {}

        if response.ok:
            return payload

        detail = ""
        if isinstance(payload, dict):
            detail = str(
                payload.get("message")
                or payload.get("description")
                or payload.get("error")
                or ""
            ).strip()

        if response.status_code == 401:
            raise UrlscanAuthError(
                detail or "urlscan.io rejected this API key. Check it and try again."
            )

        if response.status_code == 403:
            # urlscan answers in JSON. A 403 with anything else in the body
            # usually came from a proxy or filter between here and urlscan, and
            # blaming the user's key for that sends them looking in the wrong
            # place.
            if isinstance(payload, dict) and payload:
                raise UrlscanAuthError(
                    detail or "urlscan.io refused this key. Check that it is active and not rate limited."
                )
            raise UrlscanError(
                "The request to urlscan.io was blocked with HTTP 403 before it produced an API "
                "response. Check any egress proxy or firewall between this server and urlscan.io."
            )

        if response.status_code == 400:
            raise UrlscanQueryError(
                detail or "urlscan.io could not parse that query. Check the field names and syntax."
            )

        if response.status_code == 429:
            retry_after = None
            header = response.headers.get("Retry-After")
            if header and header.isdigit():
                retry_after = int(header)
            raise UrlscanRateLimitError(
                detail or "Search quota exhausted. Wait for the window to reset.",
                retry_after=retry_after,
            )

        raise UrlscanError(
            detail or f"urlscan.io returned HTTP {response.status_code}."
        )

    # -- endpoints --------------------------------------------------------

    def search(self, api_key: str, query: str, size: int, search_after: str | None = None) -> dict:
        params: dict[str, str | int] = {"q": query, "size": size}
        if search_after:
            params["search_after"] = search_after
        return self._get("/search/", api_key, params)

    def quotas(self, api_key: str) -> dict:
        return self._get("/quotas/", api_key)


# -- response shaping -----------------------------------------------------


def _text(value) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def normalise_result(raw: dict, index: int) -> dict:
    """Flatten one search hit into exactly what the grid renders.

    Every field comes straight out of the search response. In particular
    ``page.ip`` is the address that was actually contacted at scan time; we
    never resolve the domain ourselves, because a fresh lookup would report
    today's address rather than the one this scan recorded.
    """
    task = raw.get("task") or {}
    page = raw.get("page") or {}
    uuid = _text(task.get("uuid")) or _text(raw.get("_id"))

    tls_valid_days = page.get("tlsValidDays")
    try:
        tls_valid_days = int(tls_valid_days)
    except (TypeError, ValueError):
        tls_valid_days = None

    status = page.get("status")
    try:
        status = int(status)
    except (TypeError, ValueError):
        status = _text(status)

    return {
        "index": index,
        "uuid": uuid,
        "domain": _text(page.get("domain")) or _text(task.get("domain")),
        "apex_domain": _text(page.get("apexDomain")) or _text(task.get("apexDomain")),
        "scanned_url": _text(task.get("url")),
        "ip": _text(page.get("ip")),
        "ptr": _text(page.get("ptr")),
        "country": _text(page.get("country")),
        "server": _text(page.get("server")),
        "asn": _text(page.get("asn")),
        "asn_name": _text(page.get("asnname")),
        "status": status,
        "tls_issuer": _text(page.get("tlsIssuer")),
        "tls_valid_days": tls_valid_days,
        "tls_valid_from": _text(page.get("tlsValidFrom")),
        "screenshot": _text(raw.get("screenshot")),
        "time": _text(task.get("time")),
        "visibility": _text(task.get("visibility")),
        "result_url": f"https://urlscan.io/result/{uuid}/" if uuid else None,
        "sort": raw.get("sort") if isinstance(raw.get("sort"), list) else None,
    }


def build_cursor(results: list[dict]) -> str | None:
    """Cursor for the next page.

    urlscan paginates with ``search_after``: take the ``sort`` array from the
    last (oldest) hit of this batch and send it back comma-joined. This is not
    offset pagination, so there is no page number to increment.
    """
    for raw in reversed(results):
        sort_values = raw.get("sort")
        if isinstance(sort_values, list) and sort_values:
            return ",".join(str(v) for v in sort_values)
    return None
