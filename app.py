"""urlscan.io search dashboard — Flask backend.

The browser never talks to urlscan.io directly. It posts a query here, this
process forwards it with the ``API-Key`` header, and hands back a trimmed JSON
payload. The key is used for the duration of one request and is never written
to disk or to a log line.
"""

from __future__ import annotations

import logging
import os
import re
import sys

from flask import Flask, g, jsonify, render_template, request

try:  # optional convenience, not required in production
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

from config import Config
from rate_limit import RateLimiter
from urlscan_client import (
    UrlscanClient,
    UrlscanError,
    build_cursor,
    normalise_result,
)

# --------------------------------------------------------------------------
# Logging. The scrubber is a backstop: we do not deliberately log keys, but a
# stray exception repr should not be able to leak one either.
# --------------------------------------------------------------------------

KEY_SHAPE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)


class ScrubSecrets(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover
            return True
        if KEY_SHAPE.search(message):
            record.msg = KEY_SHAPE.sub("<redacted>", message)
            record.args = ()
        return True


logging.basicConfig(
    level=logging.DEBUG if Config.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    stream=sys.stdout,
)
for handler in logging.getLogger().handlers:
    handler.addFilter(ScrubSecrets())

log = logging.getLogger("urlscan-dashboard")

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

client = UrlscanClient(Config.URLSCAN_BASE_URL, timeout=Config.REQUEST_TIMEOUT)
limiter = RateLimiter(
    per_minute=Config.RATE_LIMIT_PER_MINUTE,
    per_hour=Config.RATE_LIMIT_PER_HOUR,
)

# urlscan keys are UUIDs, but accept anything key-shaped so a future format
# change does not brick the dashboard.
API_KEY_SHAPE = re.compile(r"^[A-Za-z0-9._\-]{16,128}$")

# Reject control characters outright; everything else is urlscan's problem to
# parse, and it reports syntax errors better than we could.
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
CURSOR_SHAPE = re.compile(r"^[A-Za-z0-9._:\-]+$")


# --------------------------------------------------------------------------
# Request plumbing
# --------------------------------------------------------------------------


def client_identity() -> str:
    if Config.TRUST_PROXY:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def fail(message: str, status: int = 400, code: str = "bad_request", **extra):
    body = {"ok": False, "error": {"code": code, "message": message}}
    body["error"].update(extra)
    return jsonify(body), status


def resolve_api_key() -> tuple[str | None, tuple | None]:
    """Pick the key for this request: server key wins if it is forced."""
    if Config.FORCE_SERVER_KEY:
        if not Config.URLSCAN_API_KEY:
            return None, fail(
                "This server is configured to use its own API key, but none is set. "
                "Set URLSCAN_API_KEY in the environment.",
                503,
                "server_key_missing",
            )
        return Config.URLSCAN_API_KEY, None

    supplied = (request.headers.get("X-URLScan-Key") or "").strip()
    if supplied:
        if not API_KEY_SHAPE.match(supplied):
            return None, fail(
                "That does not look like a urlscan.io API key. Copy it from your "
                "profile page at urlscan.io/user/profile.",
                400,
                "malformed_api_key",
            )
        return supplied, None

    if Config.URLSCAN_API_KEY:
        return Config.URLSCAN_API_KEY, None

    return None, fail(
        "Add your urlscan.io API key to start searching.",
        401,
        "missing_api_key",
    )


def enforce_rate_limit():
    allowed, retry_after = limiter.check(client_identity())
    if allowed:
        return None
    return fail(
        f"Too many searches from this address. Try again in {retry_after} seconds.",
        429,
        "local_rate_limited",
        retry_after=retry_after,
    )


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "img-src 'self' data: https://urlscan.io https://*.urlscan.io; "
        "style-src 'self'; script-src 'self'; connect-src 'self'; "
        "form-action 'none'; frame-ancestors 'none'; base-uri 'self'",
    )
    # Search responses are per-key and must not be cached by a shared proxy.
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------


@app.route("/")
def index():
    return render_template(
        "index.html",
        sizes=Config.ALLOWED_SIZES,
        server_key_configured=bool(Config.URLSCAN_API_KEY),
        force_server_key=Config.FORCE_SERVER_KEY,
    )


@app.route("/api/health")
def health():
    return jsonify({"ok": True, "service": "urlscan-dashboard"})


@app.route("/api/config")
def runtime_config():
    """What the frontend needs to know before it renders the key field."""
    return jsonify(
        {
            "ok": True,
            "sizes": list(Config.ALLOWED_SIZES),
            "server_key_configured": bool(Config.URLSCAN_API_KEY),
            "force_server_key": Config.FORCE_SERVER_KEY,
            "max_query_length": Config.MAX_QUERY_LENGTH,
        }
    )


@app.route("/api/search")
def search():
    limited = enforce_rate_limit()
    if limited:
        return limited

    query = (request.args.get("q") or "").strip()
    if not query:
        return fail("Enter a query, for example page.domain:example.com.", 400, "empty_query")
    if len(query) > Config.MAX_QUERY_LENGTH:
        return fail(
            f"Query is too long. Keep it under {Config.MAX_QUERY_LENGTH} characters.",
            400,
            "query_too_long",
        )
    if CONTROL_CHARS.search(query):
        return fail("Query contains characters that are not allowed.", 400, "invalid_query")

    raw_size = request.args.get("size", "100")
    try:
        size = int(raw_size)
    except (TypeError, ValueError):
        return fail("Results per page must be a number.", 400, "invalid_size")
    if size not in Config.ALLOWED_SIZES:
        allowed = ", ".join(str(s) for s in Config.ALLOWED_SIZES)
        return fail(f"Results per page must be one of: {allowed}.", 400, "invalid_size")

    cursor = (request.args.get("search_after") or "").strip()
    if cursor:
        parts = cursor.split(",")
        if len(parts) > Config.MAX_CURSOR_PARTS or not all(
            CURSOR_SHAPE.match(part) for part in parts
        ):
            return fail("Pagination cursor is not valid. Run the search again.", 400, "invalid_cursor")

    api_key, error = resolve_api_key()
    if error:
        return error

    try:
        payload = client.search(api_key, query, size, cursor or None)
    except UrlscanError as exc:
        log.info("search rejected upstream: %s (%s)", exc.code, exc.status)
        extra = {"retry_after": exc.retry_after} if exc.retry_after else {}
        return fail(exc.message, exc.status, exc.code, **extra)

    raw_results = payload.get("results") or []
    results = [normalise_result(item, i + 1) for i, item in enumerate(raw_results)]

    total = payload.get("total")
    has_more = bool(payload.get("has_more"))

    return jsonify(
        {
            "ok": True,
            "results": results,
            "meta": {
                "count": len(results),
                "total": total,
                # urlscan counts exactly up to 10,000; past that, total is a floor.
                "total_is_exact": isinstance(total, int) and total <= 10000,
                "has_more": has_more,
                "took_ms": payload.get("took"),
                "next_cursor": build_cursor(raw_results) if has_more else None,
                "query": query,
                "size": size,
            },
        }
    )


@app.route("/api/quotas")
def quotas():
    limited = enforce_rate_limit()
    if limited:
        return limited

    api_key, error = resolve_api_key()
    if error:
        return error

    try:
        payload = client.quotas(api_key)
    except UrlscanError as exc:
        return fail(exc.message, exc.status, exc.code)

    search_quota = {}
    limits = payload.get("limits") if isinstance(payload, dict) else None
    if isinstance(limits, dict) and isinstance(limits.get("search"), dict):
        search_quota = limits["search"]

    return jsonify({"ok": True, "search": search_quota, "limits": limits or {}})


@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return fail("No such endpoint.", 404, "not_found")
    return render_template("index.html", sizes=Config.ALLOWED_SIZES,
                           server_key_configured=bool(Config.URLSCAN_API_KEY),
                           force_server_key=Config.FORCE_SERVER_KEY), 404


@app.errorhandler(Exception)
def unhandled(exc):
    log.exception("unhandled error: %s", type(exc).__name__)
    return fail("Something broke on this server. Check the service logs.", 500, "internal_error")


if __name__ == "__main__":
    log.info("starting with config: %s", Config.summary())
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
