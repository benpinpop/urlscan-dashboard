"""urlscan.io search dashboard — Flask backend.

The browser sends urlscan requests through this app so the API key stays in a
request header. DOM scoring and live DNS lookups happen in the browser.
"""

from __future__ import annotations

import hashlib
import logging
import pathlib
import re
import sys
import time
from threading import Lock

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

try:  # optional convenience, not required in production
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

from config import Config
from domain_intel import DomainTable
from keyword_db import KeywordDatabase
from rate_limit import RateLimiter
from result_shaper import shape_result
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

client = UrlscanClient(
    Config.URLSCAN_BASE_URL,
    timeout=Config.REQUEST_TIMEOUT,
    site_url=Config.URLSCAN_SITE_URL,
)
limiter = RateLimiter(
    per_minute=Config.RATE_LIMIT_PER_MINUTE,
    per_hour=Config.RATE_LIMIT_PER_HOUR,
)
# Both tables are read once at import. A missing or broken keyword file must not
# take the search dashboard down with it, so the analyzer degrades instead: the
# content-analysis endpoint reports why it is unavailable and everything else
# keeps working.
KEYWORD_DB: KeywordDatabase | None = None
KEYWORD_DB_ERROR: str | None = None
try:
    KEYWORD_DB = (
        KeywordDatabase.load(Config.KEYWORD_DB_PATH)
        if Config.KEYWORD_DB_PATH
        else KeywordDatabase.load()
    )
except Exception as exc:  # pragma: no cover - configuration problem
    KEYWORD_DB_ERROR = f"{type(exc).__name__}: {exc}"
    log.error("risk keyword database unavailable: %s", KEYWORD_DB_ERROR)

DOMAIN_TABLE = (
    DomainTable.load(Config.DOMAIN_TABLE_PATH)
    if Config.DOMAIN_TABLE_PATH
    else DomainTable.load()
)

# urlscan keys are UUIDs, but accept anything key-shaped so a future format
# change does not brick the dashboard.
API_KEY_SHAPE = re.compile(r"^[A-Za-z0-9._\-]{16,128}$")

# Reject control characters outright; everything else is urlscan's problem to
# parse, and it reports syntax errors better than we could.
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
CURSOR_SHAPE = re.compile(r"^[A-Za-z0-9._:\-]+$")

# urlscan scan IDs are v4 UUIDs. Validating the shape here means the value can
# never reach the upstream path as anything but 36 hex-and-dash characters.
UUID_SHAPE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

RESULT_CACHE: dict[str, tuple[float, dict]] = {}
RESULT_CACHE_LOCK = Lock()


def cache_key(uuid: str, api_key: str) -> str:
    """Scope cached results to the key that fetched them.

    A private scan is visible to one account, so two analysts sharing this
    server must not be able to read each other's results out of the cache. The
    key itself is never stored: only a truncated digest of it.
    """
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
    return f"{uuid.lower()}:{digest}"


def cache_get(key: str) -> dict | None:
    if Config.RESULT_CACHE_TTL <= 0:
        return None
    now = time.monotonic()
    with RESULT_CACHE_LOCK:
        entry = RESULT_CACHE.get(key)
        if not entry:
            return None
        stored_at, document = entry
        if now - stored_at > Config.RESULT_CACHE_TTL:
            RESULT_CACHE.pop(key, None)
            return None
        return document


def cache_put(key: str, document: dict) -> None:
    if Config.RESULT_CACHE_TTL <= 0:
        return
    with RESULT_CACHE_LOCK:
        now = time.monotonic()
        stale = [
            existing
            for existing, (stored_at, _) in RESULT_CACHE.items()
            if now - stored_at > Config.RESULT_CACHE_TTL
        ]
        for existing in stale:
            RESULT_CACHE.pop(existing, None)
        while len(RESULT_CACHE) >= Config.RESULT_CACHE_MAX_ENTRIES:
            RESULT_CACHE.pop(next(iter(RESULT_CACHE)), None)
        RESULT_CACHE[key] = (now, document)


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
        "style-src 'self'; script-src 'self'; connect-src 'self' https://cloudflare-dns.com; "
        "form-action 'none'; frame-ancestors 'none'; base-uri 'self'",
    )
    # Search responses are per-key and must not be cached by a shared proxy.
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------


REQUIRED_ASSETS = (
    "templates/index.html",
    "static/css/styles.css",
    "static/css/analyzer.css",
    "static/js/app.js",
    "static/js/analyzer.js",
)


def missing_assets() -> list[str]:
    """Which frontend files are not where Flask will look for them."""
    root = pathlib.Path(app.root_path)
    return [rel for rel in REQUIRED_ASSETS if not (root / rel).is_file()]


def layout_help_page(missing: list[str]) -> str:
    items = "".join(f"<li><code>{name}</code></li>" for name in missing)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Frontend files are missing</title></head>
<body style="font:15px/1.6 system-ui,sans-serif;max-width:60ch;margin:48px auto;padding:0 16px">
<h1>Frontend files are missing</h1>
<p>The backend is running, but Flask cannot find these files under
<code>{app.root_path}</code>:</p>
<ul>{items}</ul>
<p>Flask resolves templates and static files by directory, so the layout has to be
exactly this:</p>
<pre style="background:#f4f4f4;padding:12px;overflow:auto">app.py
templates/index.html
static/css/styles.css
static/css/analyzer.css
static/js/app.js
static/js/analyzer.js</pre>
<p>If the files were downloaded individually they are probably sitting flat next to
<code>app.py</code>. Put them back:</p>
<pre style="background:#f4f4f4;padding:12px;overflow:auto">mkdir -p templates static/css static/js
mv index.html    templates/
mv styles.css    static/css/
mv analyzer.css  static/css/
mv app.js        static/js/
mv analyzer.js   static/js/</pre>
<p><code>app.js</code> and <code>app.py</code> are different files — do not overwrite one with
the other. Then restart the service.</p>
</body></html>"""


@app.route("/")
def index():
    missing = missing_assets()
    if missing:
        log.error("frontend files missing under %s: %s", app.root_path, ", ".join(missing))
        return layout_help_page(missing), 500

    return render_template(
        "index.html",
        sizes=Config.ALLOWED_SIZES,
        server_key_configured=bool(Config.URLSCAN_API_KEY),
        force_server_key=Config.FORCE_SERVER_KEY,
    )


@app.route("/favicon.ico")
def favicon():
    return "", 204


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
            "analyzer": {
                "content_analysis_available": KEYWORD_DB is not None,
                "keyword_count": KEYWORD_DB.summary()["keyword_count"] if KEYWORD_DB else 0,
                "category_count": KEYWORD_DB.summary()["category_count"] if KEYWORD_DB else 0,
                "domain_patterns": DOMAIN_TABLE.size,
                "max_dom_kb": Config.MAX_DOM_BYTES // 1024,
            },
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

    raw_resolve_dns = (request.args.get("resolve_dns", "true") or "").lower()
    if raw_resolve_dns not in {"true", "false"}:
        return fail("DNS resolution setting must be true or false.", 400, "invalid_dns_setting")
    resolve_dns = raw_resolve_dns == "true"

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

    search_started = time.perf_counter()
    try:
        payload = client.search(api_key, query, size, cursor or None)
    except UrlscanError as exc:
        log.info("search rejected upstream: %s (%s)", exc.code, exc.status)
        extra = {"retry_after": exc.retry_after} if exc.retry_after else {}
        return fail(exc.message, exc.status, exc.code, **extra)
    search_ms = round((time.perf_counter() - search_started) * 1000)

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
                "search_ms": search_ms,
                "dns_ms": None,
                "dns_enabled": False,
                "next_cursor": build_cursor(raw_results) if has_more else None,
                "query": query,
                "size": size,
            },
        }
    )


# --------------------------------------------------------------------------
# Result analyzer
# --------------------------------------------------------------------------


def fetch_result(uuid: str, api_key: str) -> tuple[dict | None, tuple | None, bool]:
    """Raw result document for a scan, from cache when it is still warm.

    Returns ``(document, error_response, cached)``.
    """
    key = cache_key(uuid, api_key)
    cached = cache_get(key)
    if cached is not None:
        return cached, None, True

    try:
        document = client.result(api_key, uuid)
    except UrlscanError as exc:
        log.info("result rejected upstream: %s (%s)", exc.code, exc.status)
        extra = {"retry_after": exc.retry_after} if exc.retry_after else {}
        return None, fail(exc.message, exc.status, exc.code, **extra), False

    if not isinstance(document, dict) or not document:
        return None, fail(
            "urlscan.io returned a result this server could not read.",
            502,
            "malformed_result",
        ), False

    cache_put(key, document)
    return document, None, False


def validate_uuid(uuid: str) -> tuple | None:
    if not UUID_SHAPE.match(uuid or ""):
        return fail(
            "That is not a urlscan.io scan ID. It looks like "
            "01234567-89ab-cdef-0123-456789abcdef.",
            400,
            "invalid_uuid",
        )
    return None


@app.route("/api/result/<uuid>")
def result(uuid: str):
    limited = enforce_rate_limit()
    if limited:
        return limited

    invalid = validate_uuid(uuid)
    if invalid:
        return invalid

    api_key, error = resolve_api_key()
    if error:
        return error

    started = time.perf_counter()
    document, error, cached = fetch_result(uuid, api_key)
    if error:
        return error

    payload = shape_result(document, DOMAIN_TABLE)
    payload["ok"] = True
    payload["meta"] = {
        "uuid": uuid.lower(),
        "cached": cached,
        "fetch_ms": round((time.perf_counter() - started) * 1000),
        "content_analysis_available": KEYWORD_DB is not None,
        "keyword_database": KEYWORD_DB.summary() if KEYWORD_DB else None,
        "keyword_database_error": KEYWORD_DB_ERROR,
    }
    return jsonify(payload)


@app.route("/api/dom/<uuid>")
def dom(uuid: str):
    """Fetch the stored DOM; extraction and scoring are performed by the browser."""
    limited = enforce_rate_limit()
    if limited:
        return limited

    invalid = validate_uuid(uuid)
    if invalid:
        return invalid

    api_key, error = resolve_api_key()
    if error:
        return error

    try:
        html = client.dom(api_key, uuid, max_bytes=Config.MAX_DOM_BYTES)
    except UrlscanError as exc:
        log.info("dom fetch rejected upstream: %s (%s)", exc.code, exc.status)
        return fail(exc.message, exc.status, exc.code)

    return jsonify({
        "ok": True,
        "uuid": uuid.lower(),
        "html": html,
        "meta": {"dom_bytes": len(html)},
    })


@app.route("/api/keywords")
def keywords():
    """What the scorer is working from, so a score can be argued with."""
    if KEYWORD_DB is None:
        return fail(
            "The risk keyword database could not be loaded on this server.",
            503,
            "keyword_db_unavailable",
        )
    return jsonify({"ok": True, **KEYWORD_DB.browser_data()})


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


@app.errorhandler(HTTPException)
def http_error(exc: HTTPException):
    """Render HTTP errors without touching a template.

    The 404 page used to render index.html, so a missing template turned every
    404 into a 500 and buried the real cause in a second traceback.
    """
    if request.path.startswith("/api/"):
        return fail(exc.description or exc.name, exc.code or 500, "http_error")

    body = (
        f"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{exc.code} {exc.name}</title></head>"
        f"<body style=\"font:15px/1.6 system-ui,sans-serif;max-width:52ch;"
        f"margin:48px auto;padding:0 16px\">"
        f"<h1>{exc.code} {exc.name}</h1>"
        f"<p>Nothing is served at <code>{request.path}</code>. "
        f"<a href=\"/\">Go to the dashboard</a>.</p></body></html>"
    )
    return body, exc.code or 500


@app.errorhandler(Exception)
def unhandled(exc):
    # HTTPException has its own handler above; let it through untouched.
    if isinstance(exc, HTTPException):
        return exc
    log.exception("unhandled error: %s", type(exc).__name__)
    if request.path.startswith("/api/"):
        return fail("Something broke on this server. Check the service logs.", 500, "internal_error")
    return "Internal server error. Check the service logs.", 500


if __name__ == "__main__":
    log.info("starting with config: %s", Config.summary())
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
