# Backend reference

All routes live in `app.py`. Python 3.10+ is required (`config.py` uses `X | None` annotations
without `from __future__`); Docker uses 3.12.

## Response envelopes

Two different shapes. Do not mix them.

| Routes | Success | Failure |
|---|---|---|
| urlscan routes (`/api/search`, `/api/result`, `/api/dom`, `/api/quotas`, `/api/keywords`, `/api/query-terms`, `/api/config`, `/api/health`) | `{"ok": true, ...}` | `{"ok": false, "error": {"code", "message", ...extra}}` built by `app.py:fail`. `extra` is e.g. `retry_after`. |
| `/api/wallets/check` | always HTTP 200, `{"detected", "chain", "requires_tag", "valid", "error", ...}` | same shape, `valid: false` |
| `/api/scambusters/*` | Scambusters' own status + JSON body, relayed unchanged (`app.py:_relay`), `Retry-After` passed through when numeric | Local: `{"error": "...", "source": "local"}` or `{"errors": [...], "source": "local"}`; network: `{"error": "...", "source": "proxy"}` 504 |

Any `HTTPException` under `/api/` becomes `fail(..., code="http_error")` (`app.py:http_error`),
e.g. 404 unknown route, 405 wrong method, 413 body over `MAX_CONTENT_LENGTH` (64 KB). Unhandled
exceptions under `/api/` become 500 `internal_error` (`app.py:unhandled`). Non-API errors return a
small HTML page.

## Routes

Order of checks matters: the rate limiter runs first where present, then input validation, then
key resolution, then the upstream call.

| Route | Method | Limiter | Key | Params / body | Validation (in order) | Success body |
|---|---|---|---|---|---|---|
| `/` | GET | none | none | | `missing_assets()` against `REQUIRED_ASSETS`; missing -> 500 HTML help page | `index.html` rendered with `sizes`, `server_key_configured`, `force_server_key`, `development_mode`, `evm_chains`, `other_chains`, `max_wallets` |
| `/favicon.ico` | GET | | | | | 204 empty |
| `/api/health` | GET | none | none | | | `{"ok": true, "service": "urlscan-dashboard"}` |
| `/api/config` | GET | none | none | | | `sizes`, `server_key_configured`, `force_server_key`, `max_query_length`, `analyzer{content_analysis_available, keyword_count, category_count, domain_patterns, max_dom_kb}`. Not called by the current frontend. |
| `/api/search` | GET | `limiter` | urlscan | `q`, `size` (default 100), `resolve_dns` (`true`/`false`, default `true`), `search_after` | `q` non-empty (`empty_query`), `<= MAX_QUERY_LENGTH` (`query_too_long`), no control chars (`invalid_query`); `size` int in `ALLOWED_SIZES` (`invalid_size`); `resolve_dns` (`invalid_dns_setting`); cursor `<= MAX_CURSOR_PARTS` comma parts each matching `CURSOR_SHAPE` (`invalid_cursor`) | `results[]` (from `normalise_result`), `meta{count, total, total_is_exact (total <= 10000), has_more, took_ms, search_ms, dns_ms: null, dns_enabled: false, next_cursor, query, size}` |
| `/api/result/<uuid>` | GET | `limiter` | urlscan | | `UUID_SHAPE` (`invalid_uuid`) | `shape_result(...)` + `ok` + `meta{uuid, cached, fetch_ms, content_analysis_available, keyword_database, keyword_database_error}`. Non-dict upstream -> 502 `malformed_result`. |
| `/api/dom/<uuid>` | GET | `limiter` | urlscan | | `UUID_SHAPE` | `{"ok", "uuid", "html", "meta": {"dom_bytes"}}`. Streams with `MAX_DOM_BYTES` ceiling. |
| `/api/keywords` | GET | none | none | | `KEYWORD_DB` loaded else 503 `keyword_db_unavailable` | `KeywordDatabase.browser_data()`: summary + `keywords[]` + scoring constants |
| `/api/query-terms` | GET | `limiter` | none | | `QUERY_TERMS` loaded else 503 `query_terms_unavailable` | `{"ok": true, "terms": [{field, group, type, plan, regex, description, example}]}` |
| `/api/quotas` | GET | `limiter` | urlscan | | | `{"ok", "search": limits.search or {}, "limits"}` |
| `/api/wallets/check` | POST | none | none | JSON `{"address", "chain"}` (`chain` empty = detect; address cut to 200 chars) | requested chain used if in `CHAINS`, else detected | `detected{chain, candidates, note}`, `chain`, `requires_tag` (chain == xrp), `valid`, `error`; plus `chain_label`, `canonical`, `format` when a chain was resolved |
| `/api/scambusters/submit` | POST | `scambusters_limiter` | Scambusters | Scambusters submit JSON `{"site_url", "wallets": [{address, chain, xrp_dest_tag?}]}` | key present + `KEY_SHAPE` (401 local); `scambusters.build_submission` (400 local, `errors[]` with Scambusters-style paths) | relayed |
| `/api/scambusters/check` | GET | `scambusters_limiter` | Scambusters | `site_url` | key; `site_url` present and `site_hostname()` parses (400 local) | relayed |

### Error codes (urlscan routes)

| Code | HTTP | Raised by |
|---|---|---|
| `empty_query`, `query_too_long`, `invalid_size`, `invalid_dns_setting`, `invalid_cursor` | 400 | `search` |
| `invalid_query` | 400 | `search` (control chars) or upstream 400 (`UrlscanQueryError`) |
| `invalid_uuid` | 400 | `validate_uuid` |
| `malformed_api_key` | 400 | `resolve_api_key` |
| `missing_api_key` | 401 | `resolve_api_key` |
| `invalid_api_key` | 401 | upstream 401, or 403 with a JSON body (`UrlscanAuthError`) |
| `not_found` | 404 | upstream 404 (also a scan still processing; DOM 404 has its own message) |
| `response_too_large` | 413 | DOM over `MAX_DOM_BYTES` (Content-Length or streamed count) |
| `local_rate_limited` | 429 | `enforce_rate_limit`, adds `retry_after` |
| `rate_limited` | 429 | upstream 429; `retry_after` added only on search/result when upstream sent a numeric `Retry-After` |
| `malformed_result` | 502 | `fetch_result` |
| `upstream_error` | 502 | any other upstream status, or 403 with a non-JSON body (proxy/firewall) |
| `server_key_missing` | 503 | `FORCE_SERVER_KEY` without `URLSCAN_API_KEY` |
| `keyword_db_unavailable`, `query_terms_unavailable` | 503 | table failed to load |
| `network_error` | 504 | timeout / connection error |
| `http_error` | varies | Werkzeug `HTTPException` on `/api/` |
| `internal_error` | 500 | unhandled exception on `/api/` |

The frontend refocuses the key field on `invalid_api_key`, `missing_api_key`, `malformed_api_key`
(`app.js:runSearch`).

## Configuration

Parsed in `config.py` at import. Booleans accept `1/true/yes/on` (case-insensitive). Unparseable
ints fall back to the default.

| Var | Default | Notes |
|---|---|---|
| `HOST` | `127.0.0.1` | `.env.example` and Dockerfile set `0.0.0.0` |
| `PORT` | `8000` | |
| `DEBUG` | `false` | Flask debug + DEBUG log level |
| `URLSCAN_BASE_URL` | `https://urlscan.io/api/v1` | |
| `URLSCAN_SITE_URL` | `https://urlscan.io` | DOM is fetched from `{this}/dom/<uuid>/` |
| `URLSCAN_API_KEY` | unset | optional shared key; never returned to the browser |
| `FORCE_SERVER_KEY` | `false` | ignore browser keys |
| `REQUEST_TIMEOUT` | `30` | seconds, urlscan calls |
| `KEYWORD_DB_PATH` / `DOMAIN_TABLE_PATH` / `QUERY_TERMS_PATH` | unset (shipped `database/*.csv`) | |
| `MAX_DOM_BYTES` | `4194304` | floor 65536 |
| `RESULT_CACHE_TTL` | `600` | seconds, 0 disables, floor 0 |
| `RESULT_CACHE_MAX_ENTRIES` | `64` | floor 1, per worker |
| `SCAMBUSTERS_BASE_URL` | `https://scambuster.intelligenceforgood.org` | |
| `SCAMBUSTERS_TIMEOUT` | `20` | floor 1 |
| `SCAMBUSTERS_RATE_LIMIT_PER_MINUTE` | `120` | |
| `RATE_LIMIT_PER_MINUTE` / `RATE_LIMIT_PER_HOUR` | `30` / `400` | 0 disables that window |
| `TRUST_PROXY` | `false` | use first `X-Forwarded-For` hop |
| `WEB_CONCURRENCY` | `min(4, cpu_count)` | `gunicorn.conf.py` only |
| `WEB_THREADS` | `4` | `gunicorn.conf.py` only |
| `LOG_LEVEL` | `info` | gunicorn only |

Constants (not env): `Config.ALLOWED_SIZES = (10, 25, 50, 100, 250, 500, 1000, 5000, 10000)`,
`MAX_QUERY_LENGTH = 1024`, `MAX_CURSOR_PARTS = 8`; `app.config["MAX_CONTENT_LENGTH"] = 64 KB`;
`scambusters.MAX_WALLETS = 30`, `MAX_SITE_URL_LENGTH = 2048`; `result_shaper.MAX_FILES = 1500`,
`MAX_HEADER_VALUE = 400`.

## Module APIs worth knowing

**`urlscan_client.py`**
- `UrlscanClient(base_url, timeout, site_url)`: `search(key, q, size, search_after)`, `quotas(key)`,
  `result(key, uuid)`, `dom(key, uuid, max_bytes)`. All raise `UrlscanError` subclasses.
- `UrlscanClient._interpret(response)`: status -> exception mapping (see table above).
- `normalise_result(raw, index)`: grid row fields `index, uuid, domain, apex_domain, domain_age_days,
  scanned_url, ip, ptr, country, server, asn, asn_name, status, tls_issuer, tls_valid_days,
  tls_valid_from, screenshot, time, visibility, result_url, sort`.
- `build_cursor(raw_results)`: last hit's `sort` array, comma-joined.

**`result_shaper.py`** (`shape_result` calls these)
- `summarise`: summary incl. `tls.certificate` (`_certificate` prefers the scanned host or its
  wildcard), counts, technologies (wappa processor, max 24). `report_url` / `screenshot_url` only
  built when the document UUID re-validates.
- `shape_verdicts`: `threat_score` = max of overall/urlscan/engines/community scores, floored by
  engine consensus %, floored at 60 if anything says malicious. Bands: `malicious` (>= 70 or any
  malicious flag), `suspicious` (>= 30), `low` (> 0), `clean`.
- `shape_files`: one row per `data.requests` entry (max 1500), hashes validated by length/hex
  (`_normalise_hash`) and merged with the download processor, headers ordered by `HEADER_PRIORITY`.
- `shape_domains`: from `stats.domainStats`, geo from `stats.ipStats`, sorted by request count.

**`domain_intel.py`**: `DomainTable.classify(host, path, apex)` -> `{category, category_label,
service, apex, is_first_party}`. First party (same `registrable_domain` as the scan apex) overrides
any table match.

**`scambusters.py`**: `build_submission(data) -> (payload | None, errors[])` rebuilds the payload
with canonical addresses, drops `wallets` when empty, requires `xrp_dest_tag` only for `xrp`, rejects
formula-injection prefixes `= + - @ \t \r`. `ScambustersClient._send` turns a non-JSON body into
`{"error": ...}` and a non-JSON 2xx into 502.

**`wallet_validation`**: `detect_chain(addr) -> Detection(chain, candidates, note)`,
`validate_wallet(chain, addr) -> WalletCheck(valid, canonical, format, key, errors)`,
`validate_xrp_dest_tag(raw) -> (normalized, error)`. Chain codes: `eth bsc matic arb avax op`
(EVM, `0x` defaults to `eth`), `btc trx ltc doge bch ada dash xrp`.

## Adding a route (checklist)

1. Call `enforce_rate_limit()` first if it touches urlscan or is cheap to abuse.
2. Validate every input before `resolve_api_key()` and before any upstream call.
3. Return errors with `fail(message, status, code)`; never echo the key.
4. Let `security_headers` add `no-store` (keep the path under `/api/`).
5. Add route tests in `tests/test_routes.py` with the `Stub` client; no network.
6. If a new frontend file is required for the page to work, add it to `REQUIRED_ASSETS`.
