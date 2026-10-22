# Architecture

Flask backend (no database, no build step) plus vanilla-JS frontend served from the same origin.
The backend is a thin, validating proxy to urlscan.io and Scambusters; almost all presentation,
sorting, filtering, text extraction and keyword scoring happen in the browser.

```
Browser (templates/index.html + static/js/*.js)
  |-- same-origin fetch, X-URLScan-Key ------> Flask app.py ---- API-Key header ----> urlscan.io /api/v1/*
  |                                                         \--- API-Key header ----> urlscan.io /dom/<uuid>/
  |-- same-origin fetch, X-Scambusters-Key --> Flask app.py ---- Authorization: Bearer -> Scambusters /api/submit, /api/check
  |-- direct fetch (no key) -----------------> https://cloudflare-dns.com/dns-query   (live DNS toggle only)
  `-- <img> loads -----------------------------> urlscan.io screenshots (CSP img-src allows urlscan.io)
```

## Module responsibilities

| File | Responsibility |
|---|---|
| `app.py` | Flask app, every route, input validation, key resolution, result cache, security headers, log scrubber, error handlers. Loads CSV tables at import. |
| `config.py` | `Config` class: every env var, parsed once at import. `Config.summary()` is the only thing logged. |
| `urlscan_client.py` | `UrlscanClient` (search, quotas, result, dom), `UrlscanError` hierarchy (each subclass carries `status` + `code`), `normalise_result` (search hit to grid row), `build_cursor`. |
| `result_shaper.py` | `shape_result(document, DomainTable)`: flattens one raw urlscan result into summary / verdicts / files / domains / stats. Pure, no network. |
| `domain_intel.py` | `DomainTable` (CSV pattern table, `classify`), `registrable_domain` (heuristic apex, not a PSL), `CATEGORY_LABELS`. |
| `keyword_db.py` | `KeywordDatabase` (CSV load, `browser_data`, `summary`, Python `score_text`), `extract_text`, `band_for`, scoring constants. Served to the browser via `/api/keywords`; the Python scorer itself is only exercised by tests. |
| `query_terms.py` | `QueryTerms.load` / `browser_data`: autocomplete field list from CSV. |
| `rate_limit.py` | `RateLimiter`: in-memory sliding window, per process. |
| `scambusters.py` | `ScambustersClient` (pass-through, no redirects), `build_submission` (server-side re-validation), `site_hostname`, `KEY_SHAPE`, `MAX_WALLETS`. |
| `wallet_validation/` | Port of the ScamHunt CTF validator: `detect_chain`, `validate_wallet`, `validate_xrp_dest_tag`, `CHAINS`. `codecs.py` holds Base58/Bech32/CashAddr/Keccak. Stdlib only. |
| `wsgi.py`, `gunicorn.conf.py` | Production entrypoint (`wsgi:application`), gthread workers. |
| `static/js/app.js` | Contact sheet: search, render, sort/filter, pagination, DNS, export, CSV import, lightbox, wiring of the other modules. |
| `static/js/analyzer.js` | `window.URLScanAnalyzer`: single-scan overlay, client-side DOM text extraction and keyword scoring, hash correlation. |
| `static/js/scambusters.js` | `window.ScambustersReporter`: reporter panel, key handling, wallet rows, check/submit. |
| `static/js/autocomplete.js` | Query-field autocomplete on `#query`. No global. |
| `static/js/examples.js` | `window.URLSCAN_EXAMPLES`: query strings for the empty state and the Pivot Library. |

## Startup (import of `app.py`)

1. `load_dotenv()` if python-dotenv is installed (so a local `.env` affects tests too).
2. `Config` reads env vars (import time; later env changes are ignored).
3. Logging configured; `ScrubSecrets` filter added to root handlers.
4. Module-level singletons: `client` (UrlscanClient), `limiter`, `scambusters_client`, `scambusters_limiter`.
5. CSV tables: `KEYWORD_DB` (failure sets `KEYWORD_DB_ERROR`, analyzer degrades), `DOMAIN_TABLE`
   (missing file gives an empty table, no error), `QUERY_TERMS` (failure logged, route returns 503).

Tests swap the singletons directly (`application.client = Stub()`), see `docs/CONVENTIONS.md`.

## Request flows

| Flow | Path |
|---|---|
| Search | `app.js:runSearch` -> `GET /api/search` -> `app.py:search` validates -> `UrlscanClient.search` -> `normalise_result` per hit, `build_cursor` -> grid via `app.js:render`. |
| Next page | `runSearch(true)` sends `search_after=<meta.next_cursor>`; results appended, indexes offset. |
| Live DNS | Only if `#resolve-dns` is checked: `app.js:resolveDnsResults` -> `dnsLookup` fetches Cloudflare DoH directly from the browser (A records). The server receives `resolve_dns` but only validates it; `meta.dns_enabled` is always `false`. |
| Quota | `app.js:checkQuota` -> `GET /api/quotas` -> upstream `/quotas/`, returns `limits.search`. |
| Analyzer result | `URLScanAnalyzer.open(uuid)` -> sessionStorage hit or `GET /api/result/<uuid>` -> `app.py:fetch_result` (server cache) -> `shape_result` -> cards. |
| Content analysis | `analyzer.js:runAnalysis` -> parallel `GET /api/dom/<uuid>` + `GET /api/keywords` -> `analyzeClientDom` (DOMParser text extraction + `scoreClientText`) in the browser. |
| Hash correlation | `analyzer.js:openHashPanel` -> `GET /api/search?q=hash:<value>&size=25&resolve_dns=false`. |
| Autocomplete | `autocomplete.js` fetches `GET /api/query-terms` once per page load (no key needed). |
| Wallet live check | `scambusters.js:checkRow` (debounced 300 ms) -> `POST /api/wallets/check`. |
| Report | `scambusters.js:submitReport` / `submitSiteOnly` -> `POST /api/scambusters/submit` -> `build_submission` re-validates -> `ScambustersClient.submit` -> upstream status/body relayed. |
| Site check | `scambusters.js:describeCheck` -> `GET /api/scambusters/check?site_url=` -> relayed. Key validation also uses this route (see GOTCHAS). |

## Caching

| Cache | Where | Scope / eviction |
|---|---|---|
| `RESULT_CACHE` | `app.py` module dict, guarded by `RESULT_CACHE_LOCK` | Raw result documents only. Key `"<uuid>:<sha256(api_key)[:16]>"` (`cache_key`). TTL `RESULT_CACHE_TTL` (0 disables), max `RESULT_CACHE_MAX_ENTRIES`, oldest-inserted evicted. Per gunicorn worker. Search, DOM, quotas are never cached server-side. |
| `DomainTable._cache` | `domain_intel.py` | `(host, path[:80])` -> category; cleared wholesale above 20,000 entries. |
| Analyzer result / analysis | browser `sessionStorage` `urlscan-analyzer.result.<uuid>`, `urlscan-analyzer.analysis.<uuid>` | Per tab, not key-aware: `app.js` calls `URLScanAnalyzer.clearCache()` on key `change` and on Forget. |
| DoH answers | browser HTTP cache (`cache: "force-cache"`) | Browser-managed. |
| HTTP | `Cache-Control: no-store` on every `/api/*` response | Set in `app.py:security_headers`. |

## Rate limiting

Two `RateLimiter` instances, keyed by `app.py:client_identity()` (remote addr, or first
`X-Forwarded-For` hop when `TRUST_PROXY`). In-memory, per worker: effective limit is N workers x limit.
The limiter is checked first in each route, so requests that then fail validation still count
(requests refused by the limiter itself are not recorded).

| Limiter | Limits | Routes |
|---|---|---|
| `limiter` | `RATE_LIMIT_PER_MINUTE` / `RATE_LIMIT_PER_HOUR` | `/api/search`, `/api/result/<uuid>`, `/api/dom/<uuid>`, `/api/quotas`, `/api/query-terms` |
| `scambusters_limiter` | `SCAMBUSTERS_RATE_LIMIT_PER_MINUTE`, no hourly cap | `/api/scambusters/submit`, `/api/scambusters/check` |
| none | | `/`, `/api/health`, `/api/config`, `/api/keywords`, `/api/wallets/check` |

## Key handling

**urlscan key**
- Browser: `#api-key` input. Persisted to `localStorage["urlscan-dashboard.apikey"]` only when
  "Keep this key in this browser" is checked (`app.js:persistKey`).
- Sent as `X-URLScan-Key` on same-origin requests (`app.js:request`, `analyzer.js:request`), omitted when empty.
- `app.py:resolve_api_key`: `FORCE_SERVER_KEY` -> server key (503 `server_key_missing` if unset);
  else browser key (shape-checked by `API_KEY_SHAPE`, 400 `malformed_api_key`); else server key; else 401 `missing_api_key`.
- Upstream: `API-Key` header only (`UrlscanClient._get`, `_get_text`). Never in a URL.

**Scambusters key**
- Browser: `localStorage["scambusters_api_key"]` (memory fallback if storage blocked), shown masked
  `sb_••••••••<last4>` (`scambusters.js:maskKey`), redacted from messages (`redact`).
- Sent as `X-Scambusters-Key`; `app.py:_scambusters_key` checks `scambusters.KEY_SHAPE`;
  forwarded as `Authorization: Bearer`, `allow_redirects=False`.

**Logs**: `app.py:ScrubSecrets` replaces UUID-shaped strings and `sb_...` tokens with `<redacted>`.
Gunicorn `access_log_format` omits query strings. Nothing logs headers.

## Security headers (`app.py:security_headers`, every response)

`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Permissions-Policy` (geolocation/microphone/camera off), and CSP:

```
default-src 'self'; img-src 'self' data: https://urlscan.io https://*.urlscan.io;
style-src 'self'; script-src 'self'; connect-src 'self' https://cloudflare-dns.com;
form-action 'none'; frame-ancestors 'none'; base-uri 'self'
```

## Deployment shapes

| Mode | How |
|---|---|
| Dev (any OS) | `python app.py` (Flask dev server, `HOST`/`PORT`/`DEBUG` from env). |
| Stub (no key, no network to urlscan) | `python tests/stub_server.py 8010`. |
| Prod (Linux) | `gunicorn -c gunicorn.conf.py wsgi:application` (via `run.sh`, systemd unit in `deploy/`, or Docker). |
| Docker | `Dockerfile` (python:3.12-slim, non-root, healthcheck on `/api/health`), `docker-compose.yml` (loopback publish, read-only FS, `TRUST_PROXY=true`). |
| Reverse proxy | `deploy/nginx.conf.example`. |
