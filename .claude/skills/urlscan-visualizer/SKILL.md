---
name: urlscan-visualizer
description: Orientation map for the URLScan Visualizer repo (Flask + vanilla JS over urlscan.io, result analyzer, keyword risk scoring, domain classification, Scambusters reporter, wallet validation, query autocomplete). Use for any work in this repository - reading, debugging, adding features, editing routes, JS, CSS, CSV data or tests - before opening source files.
---

# URLScan Visualizer: orientation

Read this first, then open only the one `docs/` file that matches the task. Do not re-read the
whole codebase; the tables below say exactly where things are.

## Architecture in one screen

```
templates/index.html  (one page; scripts: examples.js, autocomplete.js, analyzer.js, scambusters.js, app.js[last])
   | same-origin fetch only (CSP connect-src 'self' + cloudflare-dns.com)
   v
app.py (Flask: all routes, validation, key resolution, result cache, CSP, log scrubber)
   |-- urlscan_client.py  -> urlscan.io /api/v1 (API-Key header) and /dom/<uuid>/
   |-- result_shaper.py   -> flattens one result for the analyzer (uses domain_intel.py)
   |-- keyword_db.py      -> keyword CSV; constants served to the browser scorer
   |-- query_terms.py     -> autocomplete field CSV
   |-- scambusters.py     -> validates + forwards to Scambusters (Bearer, no redirects)
   |-- wallet_validation/ -> chain detection/checksums (CTF port, XRP additions)
   `-- rate_limit.py      -> in-memory per-worker limiter
Browser does: rendering, sort/filter, live DNS (Cloudflare DoH), DOM text extraction and
keyword scoring (analyzer.js:scoreClientText), CSV export.
```

Globals: `window.URLSCAN_EXAMPLES`, `window.URLScanAnalyzer`, `window.ScambustersReporter`.
Data: `database/crypto_scam_keywords.csv`, `database/domain_categories.csv`, `database/query_terms.csv`
(loaded once at import; restart after edits).

## Where to look for X

| Task | Go to |
|---|---|
| Add/change an API route | `app.py` (copy the pattern of `search` / `result`: `enforce_rate_limit` -> validate -> `resolve_api_key` -> client -> `fail`) |
| Error codes / envelope | `app.py:fail`, `urlscan_client.py` `UrlscanError` subclasses (`status`, `code`) |
| Upstream status mapping | `urlscan_client.py:UrlscanClient._interpret` |
| Search result fields on the grid | `urlscan_client.py:normalise_result`, then `app.js:buildFrame` |
| Pagination cursor | `urlscan_client.py:build_cursor`, `app.py:search` (`CURSOR_SHAPE`), `app.js:runSearch(append)` |
| Env var / default | `config.py:Config` (gunicorn vars in `gunicorn.conf.py`) |
| Security headers / CSP | `app.py:security_headers` |
| Key handling | `app.py:resolve_api_key`, `app.js:currentKey`/`persistKey`, `scambusters.js:readKey`/`writeKey` |
| Server result cache | `app.py:cache_key`/`cache_get`/`cache_put`/`fetch_result` |
| Analyzer payload shape | `result_shaper.py:shape_result` (`summarise`, `shape_verdicts`, `shape_files`, `shape_domains`) |
| Threat score / verdict bands | `result_shaper.py:shape_verdicts` |
| Domain category / first party | `domain_intel.py:DomainTable.classify`, `registrable_domain`; data in `domain_categories.csv` |
| Keyword score (live UI) | `analyzer.js:scoreClientText`, `extractClientText`, `renderAnalysis` |
| Keyword score (Python, tests only) | `keyword_db.py:KeywordDatabase.score_text`, `extract_text`, `band_for`, `TIER_VALUE` |
| Analyzer cards / panels | `analyzer.js:buildCards`, `render*`, `openFilePanel`/`openDomainPanel`/`openHashPanel` |
| Pivot from analyzer to search | `analyzer.js:pivot` -> `app.js` `onPivot` in `URLScanAnalyzer.init` call |
| Grid render, sort, filter, collapse | `app.js:render`, `sortResults`, `applyFilter`, `collapseToLatest` |
| Live DNS | `app.js:dnsLookup`, `resolveDnsResults` (browser only) |
| Export / reported-sites CSV import | `app.js:exportResults`, `importReportedSites`, `reportedSiteKey` |
| Query autocomplete | `autocomplete.js:tokenAt`/`rank`/`complete`; `query_terms.py`; `/api/query-terms` |
| Example queries / Pivot Library | `static/js/examples.js`; `app.js:renderExamples`/`renderPivots` |
| Scambusters submit/check (server) | `app.py:scambusters_submit`/`scambusters_check`, `scambusters.py:build_submission`, `ScambustersClient` |
| Scambusters UI | `scambusters.js:submitReport`, `handleSubmitResponse`, `describeCheck`, `checkRow`, `validateKey` |
| Wallet rules | `wallet_validation/wallets.py:detect_chain`/`validate_wallet`/`validate_xrp_dest_tag` |
| Page markup / DOM ids | `templates/index.html`; id-to-owner table in `docs/FRONTEND.md` |
| Styles | `static/css/styles.css` (tokens, sheet, console, autocomplete), `analyzer.css` (overlay, cards, `.panel`), `scambusters.css` (reporter) |
| Tests | `tests/test_routes.py`, `test_analyzer.py`, `test_scambusters.py`, `test_wallet_validation.py`, `test_query_terms.py`; fixture `tests/fixture_result.json` |

## Hard constraints

1. No `innerHTML`/`outerHTML`/`insertAdjacentHTML`/`eval`. Build DOM with `createElement` +
   `textContent`. All scan, CSV and Scambusters data is hostile.
2. Strict CSP: no inline `<script>`, no `on*=` attributes, no `style="..."` in markup. JS may set
   `element.style.prop` (CSSOM). New hosts for `fetch` require a backend route instead.
3. Keys are never logged, echoed in messages, or placed in URLs. urlscan key travels as
   `X-URLScan-Key` -> `API-Key`; Scambusters key as `X-Scambusters-Key` -> `Authorization: Bearer`.
4. Validate on the server before any upstream call; browser checks are convenience only.
5. Scanned/resource URLs are shown as text with a copy button, never as links.
6. JS: one IIFE per file, `"use strict"`, ES5 syntax (`var`, `function`; no arrows, `let`/`const`,
   template literals, classes, async/await, modules). Storage access in `try/catch`.
7. urlscan-route errors use `fail(message, status, code)`; Scambusters routes relay upstream status
   and body unchanged and tag local errors with `"source": "local" | "proxy"`.
8. `wallet_validation/`: edit only inside `XRP ADDITION` blocks.
9. Tests: stdlib `unittest`, no network; stub module-level singletons (`application.client`,
   `application.scambusters_client`) and restore them.

## Commands (repo root)

```
python -m unittest discover -s tests                      # all tests (113, all passing)
python -m unittest discover -s tests -p "test_routes.py"  # one file
python -m unittest discover -s tests -k test_bands        # by name
python tests/stub_server.py 8010                          # UI on canned data, any 16+ char key
python app.py                                             # dev server (HOST/PORT/DEBUG from env/.env)
gunicorn -c gunicorn.conf.py wsgi:application             # production, Linux only
```

Windows: use `python`, set env vars with `$env:NAME="value"`, quote the OneDrive path, gunicorn and
`run.sh` do not apply. Do not use dotted test names (`tests.test_x`); a site-packages `tests`
package shadows the repo folder.

## Before you change anything

- Scoring constants live in `keyword_db.py` (`TIER_VALUE` 5 = 1.5, `SIGNAL_MIDPOINT` 2.2); tests
  and text must import them, not repeat numbers (`test_repetition_adds_a_bounded_bonus` once broke
  that way).
- Scoring lives in two places (Python for tests, JS for the UI) with different band thresholds.
- README / INTEGRATION / CHANGELOG have drifted (e.g. Scambusters key is in localStorage, not
  sessionStorage). Trust the code.
- `app.py` imports `.env` via python-dotenv, so a local `.env` can change test results. Never print
  or commit `.env`.

## Depth (read only the one you need)

| Need | File |
|---|---|
| Flows, caching, rate limiting, key handling, CSP | `docs/ARCHITECTURE.md` |
| Every route, params, validation order, error codes, config | `docs/BACKEND.md` |
| JS functions, state, storage keys, DOM ids, CSS ownership, z-index | `docs/FRONTEND.md` |
| CSV schemas, load rules, scoring constants, fixture | `docs/DATA.md` |
| Security/style rules, test patterns | `docs/CONVENTIONS.md` |
| Traps, doc drift, Windows vs Linux, stub limits | `docs/GOTCHAS.md` |
