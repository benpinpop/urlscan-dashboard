# Gotchas

Non-obvious traps, verified against the code. When a doc and the code disagree, the code wins.

## Scoring constants: derive, never hard-code

`keyword_db.TIER_VALUE` is `{1: 0.0, 2: 0.2, 3: 0.5, 4: 1.25, 5: 1.5}` and `SIGNAL_MIDPOINT` is 2.2.
Older copies of the docs and tests assumed 4 = 1.0, 5 = 1.25 and `/ 4`, which made
`tests/test_analyzer.py:Scoring.test_repetition_adds_a_bounded_bonus` fail
(`2.1 not less than or equal to 1.751`). In the current working tree the test computes its ceiling
from `TIER_VALUE[5]`, `REPEAT_BONUS` and `REPEAT_BONUS_CAP`, and the `formula` string in
`KeywordDatabase.score_text` is built from the constants, so all 113 tests pass. Keep it that way:
tests and user-facing text should import the constants rather than repeat numbers. If that test
fails again, check for a reintroduced literal before suspecting your change.

## There are two keyword scorers, and only one runs in production

| | Python `keyword_db.KeywordDatabase.score_text` + `extract_text` | JS `analyzer.js:scoreClientText` + `extractClientText` |
|---|---|---|
| Used by | tests only (no route calls it) | the UI ("Analyze page content") |
| Bands | `band_for`: 15 / 40 / 70 | inline: 20 / 50 / 75 |
| Text extraction | `HTMLParser`, newline after block tags, attribute text inline | `DOMParser`, `body.textContent`, attribute text appended at the end |
| `formula` field | yes (built from the constants) | absent, so the formula note renders empty |
| Constants | module constants | fetched from `/api/keywords` (`browser_data()`) |

Changing scoring means changing both, and the Python tests do not cover the JS path. The
`meta.fetch_ms` / `meta.score_ms` shown under an analysis are hard-coded `0`.

## Docs that drifted from the code

`README.md` was being rewritten while these docs were written, so it is not tabulated here; check
any README claim against the code. Drift in the other docs and comments:

| Claim (where) | Reality |
|---|---|
| Scambusters key kept in `sessionStorage` (CHANGELOG, `index.html` key note in `#sb-key`) | `localStorage["scambusters_api_key"]` (`scambusters.js:readKey`/`writeKey`); survives tab close |
| `/api/dom` can return `keyword_db_unavailable` (INTEGRATION) | Only `/api/keywords` returns it |
| 103 tests (INTEGRATION) | 113 |
| Analyzer `init` takes `getKey, onPivot, onReport, checkSite` (INTEGRATION, `analyzer.js` header) | Also `hasScambustersKey`, `onAddScambustersKey`; public `refreshScambusters()`, `isOpen()` |
| Reporter API `open/close/isOpen/hasKey/describeCheck` (INTEGRATION, `scambusters.js` header) | Also `isKeyValid`, `onKeyValidityChange`, `submitSiteOnly` |
| Script order `analyzer, scambusters, app` (INTEGRATION) | `examples.js` (not deferred) and `autocomplete.js` come first |
| Pill colour comes from `CATEGORY_LABELS` (INTEGRATION) | Pill colours are CSS classes in `analyzer.css` |
| "Hash (groups identical files)" sort label (`analyzer.js:buildFileTools`) | `analyzer.js:fileRows` drops later rows whose hash was already seen, so identical files never appear twice |

## Backend

- **`.env` leaks into tests.** `app.py` calls `load_dotenv()` at import, so a developer `.env`
  (e.g. `URLSCAN_API_KEY`, `FORCE_SERVER_KEY`, rate limits) changes test behaviour; with a server key
  set, `test_missing_key_is_reported` would fail. `Config` is read once at import: patch
  `Config.X` / module globals in tests, not `os.environ`.
- **Rate limiter is per worker and per process memory.** Effective limit is workers x limit; restarts
  reset it. Requests that fail validation still count. `TRUST_PROXY=true` without a real proxy lets
  clients spoof `X-Forwarded-For`.
- **Unlimited routes:** `/api/wallets/check`, `/api/keywords`, `/api/config`, `/api/health`.
- **`resolve_dns` is validated but ignored.** DNS runs in the browser against Cloudflare DoH.
  `meta.dns_enabled` is always `false`, `dns_ms` always `null`. There is no server-side DNS cache
  or DNS setting.
- **No separate content-analysis limit.** `/api/dom` uses the shared `limiter`; older docs said
  otherwise.
- **Result cache** is keyed by UUID + key digest, per worker, evicts oldest-inserted (not LRU).
  The browser sessionStorage cache is not key-aware; `app.js` clears it on key change/Forget.
- **`not_found` (404)** is also what urlscan returns for a scan still processing.
- **`retry_after`** on upstream 429 is only forwarded by `/api/search` and `/api/result`.
- **Scambusters 403s:** submit distinguishes "expired" from "not approved" by regex on the message
  text; the check path (`describeCheckResponse`) treats every 403 as expired.
- **Non-JSON 2xx from Scambusters** becomes 502 (`ScambustersClient._send`).
- **Body limit:** `MAX_CONTENT_LENGTH` 64 KB; an oversized POST to a Scambusters route gets the
  urlscan-style `http_error` envelope, not the Scambusters shape.
- **Domain path patterns** (`google.com/recaptcha`) are substring matches on `host + path`, so they
  are not anchored to a label boundary like host patterns are.
- **`registrable_domain`** is a heuristic list, not the Public Suffix List; first-party detection can
  be wrong for unlisted multi-label suffixes.
- **Error/help pages use inline `style` attributes**, which the app's own CSP blocks, so
  `layout_help_page` and the HTML error page render unstyled. `layout_help_page` also lists an old
  file set (no `scambusters.*`, `autocomplete.js`).
- **`REQUIRED_ASSETS`** gates `/`; adding a required frontend file without listing it is fine,
  listing a file that does not exist turns `/` into a 500 help page. `examples.js` is not listed.
- **`wallet_validation/`** must stay a faithful copy of the CTF module; edits belong only in
  `XRP ADDITION` blocks.

## Frontend

- **`render()` rebuilds every frame.** Per-frame state (Scambusters check result, Instant Report
  "Reported" label) is lost on any re-render: sort, collapse, toggles, and the second render after
  DNS lookups finish. Filtering (`applyFilter`) does not re-render.
- **Scambusters key validation spends a real check.** `scambusters.js:validateKey` calls
  `/api/scambusters/check?site_url=https://google.com/` on page load (if a key is stored) and on save.
  It counts against the user's Scambusters check quota and the local limiter. A 401 wipes the key.
- **Frame Scambusters buttons** need all of: valid key (`isKeyValid`), `scanned_url`, and
  `#toggle-scambusters` checked.
- **Reported-sites CSV import** (`app.js:importReportedSites`) joins each row's cells with no
  separator and only accepts values starting with `http://` / `https://`; bare hostnames are ignored
  and multi-column rows produce wrong hostnames. A header row is skipped only if the first cell is
  `site_url_original`. Requires a valid Scambusters key.
- **Script order matters.** `app.js` must load last; `examples.js` is not deferred and must define
  `window.URLSCAN_EXAMPLES` before `app.js` runs.
- **Enter in `#query`** is handled twice by design: `autocomplete.js` (capture on `#query-box`)
  consumes it only when an option is highlighted; otherwise `app.js` searches.
- **Escape** has three independent document listeners: the reporter's (capture phase, stops
  propagation when it closes the reporter), the analyzer's (closes `#an-panel` if open, else the
  analyzer overlay) and `app.js`'s (closes the lightbox). The Pivot Library view has no Escape
  handler.
- **No inline styles in markup**, but JS sets `element.style.*` (CSSOM) in `analyzer.js` for bar
  widths and spacing; that is allowed by CSP. Never use `setAttribute("style", ...)`.
- **`autocomplete.js` must not submit.** It only edits the token under the caret; programmatic
  value changes (pivots, examples) fire no input event and never open the list.

## Running on Windows vs Linux

| Topic | Windows (maintainer's machine) | Linux / Docker |
|---|---|---|
| Server | gunicorn does not run on Windows. Use `python app.py` or `python tests/stub_server.py 8010`. | `gunicorn -c gunicorn.conf.py wsgi:application`, `./run.sh`, systemd, Docker |
| Env vars | PowerShell: `$env:DEBUG="true"; python app.py` | `DEBUG=true python3 app.py` |
| Python | `python` (3.13 here); `python3` may be the Microsoft Store alias | `python3` |
| venv | `venv\Scripts\` (`run.sh` assumes `venv/bin/`) | `venv/bin/` |
| Tests | `python -m unittest discover -s tests`; dotted module names fail because a site-packages `tests` package shadows the repo's `tests/` | same command |
| Paths | Repo lives under OneDrive with spaces in the path; quote it | |
| Line endings | `core.autocrlf=true`; make sure `run.sh` keeps LF before it reaches Linux/Docker | |

`HOST`: `Config` defaults to `127.0.0.1`, but `.env.example` (copied to `.env` by `run.sh`) and the
Dockerfile set `0.0.0.0`. On a bare host that exposes the app on every interface.

## Stub server limits (`tests/stub_server.py`)

- Replaces only the urlscan client. `/api/search` ignores the query and returns the same 3 canned
  rows; every scan ID returns `tests/fixture_result.json`; every DOM is one canned scam page.
- Scambusters is not stubbed: reporter calls go to `SCAMBUSTERS_BASE_URL` (real service unless
  overridden), and so does key validation.
- Live DNS still queries Cloudflare from the browser.
