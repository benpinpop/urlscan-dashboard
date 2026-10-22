# Changelog

## Unreleased: Export by report status

With a reported-sites CSV imported, the Export menu can include or exclude Reported and Unreported
sites. Without an import, export is unchanged.

### Added

- `templates/index.html`: `#export-report-filters` fieldset (`#export-reported`,
  `#export-unreported`, both checked) in the Export menu, hidden by default. Styled by the existing
  `.export-menu fieldset` rules; no CSS change.
- `static/js/app.js`: `hasReportedSites` and `syncReportedExportUi` (shows the fieldset only while
  `state.reportedSites` is non-empty and resets both boxes to checked when the list goes away). It is
  called from `render()`, when the menu opens, and at startup.
- `exportResults`: when the list is present it calls `markReportedResults()` and filters on
  `result.csv_reported`, the same flag the frame badge shows, after dedupe and the dead/live filter.
  The `.csv` gets a trailing `Report status` column (`Reported` / `Unreported`) only in that case;
  existing columns keep their order.
- Both boxes unchecked, or no site left after filtering: no download, a message in the alert bar
  (the existing export pattern).

### Decisions

- Export still covers every loaded result, as before. The sheet's **Hide reported sites** is a
  display toggle like **Hide dead sites** and **Latest scan per domain**, neither of which ever
  affected export, so it does not either; the new checkboxes are the export's control.
- The checkbox state is in memory only (the DOM); nothing new is persisted.

## Unreleased: Query-field autocomplete

Typing a field name in the main query box opens a list of matching urlscan search fields, built from
`database/query_terms.csv`, with a yellow **PRO** badge on fields that need a urlscan Pro plan.
Purely additive: search, Enter-to-submit and pivots behave as before.

### Added

- `query_terms.py`: reads `database/query_terms.csv` once at startup with the `csv` module (quoted
  examples such as `asnname.keyword:"CLOUDFLARENET, US"` survive intact). Rows without a valid field
  name are skipped, duplicate fields keep their first row, `plan` and `regex` are normalised, and long
  text is clipped.
- `GET /api/query-terms`: `{"ok": true, "terms": [{field, group, type, plan, regex, description,
  example}, ...]}`. Needs no urlscan key; uses the shared rate limiter and `Cache-Control: no-store`
  like the other `/api/` routes; `503 query_terms_unavailable` if the list did not load.
- `static/js/autocomplete.js`: completes the field-name token under the caret only (not inside a
  value, quotes, `/regex/` or a range; `_exists_:` completes a bare field name). ARIA combobox
  pattern with a polite result-count announcement. Tab / Enter-on-highlight / click insert `field:`;
  Shift+Enter or clicking a row's example inserts the example. Fetched once per page load.
- `.pro-badge` and the `.qac*` dropdown styles in `static/css/styles.css`, with `--pro` / `--pro-ink`
  palette variables (dark text on yellow, about 11:1).
- Config: `QUERY_TERMS_PATH`.
- Tests: `tests/test_query_terms.py`, and `/api/query-terms` cases in `tests/test_routes.py`.

### Changed

- `templates/index.html`: `#query` is wrapped in `.query-box` (the dropdown's positioning context),
  gets `autocomplete="off"` so the browser's own history list does not cover the suggestions, and an
  `aria-label`.
- `static/css/styles.css`: below 760px `.console` is `position: relative` instead of `static`, so it
  still stacks above the result frames and the list is not painted under them. It stays non-sticky.
- `app.py`: the new route, and `static/js/autocomplete.js` in `REQUIRED_ASSETS`.
- `README.md`, `.env.example`: documented.

## Unreleased: Submit to Scambusters

A **Report scam** button in the header opens a reporter panel that submits a scam site and its wallet
addresses to Scambusters (`POST /api/submit`). The result analyzer gains **Check Scambusters**
(`GET /api/check` for the scan's site) and **Report to Scambusters** (opens the reporter prefilled).
Purely additive: no URLScan behaviour changed.

### Added

- `wallet_validation/`: wallet chain detection and checksum validation, **ported from the ScamHunt
  CTF** (`scamhunt-ctf/backend/scamhunt/validation/`). `codecs.py` is byte-identical; `wallets.py`
  is identical except for blocks marked `XRP ADDITION`.
- **XRP**, a new, labelled rule: classic `r…` addresses (Base58Check with the XRP Ledger alphabet, version
  0x00). A **destination tag is required** for XRP (digits, at most 4294967295) and is never sent for
  other chains. X-addresses are refused with guidance.
- `scambusters.py`: pass-through client plus server-side report validation (hostname, 30-wallet cap,
  chain codes, checksums, XRP tag rules, formula-injection prefixes).
- Routes: `POST /api/wallets/check`, `POST /api/scambusters/submit`, `GET /api/scambusters/check`.
- `static/js/scambusters.js`, `static/css/scambusters.css`, and the reporter markup in
  `templates/index.html`.
- Config: `SCAMBUSTERS_BASE_URL`, `SCAMBUSTERS_TIMEOUT`, `SCAMBUSTERS_RATE_LIMIT_PER_MINUTE`.
- Tests: `tests/test_wallet_validation.py` (the CTF's wallet and codec tests plus XRP) and
  `tests/test_scambusters.py` (routes with Scambusters stubbed; every status relayed).

### Changed

- `app.py`: new routes, a separate rate limiter for reporter calls, `sb_…` keys added to the log
  scrubber, and the new frontend files listed in `REQUIRED_ASSETS`.
- `static/js/analyzer.js`: optional `onReport` / `checkSite` init hooks and a Scambusters status
  strip under the page title.
- `static/js/app.js`: passes those hooks to the analyzer when the reporter is loaded.
- `README.md`, `INTEGRATION.md`, `.env.example`: documented.

### Decisions and constraints

- **CORS/CSP: requests go through this server.** The dashboard's CSP is `connect-src 'self'` (plus
  Cloudflare DNS), and its security model is that the browser only talks to its own origin. The
  reporter therefore calls two small pass-through routes that forward with `Authorization: Bearer`
  and return Scambusters' status and body unchanged. No new service, no CSP change. If Scambusters
  rate-limits by IP rather than per student, users of one shared instance would share that limit;
  its docs say limits are per student.
- **The key** is stored in `sessionStorage` (`scambusters_api_key`), shown masked (`sb_••••••••1234`),
  sent per request as `X-Scambusters-Key`, never stored or logged server-side, and redacted from any
  message shown.
- **Wallets are sent in canonical form**: EIP-55-checksummed `0x…`, CashAddr for Bitcoin Cash (legacy
  `1…`/`3…` converted), as the CTF stores them.
- **Avalanche** still accepts X-Chain `X-avax1…` addresses, as in the CTF.
- **The two 403s** are told apart by Scambusters' message text ("expired" vs the approval-list
  wording). The approval-list state blocks submitting for that key until the key changes.
- **Not changed: the ScamHunt CTF itself.** Its copy of the wallet module does not have XRP yet. Adding
  it there also needs a database migration (the chain column only allows the 13 existing codes) and
  somewhere to store the destination tag.
