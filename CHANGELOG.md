# Changelog

## Unreleased: TitanEye phase 6, scan details

### Added

- `POST /api/graph/site`: pulls a full urlscan result and maps hashes, filenames, third-party domains
  and their IPs, the TLS issuer, technologies, Telegram contacts, wallets in links, brands, tags and
  redirect hops (`graph_builder.shape_scan`).
- **Scan details** section on site nodes: pull the scan, tick what to add, add it. Choices are
  remembered per category.
- **Add scan to TitanEye** button on each results-grid frame and in the analyzer header.
- `static/js/titaneye-scan.js`; tests for scan shaping, caps, hostile strings and the route.

## Unreleased: TitanEye declutter and tidy layout

### Added

- **Declutter** button and number box: hides sites with fewer than N connections (default 2), plus
  anything left with no visible neighbour by that. Composes with the other filters, never hides the
  selected node or search matches, and is saved in cases.
- **Tidy** with three presets (organic, rings by kind, hierarchy). The organic layout fans out leaves,
  removes overlaps and packs disconnected pieces; expanding a node no longer moves existing nodes.
- Edge display list (auto, all, selection only, none), hover tooltip with the full value, and label
  settings that follow graph size.
- `static/js/titaneye-layout.js`; `tests/fixtures/titaneye_declutter.csv`.

### Changed

- A leading `www.` is dropped from site names (`graph_builder.strip_www`), in imports and in urlscan
  expansions, so `www.example.com` and `example.com` are one node. Saved cases keep the names they had.
- A cluster now needs at least three sites (was two).
- Force layout uses LinLog mode and a higher scaling ratio, which cut overlapping dots by more than half
  on the test data. Sigma is created with `allowInvalidContainer` so a frame queued as the panel closes
  cannot throw.

## Unreleased: TitanEye wallet intel and scale tools, phases 3 and 4

### Added

- Wallet intel: `chain_providers/` (Etherscan V2, Blockchain.com, Tronscan), `GET /api/chain/providers`,
  `POST /api/chain/summary`, and an on-chain section in a wallet node's detail panel. Keys are entered in
  a Keys panel, held in memory only and never stored or logged; the log scrubber also redacts `apikey=`
  and `api_code=`.
- Scale view drawer: overview, hosting-concentration map, rankings, clusters of sites that share an
  indicator, a noise filter for shared infrastructure and a timeline filter with playback.
- Crawler: bounded, cancellable and resumable walk outward from a selected node.
- Cases and export: saved cases (IndexedDB) and case files, nodes/edges CSV, indicator list, GraphML.
- Scambusters: a site node can open the reporter with its linked wallets filled in
  (`ScambustersReporter.open` accepts `wallets`).
- `TitanEye.core`, a small API the add-on files use; `tests/test_chain.py` (24 tests); 161 in total.

### Decisions

- Tronscan was added because it was needed for Tron wallets and answers 401 without a key.
- EVM chains show the sent-transaction count (nonce) because totals are not available from the free
  Etherscan endpoints.

## Unreleased: TitanEye find (Ctrl+F)

- Find box on the graph: matches a node's value, id, type and attributes, supports `type:<node type>`,
  highlights matches, steps with Enter / Shift+Enter, lists the first 40 results. See
  `docs/TITANEYE.md`.

## Unreleased: TitanEye dataset import, phase 2

### Added

- Import dataset dialog in the graph: CSV/TSV/TXT/JSON/JSONL read in the browser, column mapper with
  saved presets, validation preview, then add to the graph as a named layer.
- `POST /api/graph/ingest` and `graph_builder.ingest`: URL/host normalisation (defanging, `//host`,
  ports, IDNA, registrable domain) and wallet validation with chain labels like
  `Tether (USDT) - Arbitrum One (arb)`.
- Layer toggles per data source; `TitanEye.addFragment` and `uniqueLayerName`.
- `tests/fixtures/titaneye_*.csv`; 8 more tests (137 in total).

## Unreleased: TitanEye graph workspace, phase 1

A Maltego-style graph view. Plan: `docs/GRAPH_PLATFORM_PROMPT.md`; contract: `docs/TITANEYE.md`.

### Added

- `graph_builder.py`: node/edge ids, a fixed transform table (19 transforms plus a free-form
  query), per-type value validation, and shaping of search hits into linked nodes and edges.
- `GET /api/graph/transforms`, `POST /api/graph/expand` in `app.py`.
- `static/js/titaneye.js`, `static/css/titaneye.css`, `#titaneye` shell and a **TitanEye graph**
  header button: sigma.js rendering, ForceAtlas2 layout in a worker, type legend/filter, node detail
  panel with expand, "Open scan in analyzer" and "Search this domain in the grid".
- `static/vendor/`: graphology, sigma, ForceAtlas2 (main thread and worker), with licences.
- `tests/test_graph.py` (16 tests); 129 tests in total.

### Decisions

- Vendored builds instead of a CDN because the CSP allows only same-origin scripts.
- Transforms are an allow-list; the browser sends a transform id and value, never a field name.

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
