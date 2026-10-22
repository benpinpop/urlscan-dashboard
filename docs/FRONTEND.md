# Frontend reference

One page, `templates/index.html`, no framework, no bundler. Every script is ES5-syntax inside an
IIFE with `"use strict"`; modern browser APIs (fetch, Promise.finally, Set/Map, URL, DOMParser,
regex lookbehind) are used freely.

## Script load order (`templates/index.html`)

| # | File | Attr | Exposes |
|---|---|---|---|
| 1 | `static/js/examples.js` | none (runs during parse) | `window.URLSCAN_EXAMPLES` |
| 2 | `static/js/autocomplete.js` | `defer` | nothing in the browser (`module.exports` only when `module` exists) |
| 3 | `static/js/analyzer.js` | `defer` | `window.URLScanAnalyzer` |
| 4 | `static/js/scambusters.js` | `defer` | `window.ScambustersReporter` |
| 5 | `static/js/app.js` | `defer` | nothing; wires 1, 3, 4 together |

`app.js` must stay last: it reads the three globals at startup. `examples.js` is not in
`app.py:REQUIRED_ASSETS`; a missing copy just leaves the examples list and Pivot Library empty.

## Browser storage

| Key | Store | Owner | Contents |
|---|---|---|---|
| `urlscan-dashboard.apikey` | localStorage | `app.js:persistKey` | urlscan key, only while "Keep this key" is checked |
| `urlscan-dashboard.reported-sites` | sessionStorage | `app.js:persistReportedSites` | JSON array of hostnames from the imported CSV |
| `urlscan-analyzer.result.<uuid>` | sessionStorage | `analyzer.js:cacheWrite` | `/api/result` body |
| `urlscan-analyzer.analysis.<uuid>` | sessionStorage | `analyzer.js:cacheWrite` | client-side content analysis |
| `scambusters_api_key` | localStorage (memory fallback) | `scambusters.js:writeKey` | Scambusters key |
| `scambusters_submit_blocked` | localStorage | `scambusters.js:setSubmitBlocked` | `"1"` after a non-expiry 403 on submit; cleared by `writeKey` |

## `static/js/app.js` (contact sheet)

**State** (`state`): `results`, `cursor`, `query`, `size`, `total`, `totalExact`, `hasMore`,
`dnsAvailable`, `searchMs`, `dnsMs`, `reportedSites` (Set or null), `busy`, `lastFocus`,
`displayedCount`. DOM handles live in `el`.

| Area | Functions |
|---|---|
| Key | `currentKey`, `syncKeyState`, `loadStoredKey`, `persistKey` (runs on every `input`) |
| HTTP | `request(path, params)`: same-origin GET, adds `X-URLScan-Key`, throws `Error` with `.code` from the error envelope |
| Search | `runSearch(append)`: builds params (`q`, `size`, `resolve_dns`, `search_after`), merges results, updates state, `render()`, then optional DNS |
| DNS | `validDnsName`, `dnsLookup` (Cloudflare DoH, A record), `resolveDnsResults` sets `live_ip`, `dns_status` |
| Render | `render` (collapse -> hide dead -> hide reported -> sort -> rebuild all frames -> `updateStatus` -> `applyFilter`), `buildFrame`, `sortResults`, `collapseToLatest` (latest scan per domain, `www.` stripped), `ipKey`, `statusText`, `tlsText`, `domainAgeText`, `isIpAddress` |
| Filter | `applyFilter`: toggles `.is-hidden` using each frame's `data-haystack` (no re-render) |
| Status | `updateStatus`, `showAlert`, `clearAlert`, `setBusy`, `syncDnsUi` |
| Export | `exportResults`, `csvCell` (Blob download `urlscan-sites.txt|csv`). Works on all of `state.results` (ignores the sheet's collapse / hide-dead / hide-reported / filter); its own filters run in order: dedupe -> dead/live -> reported/unreported. `hasReportedSites`, `syncReportedExportUi` show `#export-report-filters` only while `state.reportedSites` is non-empty (called from `render`, menu open and startup) and reset both boxes to checked otherwise. The report filter calls `markReportedResults` and uses `csv_reported`, so it matches the badge; CSV then gets a trailing `Report status` column. Nothing to export -> `showAlert`, no download |
| Reported-sites CSV | `importReportedSites` (needs a valid Scambusters key), `csvRows` (also TSV), `reportedSiteKey` (hostname, `www.` stripped, requires `http(s)://`), `markReportedResults`, `loadReportedSites` |
| Other | `checkQuota`, `openLightbox` / `closeLightbox`, `renderExamples`, `renderPivots` / `closePivots` |

**Event flow**
- `#run` click, or Enter in `#query` -> `runSearch(false)`. `#load-more` -> `runSearch(true)`.
- `#sort`, `#collapse-domain`, `#toggle-scambusters`, `#toggle-dead`, `#toggle-reported` -> `render()`.
- `#filter` input -> `applyFilter()`.
- `.density__btn` swaps `#sheet` class `cols-4|cols-6|cols-10`; `#toggle-details` toggles `.is-minimal`.
- Frame buttons: `.frame__analyze` -> `URLScanAnalyzer.open(uuid)`; `.frame__sb-check` ->
  `ScambustersReporter.describeCheck`; `.frame__sb-report` -> `open({siteUrl})`;
  `.frame__sb-instant` -> `submitSiteOnly`. SB buttons only render when the reporter key is valid,
  the row has `scanned_url`, and `#toggle-scambusters` is checked.
- Startup: `URLScanAnalyzer.init({...})` with `getKey`, `onPivot` (close analyzer, set `#query`,
  clear `#filter`, `runSearch(false)`), `onReport`, `checkSite`, `hasScambustersKey`,
  `onAddScambustersKey`; `ScambustersReporter.onKeyValidityChange` toggles `#sb-open`,
  `#sb-key-open`, `#scambusters-utility-control`, `#reported-sites-control`,
  `#reported-status-control` and calls `URLScanAnalyzer.refreshScambusters()`.

## `static/js/analyzer.js` (`window.URLScanAnalyzer`)

Public: `init(opts)`, `open(uuid|null)`, `close()`, `clearCache()`, `refreshScambusters()`, `isOpen()`.

`init` options: `getKey` (default reads `#api-key`), `onPivot(query)` (unset -> toast),
`onReport(siteUrl)`, `checkSite(siteUrl) -> Promise<{tone, title, detail, action, label?}>`,
`hasScambustersKey()`, `onAddScambustersKey()`. Scambusters buttons stay hidden unless the
relevant hooks exist and `hasScambustersKey()` is true (`paintScambusters`).

| Area | Functions |
|---|---|
| Lifecycle | `buildShell` (once; binds static ids), `open`, `close`, `load(uuid, force)`, `paintHeader`, `buildCards` |
| Cards (ids) | `card-summary` `renderSummary`; `card-verdicts` `renderVerdicts`; `card-content` `renderContentAnalysis`; `card-files` `buildFileTools` + `renderFiles` / `fileRows`; `card-domains` `renderDomains`. Built by `card(id, title, subtitle)`. |
| Content analysis | `runAnalysis` -> `analyzeClientDom` -> `extractClientText` (DOMParser; drops script/style/noscript/template/svg/iframe; appends alt/title/placeholder/value/aria-label text) + `scoreClientText` (the live scorer; constants from `/api/keywords`) -> `renderAnalysis`, `matchCard`, `highlightKeywordMatches` |
| Slide-over `#an-panel` | `openPanel`, `closePanel`, `openFilePanel`, `openDomainPanel` (choice of `domain:"x"` or `page.domain:"x"` pivot), `openHashPanel` (searches `hash:<v>`, stores count in `state.hashSeen`, re-renders files) |
| Scambusters strip | `paintScambusters`, `checkScambusters` (token guards against a scan switch mid-request), `scanSiteUrl` |
| Utils | `node(tag, cls, text)`, `clear`, `copyButton`, `copyText` / `fallbackCopy`, `withCopy`, `toast`, `chip`, `pill`, `statusCell`, `stat`, `barRow`, `pivot` |
| Cache | `cacheRead`, `cacheWrite` (on quota error clears the whole cache), `clearCache` |

Pivot queries emitted: `page.asn:<asn>`, `page.domain:"<d>"`, `page.apexDomain:"<d>"`,
`page.ip:<ip>`, `domain:"<d>"`, `filename:"<path>"`, `hash:<value>`.

## `static/js/scambusters.js` (`window.ScambustersReporter`)

Public: `open({siteUrl, focusKey})`, `close()`, `isOpen()`, `hasKey()`, `isKeyValid()`,
`onKeyValidityChange(fn)` (fires immediately with the current value), `submitSiteOnly(siteUrl) ->
Promise<{ok, submissionId, message}>`, `describeCheck(siteUrl)` (never rejects), plus test hooks
`_siteHostname`, `_refang`, `_mask`. `init()` runs itself (DOMContentLoaded or immediately).

| Area | Functions |
|---|---|
| Key | `readKey`, `writeKey`, `maskKey`, `redact`, `validateKey` (calls `/api/scambusters/check` for `https://google.com/`; 200 = valid, 401 = key wiped), `saveKey`, `editKey`, `paintKey`, `setKeyValidity` |
| Wallet rows | `addRow` (clones `#sb-wallet-template`), `wireRow`, `checkRow` (instant `guessChain`, then server check; `data-token` drops stale answers), `resetRow`, `paintTag`, `tagProblem`, `updateCap` |
| Row state | `data-state` = `empty|pending|valid|invalid|unchecked`; `data-user-chose` when the chain was picked by hand; `data-canonical` from the server |
| Submit | `submitReason` (single gate; its text is shown in `#sb-submit-hint`), `updateSubmitState`, `buildPayload`, `submitReport`, `handleSubmitResponse` (201/200 duplicate/400/401/403 expired/403 not approved/429 cooldown/503 retry/other), `applyValidationErrors` (maps `site_url ...` and `wallets[N].field ...`), `startCooldown` |
| Lookup | `describeCheck`, `describeCheckResponse` (tones `ok|info|warn|bad`, optional `label` used by frame buttons) |
| URL helpers | `refang` (`hxxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `[:]`), `siteHostname` (mirror of `scambusters.site_hostname`) |

Escape: `onKeydown` is registered in the capture phase and stops propagation so only the reporter
closes when it is open over the analyzer.

## `static/js/autocomplete.js`

Pure functions (exported for non-browser use): `tokenAt(value, caret)` (field token under the caret,
or null inside a value, quotes, `/regex/`, `[range]`/`{range}`; `_exists_:` completes a bare field),
`rank(terms, text)` (tier 0 prefix, 1 dotted-segment prefix, 2 substring; free before pro; max 40),
`complete(value, token, term, useExample)`.

Widget: `update(mayOpen)`, `show`, `close`, `setActive`, `move`, `accept`, `buildOption`, `announce`
(350 ms debounced, `#query-suggest-status`). Keydown handler is on `#query-box` in the capture
phase so a highlighted Enter is consumed before `app.js`'s Enter-to-search. Plain Enter closes the
list and lets the search run. Option selection uses `mousedown` + `preventDefault` to keep focus.

## DOM ids that JS depends on

| Owner | Ids |
|---|---|
| `app.js` | `api-key key-panel key-reveal key-forget key-remember query size sort filter collapse-domain toggle-scambusters reported-sites-file reported-sites-status reported-sites-control reported-status-control scambusters-utility-control sb-open sb-key-open resolve-dns toggle-details toggle-dead toggle-reported dns-status-control toggle-export export-menu export-dead export-live export-dedupe export-status-filters export-report-filters export-reported export-unreported export-type export-download run quota sheet empty status-line alert alert-msg alert-close loading more load-more more-note lightbox lightbox-img lightbox-title lightbox-facts lightbox-close frame-tpl example-list open-analyzer open-pivots pivots-view pivots-back pivots-list` |
| `autocomplete.js` | `query query-box query-suggest query-suggest-list query-suggest-status` |
| `analyzer.js` | `analyzer an-back an-uuid an-pull an-verdict-chip an-report an-loading an-loading-label an-alert an-alert-msg an-alert-close an-intro an-title an-page-title an-page-url an-body an-panel an-panel-title an-panel-body an-panel-close an-sb-check an-sb-report an-sb-add-key an-sb-status`; creates `card-*`, `an-analysis-results` |
| `scambusters.js` | `sb-panel sb-close sb-key sb-key-edit sb-key-input sb-key-save sb-key-cancel sb-key-error sb-key-saved sb-key-mask sb-key-edit-btn sb-key-clear sb-result sb-result-body sb-result-close sb-form (data-max-wallets) sb-site sb-site-error sb-wallet-rows sb-add-wallet sb-cap sb-submit sb-submit-hint sb-wallet-template` |

Frame template `#frame-tpl` classes used by `buildFrame`: `.shot .shot__img .frame__no .frame__domain
.dns-status .domain-age .report-status .frame__analyze .frame__scambusters .frame__sb-check
.frame__sb-report .frame__sb-instant .fact--ip|status|tls|time dd`.

State classes toggled by JS: `.is-hidden`, `.is-blank`, `.is-minimal`, `.is-set`, `.is-on`,
`.is-active`, `.is-collapsed`, `.is-failed`, `.is-done`, `.is-busy`, `.has-error`,
`.flag--ok|warn|bad`, `.dns-status--live|dead`, `.report-status--reported|unreported`,
`.frame__sb-check--ok|warn|bad`, `.frame__sb-instant--sent`, `.alert--<tone>`, `.sb-result--<tone>`,
`.sb-status--<tone>|busy`.

## CSS ownership

| File | Owns | Tokens |
|---|---|---|
| `static/css/styles.css` (loads first) | Global reset incl. `[hidden] { display: none !important; }`, header, key panel, `.console` controls, query autocomplete `.qac*` and `.pro-badge`, `.btn*`, `.field`, status/alert/loading, empty state, the `.sheet` and `.frame`s, pagination, lightbox, responsive breakpoints (1320, 1060, 760, 430 px) | `--mount* --paper* --ink* --annot* --cyan --alert --warn --ok --pro --pro-ink --sans --mono --gutter --frame-radius` |
| `static/css/analyzer.css` | `.analyzer` overlay (also used by `#pivots-view`), `.acard` cards, summary, `.stat`s, `.chip--*`, `.pill--*`, hash badges, `.copy`, `.atable`, engines, `.hero`/`.gauge`/bars, keyword matches, `.panel` slide-over (shared with the reporter), `.toast`, `.sr-only`; breakpoints 900, 620 px | `--a-clean --a-low --a-suspicious --a-malicious --a-sev-1..5 --a-surface* --a-line*` |
| `static/css/scambusters.css` | `.sheet-head__tools`, `.sb-open`, `.sb` panel, key section, `.sb-wallet` rows, submit/results, analyzer `.sb-status` strip; breakpoint 560 px | uses the other two files' tokens |

Single dark theme; there is no light/dark switch or `prefers-color-scheme` rule.

Stacking (`z-index`): `.console` 20 (sticky), `.export-menu` 30, `.qac` 40, `.analyzer` 60,
`.lightbox` 60, `.panel` 70, `.sb` 75, `.toast` 90.

Category pills with their own colour: `.pill--first_party`, `--ads`, `--tracker`, `--crypto`,
`--unknown`. Other categories render with the base `.pill` style.

CSS is being edited by others; check selectors and line positions in the file before relying on
this table for a specific rule.
