# Prompt: Link-Analysis Graph Platform (Maltego-style) for URLScan Visualizer

Paste everything below the line into a fresh Claude Code session at the repo root.
Before starting, the agent must load the `urlscan-visualizer` skill and `docs/CONVENTIONS.md`.

---

## Role and goal

You are extending the URLScan Visualizer (Flask + vanilla JS over urlscan.io) with a **link-analysis
graph workspace** for ScamBusters investigators. It works like Maltego: entities are nodes, shared
indicators are edges, and every node can be expanded with a "transform" that runs a urlscan query
and merges the results into the graph. It must also work as a **scale view** that maps whole scam
infrastructure (crypto investment scams in particular) and shows how many sites share an IP, a
domain, a certificate, a template, or a wallet.

Build it as a new full-screen tab/overlay next to the existing grid and analyzer. Reuse existing
routes, the result cache, key handling, rate limiter and validators. Do not weaken any hard
constraint in the skill file.

**When finished, stop and wait for my review. Do not commit, push, or deploy.**

## Hard constraints (from this repo, non-negotiable)

1. No `innerHTML` / `outerHTML` / `insertAdjacentHTML` / `eval`. Build DOM with `createElement` +
   `textContent`. All scan data, CSV rows and uploaded files are hostile (formula-injection
   prefixes `= + - @ \t \r` must never reach an export or a Scambusters payload unescaped).
2. Strict CSP: no inline script, no `on*=`, no `style="..."` in markup. `connect-src 'self'` only,
   so every external call goes through a new Flask route.
3. Project JS: one IIFE per file, `"use strict"`, ES5 only (`var`, `function`, no arrows/let/const/
   classes/async). Storage access wrapped in try/catch.
4. API keys never logged, echoed, or put in URLs. urlscan key travels as `X-URLScan-Key`.
5. Validate on the server before any upstream call; browser validation is convenience only.
6. Scanned and resource URLs render as text with a copy button, never as clickable links.
7. New routes: `enforce_rate_limit()` -> validate -> `resolve_api_key()` -> client -> `fail(...)`.
   Add tests (stdlib `unittest`, no network, stub `application.client`). Add new frontend files to
   `REQUIRED_ASSETS`.
8. Graph library: vendor it into `static/vendor/` (CSP forbids CDNs). Recommend **graphology +
   sigma.js (WebGL)** for 10k-100k nodes. Layout via `graphology-layout-forceatlas2` in a Web Worker
   if CSP `worker-src 'self'` allows it; otherwise run chunked layout on the main thread. Justify
   the choice in the PR notes. The ES5 rule applies to our code, not the vendored bundle.
9. Update `docs/` (FRONTEND, BACKEND, DATA, ARCHITECTURE) and `CHANGELOG.md`. Trust code over the
   drifted README.

## Entity model (node types)

| Type | Source field(s) in urlscan | Notes |
|---|---|---|
| `site` | `page.url`, `task.uuid`, `page.domain` | One node per scanned hostname; keep latest scan UUID plus all scan UUIDs as attributes |
| `apex_domain` | `page.apexDomain`, `task.apexDomain` | Group node for sibling subdomains |
| `ip` | `page.ip`, `ip` (contacted) | Count of sites on it is the key scale metric |
| `cidr` | derived /24 from `page.ip` | Optional rollup for hosting clusters |
| `asn` | `page.asn`, `page.asnname.keyword` | Hosting provider cluster |
| `ptr` | `page.ptr` | Reverse DNS |
| `tls_cert` | `page.tlsIssuer`, TLS subject/validFrom from result JSON | Shared cert = strong link |
| `file_hash` | `hash`, `files.sha256`, `dom.hash`, `text.hash` | Identical page builds / assets |
| `filename` | `filename`, `filename.keyword` | Shared template asset paths (the existing examples are mostly this) |
| `text_string` | `text.content`, `page.title`, `content.identifiers` | Common marketing copy, GA/analytics IDs |
| `third_party` | `domain`, `frames.domains`, `links.domains`, `websockets.domains` | Chat widgets, chart widgets (smartsuppchat, tidio, tradingview, coingecko) |
| `tech` | `content.technologies`, `page.server`, `server` | Stack fingerprint |
| `brand` | `brand.name`, `visible.brandname` | Impersonated brand (pro) |
| `contact` | `links.domains`/`links.urls` (t.me, wa.me), `clipboard.text` | Telegram / WhatsApp / email handles |
| `wallet` | Extracted from page text/DOM, uploads | Chain-tagged via `wallet_validation.detect_chain` |
| `tag` | `task.tags`, `labels`, `task.source` | Campaign tags |
| `case` | user-defined | Analyst grouping container |

Edge types: `hosted_on`, `resolves_to`, `same_apex`, `uses_cert`, `serves_file`, `contains_text`,
`loads_third_party`, `uses_tech`, `impersonates`, `links_to_contact`, `pays_to`, `tagged`,
`redirects_to`, `uploaded_link` (from datasets), `analyst_link` (manual). Every edge stores
`source` (urlscan query / upload filename / manual), `first_seen`, `last_seen`, `weight`.

## Features

### 1. Transforms (expand a node)
Right-click or detail-panel button on a node runs a transform: build a urlscan query from the
node, call a new `/api/graph/expand` route, merge results. Examples:
- `ip` -> `page.ip:<ip>` (all sites on that IP), also `ip:<ip>` (contacted)
- `apex_domain` -> `page.apexDomain:<d>`
- `file_hash` -> `hash:<sha256>` / `dom.hash:` / `text.hash:`
- `filename` -> `filename:"<path>"`
- `text_string` -> `text.content:"<phrase>"` (pro) with a note on the 20 kB truncation
- `tls_cert` -> `page.tlsIssuer` plus `page.tlsValidFrom` window
- `asn` -> `page.asn:<AS>`, optionally combined with `page.domainAgeDays:<30`
- `third_party` -> `domain:<d>`; offer "AND" pairing with a second third_party (pattern used in
  `examples.js`)
- `contact` -> `links.urls:/https:\/\/t\.me\/<handle>.*/`
- `wallet` -> `text.content:"<address>"`
- `site` -> fetch `/api/result/<uuid>` and expand into IP, cert, hashes, third parties, tech,
  wallets found in text/DOM, brand, redirects

Drive the transform menu from `database/query_terms.csv` (field, type, plan). Gray out pro-only
transforms when the plan is free. Show the exact query before running with an "edit query" option,
plus an ad-hoc "Search to graph" box that accepts any urlscan query (reuse `autocomplete.js`).

Safeguards: per-expansion cap (default 250 results, max `ALLOWED_SIZES`), cursor pagination via the
existing `search_after`, a request budget counter tied to `/api/quotas`, and a visible "N more
results not loaded, load more" stub node. Never run unbounded expansions automatically.

### 2. Grouping and clustering
- Group-by toggles: IP, /24, apex domain, ASN, cert, file hash, filename, third party, tag, wallet,
  text string. Group nodes become hubs with a member count badge; collapse/expand a group.
- "Cluster by shared indicator" runs connected-components or Louvain on the current graph, colors
  clusters, and lists them in a sidebar sorted by size and indicator strength (hash/cert/wallet
  weigh more than generic third parties).
- Down-weight or hide ubiquitous nodes (Cloudflare IPs, Google Fonts, jQuery CDN) using
  `database/domain_categories.csv` categories and a "noise threshold" slider (e.g. hide indicators
  shared by >N unrelated apexes).
- Pin, lock, hide, delete, merge nodes. Analyst-drawn edges. Undo/redo.

### 3. Infrastructure scale view
A dedicated mode to answer "how big is this operation?":
- Treemap / sunburst or bubble-pack: ASN -> IP -> sites, bubble size = site count, color = risk
  or domain age bucket.
- Ranked tables: top IPs by hosted sites, top apex domains by subdomain count, top certs, top
  shared hashes, top third parties. Each row click focuses/selects it in the graph.
- Headline stats: total sites, unique IPs, unique apexes, ASNs, countries, wallets, median domain
  age, scans per day timeline (histogram from scan `time`).
- Timeline scrubber that filters the graph by `first_seen`/`last_seen` to show infrastructure
  growth and IP rotation (animate playback).
- "Map the whole infrastructure" crawler: from a seed node, run bounded breadth-first expansion
  (depth <= 3, per-node and global caps, user-visible progress and cancel, respects the rate
  limiter and `Retry-After`). Persist partial progress so a rate-limit stop is resumable.
- Level-of-detail rendering: aggregate to group nodes when zoomed out, reveal members when zoomed
  in; labels only above a zoom threshold; target 60 fps at 50k nodes / 150k edges.

### 4. Node detail panel
Clicking any node opens a side panel (built with `createElement`, uses existing `.panel` CSS):
- Identity: type, value (copy button), first/last seen, degree, cluster, source of each edge.
- Per-type details:
  - `site`: latest scan screenshot, threat score and band (from `shape_verdicts`), domain age,
    TLS, brand, keyword-risk score from `analyzer.js:scoreClientText`, **link to the urlscan report
    shown as text + copy** (never `<a>`), "Open in analyzer" (existing `URLScanAnalyzer`), "Open in
    search grid" (existing pivot), "Check / Report to Scambusters" (existing reporter).
  - `ip`: list of sites on it, PTR, ASN, country, count of sites seen, reverse-DNS, DoH live
    lookup (reuse `dnsLookup`).
  - `wallet`: chain, canonical form, validation result, sites referencing it, and on-chain basic
    info from Etherscan / Blockchain.com when a key is entered (see Wallets section).
  - others: member list, strength of indicator, the exact query that produced it.
- Actions: expand, group-by, hide, add to case, add note/tag, copy as IOC, "show shortest path to...".

### 5. Dataset upload and ingestion
Add an Import dialog (drag-drop + file picker, parsed in the browser with a Web Worker or chunked
reader; nothing is uploaded unless the analyst chooses to enrich).
- Formats: CSV, TSV, JSON, JSONL, TXT (one indicator per line), and urlscan search-export JSON.
  Max size configurable (default 25 MB, 200k rows).
- **Column mapper**: auto-detect and let the analyst override column -> entity type
  (`site_url`, `domain`, `ip`, `wallet_address` + `chain`, `asn`, `hash`, `tag`, `email`,
  `telegram`, `date`, `note`, `case_id`). Save mapper presets in localStorage.
- Auto-detection: URLs/domains via `registrable_domain` logic mirrored in JS or a server helper
  (`domain_intel.py`), IPv4/IPv6 and CIDR, hex hashes by length, wallets via a new batch endpoint
  that calls `wallet_validation.detect_chain/validate_wallet` (cap at a few thousand per call,
  keep `MAX_CONTENT_LENGTH` in mind or raise it only on this route with justification).
- Row semantics: each row creates entities for every mapped column and `uploaded_link` edges
  between them (e.g. a row with site + wallet + Telegram handle links all three). Support
  "edge-list" mode (source, target, relation) as well.
- Dedup/normalize: lowercase hosts, strip `www.`, canonical wallet form, defang `hxxp`/`[.]`,
  trim, reject control characters. Show an import preview with counts, rejected rows and reasons
  before committing.
- Provenance: every imported node/edge carries `source = file:<name>` and row number; layer
  toggle to show/hide each dataset; "diff" view to see what a dataset added to the graph.
- Optional enrichment: "Resolve with urlscan" button queues bounded `/api/search` lookups
  (`page.domain`/`task.apexDomain`) for imported sites to attach IP/ASN/cert/hash, with the same
  budget and cancel controls as the crawler.
- Reuse the existing reported-sites CSV import (`app.js:importReportedSites`, `reportedSiteKey`)
  so already-reported sites render with a "reported" badge.
- I will supply sample datasets (the files referenced earlier). Inspect them, design the default
  mappers around their real columns, and add them as test fixtures with any sensitive values
  replaced. If you cannot find them in the repo, say so and ask before inventing a schema.

### 6. Wallets
- Extract candidate addresses from site text/DOM (`/api/result` text and `/api/dom`) with regexes
  per chain, then validate via `wallet_validation`. Only validated wallets become nodes.
- Wallet clusters: sites sharing a wallet are strongly linked; highlight multi-site wallets as the
  top "operation" signal.
- Wallet-to-wallet edges (`pays_to`) come only from uploads for now (with amount and timestamp
  attributes); on-chain counterparty edges are deferred with the deeper analysis.

#### On-chain providers (basic info only; backend proxy, opt-in, labeled as external data)

Create a `chain_providers/` package with a common interface (`summary(address)`, `capabilities`)
and one module per provider, so more chains and deeper analysis can be added later. Deeper analysis
(counterparty graphs, flow heuristics, multi-hop tracing) is **out of scope for this build**; design
the interface so it can be added without rework, but do not implement it. The browser never calls
providers directly (CSP `connect-src 'self'`); it calls new `/api/chain/*` routes. Verify each
provider's current endpoints, limits and terms in its official docs before coding; do not rely on
memory.

| Provider | Chains | Auth | Notes |
|---|---|---|---|
| **Etherscan** (API V2, single key with a `chainid` param) | `eth`, `bsc`, `matic`, `arb`, `avax`, `op` (the EVM codes in `wallet_validation`) | API key entered by the user | Respect the free-tier rate limit and per-chain availability; surface "chain not supported on this plan" cleanly |
| **Blockchain.com** (blockchain.info explorer API) | `btc` (and `bch` only if the API actually supports it) | Key optional or none; check current terms | Heavily rate limited; queue and back off, cache aggressively |

**Key handling (client-side entry, never persisted):**
- Keys are typed into a "Chain provider keys" panel in the browser. They live **only in a JS
  variable in memory** for the current page session. Do not write them to `localStorage`,
  `sessionStorage`, IndexedDB, cookies, case exports, mapper presets, the URL, or the DOM beyond a
  masked `type="password"` input. A page reload clears them; the UI must say so ("Keys are kept in
  memory only and are cleared when you close or reload this page"). Disable autofill/password
  manager saving on these inputs (`autocomplete="off"`).
- Each request sends the key to our backend as a header (`X-Etherscan-Key`, and
  `X-Blockchain-Key` if the provider uses one). The backend forwards it upstream for that request
  only and never stores it: no env var, no config, no cache entry, no log line, no error message.
  There is no server-side shared key for these providers.
- Etherscan takes the key as an upstream query parameter, so extend the log scrubber to redact
  `apikey=` and never log full upstream URLs. The response cache key must exclude the API key.
- Do not include keys in any telemetry, exported file, or "copy debug info" output.
- Add `ETHERSCAN_BASE_URL`, `BLOCKCHAIN_BASE_URL`, `CHAIN_TIMEOUT` and per-provider rate-limit
  settings to `config.py` and the BACKEND docs (no key settings). Reuse the in-memory limiter (one
  bucket per provider) and a TTL cache keyed by `(provider, chain, address)` with a visible "cached
  N min ago" label.
- Note: the existing urlscan and Scambusters keys keep their current behavior; this requirement
  applies to the new chain provider keys. Make sure case exports and presets exclude **all** keys.

**Basic information (shown in the wallet node's detail panel, fetched on click):**
- Chain, canonical address, validity (from `wallet_validation`), address type (EOA vs contract on
  EVM; legacy / P2SH / bech32 on BTC).
- Balance (native coin, plus top token balances on EVM), total received/sent, transaction count,
  first-seen and last-seen timestamps, and the contract name/verified flag when it is a contract.
- Explorer link shown as text with a copy button (never as an `<a>`).
- A "sites referencing this wallet" list from the graph and a count of linked scam-site nodes.
- Native units only; show fiat only if a price source is configured, labeled as an estimate with a
  date. Never guess a price.

**UI and output:** a "Wallet intel" tab in the detail panel and a ranked table in the Scale view
(top wallets by linked sites). Include on-chain basic info in the case JSON, node/edge CSV and IOC
list, formula-injection safe, with provenance (`provider`, `queried_at`). Add a one-click "Add
wallets to Scambusters report" for site+wallet pairs using the existing reporter (respect
`MAX_WALLETS = 30`).

**Failure handling:** distinguish provider errors from local ones (`provider_rate_limited` with
`retry_after`, `provider_key_missing`, `provider_unsupported_chain`, `provider_error`,
`provider_timeout`), degrade to "validation only" when no key is entered, and never block the rest
of the graph on a provider failure.

### 7. Cases, persistence, export
- Cases: named workspaces saved to localStorage (try/catch, size-aware) with Export/Import as a
  versioned JSON file (`schema_version`, nodes, edges, layers, layout positions, notes, queries
  run). Large graphs: use IndexedDB with chunking.
- Exports: PNG/SVG of the viewport, CSV of nodes and edges (formula-injection safe), IOC list
  (domains, IPs, hashes, wallets), GraphML/GEXF for Gephi/Maltego, and a Scambusters batch of
  site+wallet pairs honoring `MAX_WALLETS = 30` per submission and the existing reporter flow.
- Search within graph, filter by type/cluster/date/risk, bookmark views, keyboard shortcuts,
  accessibility pass (focus order, `aria-label` on controls, a table alternative to the canvas).

### 8. Visual design
- Follow `static/css/styles.css` tokens; add `static/css/graph.css`; support light and dark.
- Distinct shape + color per node type, redundant encoding (not color alone), edge style per type,
  legend that doubles as a type filter. Node size = degree or site count. Risk ring = threat band.
- Layouts: force-directed (default), radial from selected node, hierarchical (ASN -> IP -> site),
  grid-by-cluster. Layout is cancelable and positions are stable across expansions.
- Mini-map, zoom-to-selection, lasso select, multi-select actions.

## Backend work

New module `graph_builder.py` (keep `app.py` thin) and routes:

| Route | Purpose |
|---|---|
| `POST /api/graph/expand` | Body `{type, value, transform, size, search_after}`. Validate type/value shape (IP, CIDR, hash length, domain regex, UUID), build the query server-side from an allow-listed transform table (never accept a raw field name from the client), call `client.search`, return `{nodes, edges, meta{query, count, total, has_more, next_cursor}}` |
| `POST /api/graph/site` | Body `{uuid}`. Reuses `fetch_result` cache, returns the node/edge fragment for one scan including wallets extracted from text |
| `POST /api/graph/ingest` | Optional server-side normalize/validate of an uploaded batch (domains, wallets, hashes) so rules match the backend |
| `POST /api/wallets/check-batch` | Batch variant of `/api/wallets/check` |
| `GET /api/graph/transforms` | The transform catalog (id, label, entity type, field, plan) derived from `query_terms.csv` |
| `GET /api/chain/providers` | Which providers exist per chain, their capabilities and limits (no keys) |
| `POST /api/chain/summary` | Body `{chain, address}`, key in `X-Etherscan-Key` header. Validate with `wallet_validation` first, then call the Etherscan or Blockchain.com provider; returns the basic-info payload. Key is used for that request only |

All use the standard envelope and error codes. Shape the nodes/edges in Python so the browser only
merges. Add node-id canonicalization (`type:value`) in one shared place. Cap response size.

## Testing and verification

- Unit tests for: transform allow-list and query building (injection attempts like quotes,
  `AND`, newlines in node values), node/edge shaping from `tests/fixture_result.json`, ingestion
  normalizer (defanging, formula prefixes, dedup), wallet batch, route validation/errors.
- Provider tests use recorded fixture responses and a stub provider; no network. Cover key
  redaction in logs, unsupported chains, rate-limit and timeout mapping,
  hostile values in contract names/labels, and a test that no log line, error body, cache key or
  response contains the key.
- Run `python -m unittest discover -s tests`; all existing 113 tests must still pass.
- Use `tests/stub_server.py` extended with canned graph data to demo the UI offline. Verify in a
  real browser at 1k, 10k and 50k synthetic nodes; report frame rate and memory.
- Write a manual QA checklist in the docs. Confirm no CSP violations in the console.

## Deliverables

1. Working feature behind a "Graph" entry in the header, with the code organized in the existing
   file-per-feature pattern (`static/js/graph.js`, `graph-import.js`, `graph-scale.js`,
   `graph.css`, `graph_builder.py`).
2. Updated docs and CHANGELOG, plus a short user guide (`docs/GRAPH.md`) with example
   investigations, e.g. start from `domain:"smartsuppchat.com" AND domain:"coingecko.com"`
   and expand outward by IP, hash and filename to map a crypto-investment-scam cluster.
3. A summary listing what was built, what was deliberately deferred, any decision you made without
   me, and risks (API quota usage for urlscan, Etherscan and Blockchain.com, memory at scale,
   privacy of uploaded datasets, key handling for chain providers).

Then **stop and wait for my review**.
