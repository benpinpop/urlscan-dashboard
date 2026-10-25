# TitanEye (link-analysis graph)

Maltego-style graph workspace: nodes are entities, edges are shared indicators, and a node is
expanded by running a urlscan query built from it. Opened from the **TitanEye graph** button in the
header. The full build plan is in `GRAPH_PLATFORM_PROMPT.md`; this file is the contract every phase
shares. Trust the code over this file if they disagree.

## Phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Schema, `graph_builder.py`, `/api/graph/*`, viewer, detail panel, expand | done |
| 2 | Dataset import (column mapper, wallets, provenance layers) | done |
| Find | Ctrl+F find-in-graph (added between phases 2 and 3) | done |
| 3 | Wallet basic info (Etherscan, Blockchain.com, Tronscan; keys in memory only) | done |
| 4 | Scale view, clustering, noise filter, timeline, crawler, cases and exports | done |
| 6 | Pull a full scan and map its indicators (`/api/graph/site`, `titaneye-scan.js`) | built, awaiting review |
| 7 | Pivot by indicator | not started |

## Node and edge contract

Node id is `type:value`, built by `graph_builder.node_id`. Values are canonical (lowercase hosts with a leading `www.` removed,
compressed IPs, `AS` prefix, lowercase SHA-256, checksummed wallets). Edge id is
`source|relation|target`, so the same fact from two queries merges instead of duplicating.

```
node  {id, type, label, attrs}
edge  {id, source, target, type, attrs{source, first_seen, last_seen}}
```

`attrs.source` on an edge is its provenance (`urlscan:<query>`; later `file:<name>`). Types:
`graph_builder.NODE_TYPES` and `EDGE_TYPES`; colours and labels live in `titaneye.js:TYPES`.
Search hits only expose apex, IP, ASN, PTR, TLS issuer and server, so only those become
infrastructure nodes in phase 1. `tls_cert` is keyed by issuer name until the full-result path
(`/api/graph/site`, phase 2/3) can supply a real certificate identity. Hash, filename, text,
third-party, brand, contact, tag and wallet nodes appear when you expand a seed of that type;
the seed is linked to every site returned (always `site -> seed`).

## Backend

| Route | Notes |
|---|---|
| `GET /api/graph/transforms` | Catalog: `id, label, node_type, field, plan, template`; `max_expand` |
| `POST /api/graph/ingest` | Body `{sites: [str], wallets: [{address, chain}]}`, each list at most 200. Needs no urlscan key and has its own limiter (`ingest_limiter`, 3000/min). Returns `sites[]` (`{host, apex}` or `{error}`) and `wallets[]` (`{valid, chain, canonical}` or `{valid: false, error}`), aligned with the input by index |
| `POST /api/graph/expand` | Body `{transform, value, size, search_after}`. `transform: "query"` is a free-form urlscan query with no seed node. Returns `nodes`, `edges`, `meta{query, transform, seed, count, total, total_is_exact, has_more, next_cursor}` |

Order of checks: rate limiter, JSON body, `build_query` (value checked against its node type; the
query comes from the fixed `TRANSFORMS` table, never from a client field name), query length,
`size` (in `ALLOWED_SIZES` and <= `GRAPH_MAX_EXPAND` = 10000), cursor shape, key, upstream.
Errors use `fail()`: `invalid_body`, `invalid_graph_value`, `invalid_size`, `invalid_cursor`,
`query_too_long`, plus the usual urlscan codes. `tests/test_graph.py` checks every transform
`field` exists in `database/query_terms.csv` and that injection attempts are rejected.

Pro-only fields are marked `plan: "pro"`; the server does not know the account plan, so a free key
gets urlscan's own error back.

## Frontend

`static/js/titaneye.js` (`window.TitanEye`, ES5, one IIFE), `static/css/titaneye.css`, shell markup
`#titaneye` in `templates/index.html`, wired in `app.js` (`getKey`, `onSearch`, `onAnalyze`).

- Rendering: sigma.js 2.4.0 (WebGL) over graphology 0.25.4, vendored in `static/vendor/` because the
  CSP allows only same-origin scripts.
- Layout: ForceAtlas2 in a Web Worker (`static/vendor/forceatlas2.worker.js`), flat matrices in,
  positions out every 10 iterations. Any graph change restarts it from current positions. Node size
  scales down with graph size.
- The selected node's lines are drawn on a transparent 2D canvas above the WebGL layers, over every node except the selected one
  (`drawSelectionEdges`, after every sigma render) because sigma always draws edges under nodes; the
  normal edge pass hides those edges so they are not drawn twice.
- Selection dims everything except the node and its neighbours; the legend doubles as a type filter.
- Node detail: value with copy button, connection counts, scan attrs, screenshot (only from
  `https://urlscan.io/`), per-type transforms with the exact query shown, "Open scan in analyzer",
  "Search this domain in the grid", hide, remove.
- All text is set with `textContent`; scanned URLs are text plus copy, never links.

## Dataset import (phase 2)

`static/js/titaneye-import.js` (`window.TitanEyeImport`), the `#te-import` dialog in `index.html`,
and `graph_builder.ingest` / `normalise_site` / `normalise_wallet` / `chain_from_label`.

- Files are read in the browser (25 MB, 200,000 rows). CSV/TSV/`;`/`|` (delimiter picked from the
  first lines), TXT lists, JSON arrays or `{key: [...]}`, and JSONL.
- Split URLs: a cell `https` followed by a cell starting `//` is rejoined to `https://...`, because
  some exports split at the colon.
- Column mapper: header aliases first (`site_url_original`, `site_key`, `wallet_address`,
  `wallet_chain`, ...), then a vote over the first 50 values. Roles: site URL, apex domain, IP, ASN,
  wallet address, wallet chain, SHA-256, tag, Telegram handle. Mappings are saved in `localStorage`
  per header signature (`titaneye.mapper:<headers>`); no keys or data are stored.
- Check step: unique sites and wallets go to `/api/graph/ingest` in batches of 150 (the body limit
  is 64 KB). Wallet chain labels such as `Tether (USDT) - Arbitrum One (arb)` resolve to the code in
  the last parentheses; a wrong label falls back to address detection. EVM wallets are keyed by the
  EIP-55 checksummed address, so the same wallet on several chains is one node with `chains`.
- Row semantics: a row with a site links the site to everything else on it (`same_apex`,
  `resolves_to`, `hosted_on`, `serves_file`, `links_to_contact`, `tagged`, and `uploaded_link` to
  wallets). A row without a site links its entities to each other with `uploaded_link`. A mapped
  apex column overrides the server's guess (the built-in suffix list is short).
- Bad values are dropped and listed (first 25) while the valid values on that row still import.
- Provenance: nodes carry `layers: ["file:<name>"]`, edges carry `source: "file:<name>"` and
  `row`. The layer buttons at the top left of the graph hide everything that came only from one
  source; nodes from several sources stay visible while any source is on. Expansions are the
  `urlscan` layer.
- Fixtures: `tests/fixtures/titaneye_wallets.csv` and `titaneye_sites_split.csv`, shaped like the
  real exports (the last wallet row has a deliberate checksum error).

## Find on the graph

Ctrl+F (Cmd+F on Mac) while the graph is open, or the **Find** button, opens a search box at the top
right of the canvas; the browser's own find is suppressed only while TitanEye is on screen and the
import dialog is closed. Implemented in `titaneye.js` (`runFind`, `stepFind`, `reduceNode`).

- Case-insensitive substring match over each node's value, id, type name and every scalar or list
  attribute (scan IDs, country, wallet chains, scanned URL, dates). Hidden nodes are skipped.
- `type:ip 203.0` limits the search to one node type (type id or label, e.g. `type:apex_domain`,
  `type:wallet`); `type:wallet` alone lists every wallet.
- Matches keep their colour and label and grow; everything else dims (this takes priority over the
  selection's neighbour dimming). Enter / Shift+Enter or the arrow buttons step through matches and
  centre the camera; clicking a result in the list selects the node and opens its detail panel.
- Matches are ordered by connection count, the list shows the first 40, and the search re-runs
  when the graph, a type filter, a layer or a hidden node changes.
- Esc closes the find box first; a second Esc leaves the graph.

## Wallet intel (phase 3)

`chain_providers/` (`etherscan.py`, `blockchain.py`, `tronscan.py`), `/api/chain/*` in `app.py`,
`static/js/titaneye-wallet.js`. Basic information only; the provider interface (`summary`,
`capabilities`) leaves room for deeper analysis later.

| Provider | Chains | Key | Notes (checked live 2026-10-22) |
|---|---|---|---|
| Etherscan API V2 | eth, bsc, matic, arb, avax, op | required, header `X-Etherscan-Key` | A free key covered Ethereum, Arbitrum and Polygon; BNB Chain, Avalanche and Optimism returned `provider_plan_unsupported`. About 7 calls per lookup, spaced 0.36 s apart for the 3 calls/s free limit |
| Blockchain.com (`rawaddr`) | btc | optional, header `X-Blockchain-Key` (sent as `api_code`) | Works without a key. First-seen needs a second call at `offset=n_tx-1`; on very busy addresses that call can fail and first-seen is blank |
| Tronscan (`accountv2`) | trx | required, header `X-Tronscan-Key` (sent as `TRON-PRO-API-KEY`) | Answers 401 without a key. Returns TRX and TRC-20 balances, transaction counts, created/last activity and risk tags |

- Shown in the wallet node's detail panel, one block per chain the wallet was seen on (a Look up /
  Refresh button each): address type, balance, totals and counts where the provider has them,
  first/last seen, contract name and verified flag (EVM), token balances (Tron) or tokens seen in
  recent transfers (EVM), risk tags (Tron), explorer URL as text with a copy button, and the source with
  how old the data is. EVM does not expose total received/sent or a total transaction count cheaply, so
  it shows the sent-transaction count (account nonce) instead.
- Results are stored on the node as `data.onchain[chain] = {summary, cached_at}` and appear in the
  case file and nodes CSV with their provider and query time.
- **Keys (client-side, not saved).** The **Keys** button opens a panel with masked inputs. A saved key
  lives only in a variable in `titaneye-wallet.js`; the inputs are emptied on save, nothing is written to
  `localStorage`, `sessionStorage`, IndexedDB, cookies, case files or exports, and a reload forgets
  them. Each lookup sends the key as a header; the server uses it for that request only. There are no
  key settings on the server. The log scrubber (`app.py:ScrubSecrets`) also redacts `apikey=` and
  `api_code=`. Provider exceptions are never echoed because `requests` embeds the request URL (and so
  the Etherscan key) in their text.
- Server: `chain_limiter` (20 per minute per client, `CHAIN_RATE_LIMIT_PER_MINUTE`), a 5-minute cache
  keyed by `(provider, chain, address)` that never contains a key (`CHAIN_CACHE_TTL`,
  `CHAIN_CACHE_MAX_ENTRIES`), `ETHERSCAN_BASE_URL`, `BLOCKCHAIN_BASE_URL`, `TRONSCAN_BASE_URL`,
  `CHAIN_TIMEOUT`. Error codes: `provider_key_missing`, `provider_key_invalid`,
  `provider_unsupported_chain`, `provider_plan_unsupported`, `provider_rate_limited` (with
  `retry_after`), `provider_timeout`, `provider_error`, plus `invalid_wallet`, `unsupported_chain`.
- Limitation: the Etherscan and Blockchain.com documentation pages could only be read in part, so the
  request shapes follow the long-standing v2 / `rawaddr` behaviour and were confirmed with live calls for
  Etherscan (eth, arb, matic, plan errors), Tronscan, and Blockchain.com. Run a lookup per provider after
  any API change.
- Tests: `tests/test_chain.py` (fake sessions, dummy keys) covers parsing, error mapping, key redaction
  in messages and logs, key shape checks, the cache and the rate limit.

## Scale view, filters and clusters (phase 4)

`static/js/titaneye-scale.js`. The right-hand panel (`#te-side`) is hidden until the graph has at least
one node (the canvas uses the full width until then), and clearing the graph hides it again. Once shown it
fills with the scale view whenever no node is selected;
selecting a node (click, Find result, cluster or ranking jump) swaps it for that node's details, and
clicking empty canvas or **&larr; Scale view** in the detail panel swaps it back (`core.onSelect`). It
refreshes on return, so changes made while a node was selected are caught up. Hovering does not swap it.

- Overview: sites, IPs, apex domains, ASNs, countries, wallets, median domain age and a scans-over-time
  histogram.
- Filters (applied to the graph through `TitanEye.core`): the **noise filter** hides IPs, ASNs, TLS
  issuers, technologies, third parties, reverse-DNS names and ranges shared by more than N sites; the
  **timeline** (two sliders plus Play growth) shows only sites scanned in the range, and their
  infrastructure disappears with them. Imported sites with no scan time always show. A node's
  visibility combines type filter, dataset layer, time range, noise filter and a manual hide
  (`refreshVisibility`).
- Hosting concentration: ASN blocks sized by sites with their busiest IPs inside; click to select.
- Rankings: top 25 nodes of a chosen type by linked sites (IPs, apex domains, ASNs, wallets, TLS
  issuers, hashes, third parties, filenames, text, tags, contacts, technologies, reverse DNS).
- Clusters: sites joined through the indicator types you tick (wallet, hash, contact, filename, text,
  IP, apex domain and tag are on by default), ignoring indicators shared by more than a cap. A cluster
  needs **at least three sites** (`MIN_CLUSTER_SITES`). Clusters are ranked by indicator strength (wallet 5, hash and contact 4, filename and text 3, IP 2, ...)
  times how many sites share it; each lists its strongest evidence and can be highlighted on the graph.

## Crawler (phase 4)

`static/js/titaneye-crawl.js`, a collapsible **Crawl outward from this node** section in the selected
node's detail panel. Select a node, set depth (1-3),
request and node caps, the delay between requests (default 2 s, which fits the default 30 per minute
limit), a skip threshold for indicators shared by many sites, the indicator types to follow (IP, apex
domain, hash and filename by default) and whether to include Pro transforms. It runs one expansion at
a time through `/api/graph/expand`, queues newly found indicators up to the depth, shows progress,
can be cancelled, stops on a rate limit and **Resume** continues from the queue. A site is crawled
through the indicators around it.

## Cases and exports (phase 4)

`static/js/titaneye-cases.js`, opened from **Cases & export**.

- Cases: the graph, positions, which datasets are on, hidden nodes and type filters. Saved in this
  browser's IndexedDB (database `titaneye`, stores `cases` and `graphs`), or downloaded and loaded as a
  JSON file (`{app: "TitanEye", schema_version: 1, name, saved_at, graph}`). A case never contains an
  API key because keys are not part of the graph.
- Exports: nodes CSV, edges CSV (with provenance), an indicator list (domains, IPs, ranges, SHA-256,
  wallets with chain, Telegram handles) and GraphML for Gephi or Maltego. An option limits the export to the
  nodes currently shown. CSV cells starting with `=`, `+`, `-`, `@`, tab or CR get a leading quote, and
  the file starts with a UTF-8 BOM so Excel reads it correctly.
- Scambusters: a site node gets **Report site and N wallets**, which opens the existing reporter with the
  site and up to 30 linked wallets filled in (`ScambustersReporter.open({siteUrl, wallets})`); you
  review and submit it as usual.

## Scan details (phase 6)

`POST /api/graph/site` with `{scan_id}` (UUID, validated before it goes upstream) fetches the full
urlscan result through `fetch_result` (so the 5-minute result cache applies) and
`graph_builder.shape_scan` turns it into the usual `{nodes, edges}` plus `meta{scan_id, site,
categories, skipped, cached}`. Every node and edge has a `category`: `core` (site, apex, page IP, ASN,
reverse DNS; always added) or one of `hashes, filenames, domains, ips, cert, tech, contacts, wallets,
brands, tags, redirects`. Errors: the usual urlscan codes (a scan still processing is `not_found`, 404),
`invalid_uuid`, `invalid_body`, `scan_unusable` (422, no usable website address).

| Category | From the result | Edge from the site |
|---|---|---|
| hashes | `data.requests[].response.hash` (SHA-256 only, empty bodies skipped, biggest first) and `meta.processors.download` files (first, with their filename) | `serves_file` |
| filenames | last path segment of each request URL, minus a short generic list (`GENERIC_FILENAMES`) and hash-looking names; download file names | `serves_file` |
| domains | `lists.domains` outside the page's apex | `loads_third_party` |
| ips | `stats.domainStats[].ips` of those domains (not the page IP) | `third_party -> ip` `resolves_to` |
| cert | `page.tlsIssuer`; subjects from `lists.certificates` ride on the node as `subjects` | `uses_cert` |
| tech | `page.server` and `meta.processors.wappa` | `uses_tech` |
| contacts | `t.me` / `telegram.me` links | `links_to_contact` |
| wallets | wallet-shaped strings in link hrefs and text, checksum-validated | `contains_text` |
| brands, tags | verdict brands; task and verdict tags | `impersonates`, `tagged` |
| redirects | 3xx `Location` hops, host to host | `redirects_to` (with `hop`) |

Caps: 100 each of hashes, filenames, domains and IPs, 20 tags, 10 redirects; anything dropped is counted
in `meta.skipped`. The certificate stays keyed by issuer so it merges with search hits; the result has
no fingerprint or serial, so a real certificate identity is not possible from it.

Frontend (`static/js/titaneye-scan.js`, `window.TitanEyeScan`): a **Scan details** section on every
site node (newest scan by default, a picker when several are known, a scan-ID box when none is) with
**Pull scan and map details**. The pull shows a checklist with counts and how many are new; nothing but
the core nodes goes on the graph until **Add selected to graph** (confirm above 300 nodes). Ticks are
remembered per category in `localStorage` (hashes, filenames, domains, IPs, certificate, contacts,
wallets, brands and tags on; technologies and redirects off). **Add scan to TitanEye** buttons on each
results-grid frame and in the analyzer header call `TitanEyeScan.addScan(uuid)`: open the graph, add
the site with its core nodes, select it, and leave the checklist open.

**Only add lines to nodes already on the graph** (checkbox above the list, remembered): nothing new is created;
a node is kept only if it is already on the graph and an edge only if both ends are, so the scan links the
site to indicators you already have. The category counts then show how many are already present.

Not covered: wallets in page text (the DOM is a separate fetch, and the result document has no page
text), certificate fingerprints, and looking a scan up from a bare domain.

## Undo

`titaneye.js` (`pushUndo`, `undo`). Backspace or Delete removes the selected node (`removeNode`, undoable). The **Undo** button (top right) and Ctrl+Z reverse, newest first, up to 50
changes to the graph's contents: an add (`merge` journals the node and edge ids it created and the
previous attributes of nodes it merged into), **Remove from graph**, **Hide node**, and **Clear**
(restored from `graph.export()`). Not undoable: filters, layout moves, case loads (a case load empties the
history), and attribute changes to edges that already existed. The shortcuts are active only while the
graph is on screen and neither the analyzer nor a dialog is open; in a text box Ctrl+Z is the browser's.

## Declutter and tidy layout

Controls in the graph's top bar; code in `titaneye.js` (`refreshVisibility`, `runLayout`) and
`titaneye-layout.js`.

**Declutter** (button plus a number box, default 2): hides **sites with fewer than N connections**.

- A connection is a distinct neighbour that is still visible after every other filter (type, dataset,
  time range, noise, manual hide), so the filters compose in any order. Parallel edges count once.
- Anything left with no visible neighbour because of it goes too, for example a hidden site's own apex
  domain; otherwise the loose domain dots stay behind and nothing is decluttered. A node that still
  touches something else stays (an IP that links to an ASN keeps showing). There is no separate
  "orphaned IP" filter.
- The selected node and the nodes of an active search are never hidden. The button shows how many nodes
  are hidden ("Declutter: 2400 hidden"). Turning it off restores everything.
- A site imported with only a site column has one connection (its domain), so it is hidden at N = 2.
- The setting is saved in cases (`snapshot.declutter`); older case files load with it off. Turning it
  off lays out any node that was added while it was hidden.
- Cost: the visibility pass took 64-127 ms at 16,940 nodes / 48,000 edges.

**Tidy** (preset list plus a button) re-lays out the nodes that are showing; hidden nodes keep their
positions.

- *Organic*: ForceAtlas2 in the worker (LinLog mode, scaling 20, gravity 0.05; LinLog was the single
  biggest improvement), then leaves of a hub (6 or more, one connection each) are fanned out on a ring
  around it, then relaxing overlapping dots and packing disconnected pieces into shelves alternate at the
  current view scale (dots are a fixed size on screen, so spreading the layout makes dots inside each
  piece look more crowded; 5 rounds under 3,000 nodes, 3 under 8,000, 2 above, yielding to the page
  between rounds). Largest piece top-left.
- *Rings by kind*: evidence (wallets, hashes, contacts, filenames, text, tags) in the centre, then
  hosting (ASN, IP, reverse DNS, TLS issuer, technology, third party), then apex domains, then sites on
  the outside, ordered by where their neighbours sit.
- *Hierarchy*: rows ASN, IP, site, apex domain, everything else; wide rows wrap; ordered with a
  barycentre sweep. Reads best below a few thousand nodes.
- **Expanding no longer rearranges the graph.** Only nodes that have never been laid out move
  (`placed` flag); existing nodes are held in place by the layout's `fixed` flag. Tidy moves everything.

**Labels, edges and hover.** Label settings follow the node count (`applyLabelSettings`: at most one
label per grid cell, bigger nodes first, fewer labels as the graph grows). Edges are fainter and the
**Edges** list picks auto, all, selection only or none; auto switches to selection only above 1,500
nodes. Hovering a node shows its full value and connection count.

Measured with headless Chrome (software GL) on generated data, overlapping dot pairs at the fitted view:

| Graph | Plain force layout (before) | Tidy organic | Notes |
|---|---|---|---|
| 5,090 nodes (60 clusters, 1,200 one-link sites, 400 two-link sites) | 4,753 | 53 to 0 | worker 7-10 s, post-process 0.6-1.1 s |
| same, Declutter on (2,690 showing) | | 0 | 2,400 hidden |
| 16,940 nodes / 48,000 edges | 27,014 | 19,494 | post-process 1.8 s, in yielding rounds; some overlap is unavoidable at this density, so use Declutter, the noise filter, Edges: selection only, or zoom |

Rings: 88 and hierarchy: 52 overlapping pairs at 5,090 nodes; 16,553 and 68,080 at 16,940.

## Vendored files

`static/vendor/` holds built copies, so rebuilds are manual:

| File | Source |
|---|---|
| `graphology.umd.min.js` | npm `graphology@0.25.4`, `dist/graphology.umd.min.js` (global `graphology`) |
| `sigma.min.js` | npm `sigma@2.4.0`, `build/sigma.min.js` (global `Sigma`) |
| `forceatlas2.min.js` | npm `graphology-layout-forceatlas2@0.10.1`, bundled with esbuild (`--format=iife --global-name=ForceAtlas2`); only `inferSettings` is used on the main thread |
| `forceatlas2.worker.js` | same package, esbuild bundle of a ~20 line worker that calls `iterate` (matrix in, matrix out) |

Licences sit next to them (`LICENSE.*.txt`). Sourcemap comments were stripped.

## Measured (headless Chrome, software GL, stub data)

16,940 nodes / 48,000 edges: merge 200-300 ms per 1,000-site expansion, layout about 20 s in the
worker, page stays at about 56 fps while it runs. 50,000 nodes has not been measured.

## Known gaps

- Node shape is not yet a second encoding beside colour, and there is no table alternative to the
  canvas.
- No value autocomplete in the toolbar box.
- Not built from the original plan: collapsing a group into one badge node, lasso select, merging
  nodes, analyst-drawn edges, undo/redo, PNG/SVG export, and an `/api/graph/site` call that expands a
  site into its certificate, hashes and wallets from the full scan.
- Deeper wallet analysis (counterparties, fund tracing, pattern flags) was deferred by request.
- Shared CDN infrastructure is only handled by the noise filter and the crawler's skip threshold; there is
  no category-based filter from `domain_categories.csv`.
- No unit tests for the browser code (import parser, find, clusters, crawler, cases). It was checked in
  headless Chrome against the fixtures and a stub server; `tests/test_graph.py` and `tests/test_chain.py`
  cover the Python side.
- Measured only up to 16,940 nodes / 48,000 edges (phase 1); 50,000 nodes is untested.
