# Prompt: TitanEye phases 5 to 7 (add a site, pull indicators from a scan, pivot on them)

Paste everything below the line into a fresh Claude Code session at the repo root on the `Visualizer`
branch. Before starting, load the `urlscan-visualizer` skill and read `docs/TITANEYE.md` and
`docs/CONVENTIONS.md`. Where the code and `docs/TITANEYE.md` disagree, trust the code.

---

## Goal

Today a site only enters the graph as a by-product of an expansion (search hits) or a dataset import.
Search hits expose little (apex, IP, ASN, reverse DNS, TLS issuer, server), so hashes, filenames, text
and third-party domains only appear if you already had them as a seed. Fix both ends:

- **Phase 5: add a site to the graph** directly (URL, domain or scan ID), no urlscan search needed to get it on the canvas.
- **Phase 6: pull indicators out of a scan.** From a site (or domain, or scan), fetch the full urlscan result and add its hashes, filenames, domains, IPs, certificate, text, technologies, contacts and wallets as linked nodes. This is the `/api/graph/site` call listed under "Known gaps" in `docs/TITANEYE.md`.
- **Phase 7: pivot by indicator.** Clicking any indicator node searches urlscan for other scans that share it and adds those sites, with the indicator's strength explained.

Work in three separate, reviewable steps (5, then 6, then 7). **Stop after each phase and wait for my
review. Do not commit, push or deploy. Never write an API key into a file.**

## Hard constraints (from this repo)

- No `innerHTML` / `outerHTML` / `insertAdjacentHTML` / `eval`; build DOM with `createElement` and
  `textContent`. All node data is hostile (scanned pages control every string in a result).
- Strict CSP: no inline script, no `on*=`, no `style="..."` in markup (CSSOM `element.style.x` is fine).
  New scripts are same-origin files under `static/`.
- Project JS is ES5, one IIFE per file with `"use strict"` (no arrows, `let`/`const`, template literals,
  classes, async/await). Vendored bundles are exempt.
- Server queries come only from the fixed `TRANSFORMS` table with the value checked against its node
  type (`graph_builder.build_query`). Never accept a field name or raw query from a node click. Every
  new transform field must exist in `database/query_terms.csv` (a test checks).
- Visibility stays computed in one place (`titaneye.js:refreshVisibility`). Do not weaken the type
  filter, dataset layers, time range, noise filter, declutter, find, saved cases or exports.
- Node ids are `type:value` via `graph_builder.node_id`; values canonical; edge ids are
  `source|relation|target` so the same fact from two sources merges. Provenance goes in `attrs.source`
  (`urlscan:<query>` or `urlscan:scan:<uuid>`).
- Tests: stdlib `unittest`, no network (fake the urlscan session, use fixtures; `tests/fixture_result.json`
  already has a result-shaped sample and should be extended, not replaced). All existing tests must
  still pass. Update `docs/TITANEYE.md` (phases table, contract, known gaps) and `CHANGELOG.md`.
- Check urlscan.io's current docs for the result schema and rate limits before relying on a field. If a
  field is not in the fixture or the docs, do not guess: skip it and say so in the report.

## Phase 5: add a website to the graph

**Entry points** (all use the same path):

1. A **Add site** control in the top bar next to the expansion box (or make the existing value box
   accept it): paste a URL, bare domain, host:port, or a 36-character scan UUID / `urlscan.io/result/<uuid>` link.
2. A multi-line paste (one per line, max 200, same cap as ingest).
3. From the main grid and analyzer: an **Add to TitanEye** action on a result row and in the analyzer
   header, so a scan you are already looking at goes straight onto the graph.

**Behaviour**

- Reuse `graph_builder.normalise_site` / `ingest` so the site, its apex domain and a `same_apex` edge
  are created exactly like an import. No urlscan key and no urlscan call is needed for this step, only
  the ingest limiter. Layer: a new `manual` source (`file:`-style layer named "Added by hand") so the
  layer buttons can hide it.
- A scan UUID is different: it maps to a scan, so it needs the key and goes to phase 6's fetch. Until
  phase 6 lands, an unknown UUID shows "needs a key / fetch not available".
- Already present nodes merge, never duplicate. After adding, select the new site, centre the camera on
  it, and open its detail panel. Only new nodes get laid out (existing `placed` rule).
- Invalid input is listed per line with the reason; valid lines still add.
- The detail panel for a site gets a visible next step: **Get indicators from scan** (phase 6), disabled
  with a reason when there is no key or no scan ID known.

**Tests**: add-site normalisation (URL with path/port/userinfo, IDN, IP-literal, `www.` stripping,
garbage, over-long, UUID forms), merge on repeat, the 200 cap.

## Phase 6: indicators from a site, domain or scan

**Backend: `POST /api/graph/site`**

- Body: exactly one of `{scan_id}` or `{url}` / `{domain}`. For a domain or URL, run a bounded urlscan
  search (newest first, `size` small) to find the latest scan, or use the scan IDs already stored on the
  site node (`attrs.scans`, `MAX_SCANS_PER_SITE`). Let the user choose which scan when a site has several.
- Validate the UUID shape before it goes anywhere near a URL (`/api/result/<uuid>` at `app.py:776` is the
  pattern to copy). Same order of checks as expand: rate limiter, body, value, key, upstream. Same error
  codes plus `scan_not_found`, `scan_not_ready` (urlscan returns 404 while a scan is still running; say
  so and let the client retry, do not loop on the server).
- Add `graph_builder.shape_scan(result, scan_id)` that turns one full result into a fragment (same
  `{nodes, edges, meta}` shape as `shape_expansion`). Every string is clamped to `MAX_VALUE_LENGTH`,
  stripped of control characters, and canonicalised through `canonical_value`; anything that fails
  validation is dropped and counted in `meta.skipped` by reason.

**Indicators to extract** (each a node type that already exists; add a new type only if it clearly needs
one, and then update `NODE_TYPES`, colours/labels in `titaneye.js:TYPES`, exports and the legend):

| From the result | Node type | Edge from site | Notes |
|---|---|---|---|
| Resource hashes (`data.requests` response `hash`, `lists`/`data.links`), SHA-256 | `file_hash` | `serves_file` | Cap per scan (default 100, keep the biggest/most distinctive). Skip empty-body hashes and known-boring ones. |
| Page DOM hash and text hash (`dom`/`text` hashes if present in the result) | `file_hash` with `attrs.kind` | `serves_file` / `contains_text` | Label as DOM or text hash, not just a hash. |
| Requested filenames and URL paths (last path segment, with extension) | `filename` | `serves_file` | Drop generic names (`index.html`, `favicon.ico`, hashed bundle names under a CDN) via one small editable list, not hard-coded in several places. |
| Contacted domains (`lists.domains`), third-party resource hosts | `third_party` | `loads_third_party` | Exclude the page's own apex. Each also gets its apex. |
| Contacted IPs (`lists.ips`) | `ip` | `resolves_to` | Mark the primary page IP separately from third-party IPs (`attrs.role`). |
| ASN, server, country, reverse DNS | `asn`, `tech`, `ptr` | `hosted_on`, `uses_tech`, `resolves_to` | Same as search hits so they merge with existing nodes. |
| TLS certificate (issuer **and** subject/SAN/serial when present) | `tls_cert` | `uses_cert` | This closes the "`tls_cert` is keyed by issuer name" gap. Use a certificate identity (fingerprint or issuer+serial) as the id and keep the issuer as the label. Do not break existing issuer-keyed nodes: keep an edge from the cert to its issuer, or migrate on load with a documented rule. |
| Technologies (`meta.processors`/Wappalyzer results) | `tech` | `uses_tech` | |
| Brand matches | `brand` | `impersonates` | |
| Telegram/WhatsApp/email links on the page (`links`) | `contact` | `links_to_contact` | Reuse the handle validation in `_HANDLE`. |
| Wallet addresses in page text or links | `wallet` | `contains_text` | Validate with `normalise_wallet`; invalid ones are dropped, not shown. |
| Redirect chain (`data.requests` with redirect responses) | `site` / `apex_domain` | `redirects_to` | Order matters; keep hop number in `attrs`. |
| Tags and verdicts | `tag` | `tagged` | Verdict score goes in site `attrs`, not a node. |

**Frontend**

- A **Get indicators** button on a site node (and on an apex domain, which resolves to its latest scan)
  opens a small checklist of indicator categories with counts before anything is added, so a 400-request
  page does not dump 400 nodes. Defaults: hashes, filenames, third-party domains, IPs, certificate,
  contacts, wallets on; technologies and redirect hops off. Remember the choice in `localStorage` per
  category (preference only, no data).
- "Add all" and "Add selected". Show how many were added, merged and skipped (with reasons).
- Indicator nodes that already exist merge and just gain the new edge. New ones are placed near the site.
- The scan itself is kept: the site node stores `attrs.scans` (id, time, verdict) and **Open scan in
  analyzer** keeps working.
- Rate limit: reuse the existing urlscan limiter and show its `retry_after`. The crawler (`titaneye-crawl.js`)
  must be able to call the same fetch as an optional step ("fetch scan for each new site", off by default,
  capped, because it costs one result call per site).

**Tests**: `shape_scan` against `tests/fixture_result.json` (extend it with a resource hash, a repeated
filename, a wallet in text, a Telegram link, a redirect, a SAN-bearing certificate, and a hostile string
with control characters and 10,000 characters); every dropped category counted; id stability across two
calls; the new route's error mapping; UUID validation; the per-scan caps.

## Phase 7: pivot by indicator

**Goal:** click an indicator node and search urlscan for it, without opening the expansion box.

- In the detail panel of every indicator type, the transforms list from `catalog()` already offers the
  right searches. Add a single prominent **Pivot** button at the top of the panel that runs the
  indicator's primary transform (hash → `hash_sites`, filename → `filename_sites`, third-party →
  `third_party_sites`, IP → `ip_sites`, certificate → `cert_sites`, contact → `contact_sites`, and so on)
  and lists the alternatives (including Pro ones, marked, with the account-plan caveat) in a menu.
  Add a **double-click** on an indicator node to run the same primary pivot, and keep single-click as select.
- Show the exact query before it runs (as the panel does now) and a result summary after: how many
  sites were found, how many were new to the graph, whether more pages exist (`Load next page`), and the
  `total` from urlscan.
- **Indicator strength.** A hash shared by 3 sites is evidence; a jQuery hash shared by 2 million is
  noise. After a pivot, store `attrs.total` (from `meta.total`) on the indicator and show it as
  "seen on N scans". Above a threshold (default 500, editable), do not add the sites automatically:
  ask "This indicator is on ~N scans. Add the newest 100?" so a click cannot flood the graph. Feed the
  same number into the existing noise filter and the cluster strength ranking instead of inventing a
  second measure.
- **New transforms** where the `TRANSFORMS` table has gaps (add each with a `field` from
  `query_terms.csv`, a test, and a plan marker): file-name-plus-extension variants, TLS certificate by
  fingerprint/subject if the query terms support it, `page.title`, `page.domain` for third-party hosts
  seen in `lists.domains`, response hash vs DOM hash vs text hash kept as separate transforms so a hit
  says which one matched. Do not add a transform whose field is not searchable.
- **Chaining.** After a pivot, the new sites can be fed straight into phase 6 ("Get indicators for
  these N sites", capped, confirmation required, rate-limit aware). The crawler's follow list should gain
  the new indicator types (certificate, contact, wallet, third-party) with the existing skip threshold.
- **Right-click / context** is out of scope. Keyboard: with an indicator selected, `P` pivots.
- Edge labels: every pivot edge keeps `attrs.source = urlscan:<query>` so provenance shows which query
  linked two sites. The detail panel for an edge (or the site's connection list) should show it.

**Tests**: primary-transform mapping for every indicator type, threshold behaviour (pure function,
testable without a browser), query building for each new transform including injection attempts
(quotes, backslashes, regex metacharacters, newlines, over-long values), cursor paging.

## Report back (after each phase)

- What changed, file by file, and why.
- The checks you ran, including anything verified in a real browser against the fixtures or a stub server.
  Say plainly what was **not** verified (a live urlscan call, 50k nodes, browser code with no unit tests).
- Anything in the urlscan result you wanted to extract but could not confirm from docs or the fixture.
- Open questions and any decision you made that I might want to change.
