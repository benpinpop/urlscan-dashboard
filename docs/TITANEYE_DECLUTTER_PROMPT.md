# Prompt: declutter the TitanEye graph

Paste everything below the line into a fresh Claude Code session at the repo root on the `Visualizer`
branch. Before starting, load the `urlscan-visualizer` skill and read `docs/TITANEYE.md` and
`docs/CONVENTIONS.md`.

---

## Goal

The TitanEye graph gets visually cluttered as it grows: hundreds of dots in a tangle, singletons
scattered around the edge, lines crossing everywhere, labels on top of each other. Make the layout
tidier by default, and add a filter that removes the low-value nodes: **orphaned IP addresses** and
**sites with fewer than two connections**.

Two deliverables:

1. A **declutter filter** with explicit, explainable rules (below).
2. **Better organisation of the bubbles**: layout, spacing, labels and edge rendering.

**When finished, stop and wait for my review. Do not commit, push or deploy. Never write an API key
into a file.**

## Hard constraints (from this repo)

- No `innerHTML` / `outerHTML` / `insertAdjacentHTML` / `eval`; build DOM with `createElement` and
  `textContent`. All node data is hostile.
- Strict CSP: no inline script, no `on*=`, no `style="..."` in markup (CSSOM `element.style.x` is fine).
  Anything new that is a script must be a same-origin file under `static/`.
- Project JS is ES5 in one IIFE per file with `"use strict"` (no arrows, `let`/`const`, template
  literals, classes, async/await). Vendored bundles are exempt.
- Do not weaken any existing behaviour: type filter, dataset layers, time range, noise filter, find,
  selection dimming, saved cases, exports. Visibility must stay computed in one place
  (`titaneye.js:refreshVisibility`).
- Tests: stdlib `unittest`, no network. All 161 existing tests must still pass. Update `docs/TITANEYE.md`
  and `CHANGELOG.md`.

## Part 1: the declutter filter

Add a **Declutter** group to the **Filters** section of the scale drawer (`titaneye-scale.js:renderFilters`)
and also a small always-visible toggle in the graph's top bar (a **Declutter** button with a count of
what it is hiding, for example "Declutter (37 hidden)"), because I want to flip it without opening the
drawer. Both controls drive the same state.

### Rules (all individually switchable, all off by default except where noted)

| Option | What it hides |
|---|---|
| **Hide orphaned IPs** | IP nodes (and `cidr` nodes) that have **no visible site** attached. This includes an IP that only connects to an ASN or reverse-DNS name, and IPs left behind after their sites were hidden by another filter (time range, noise, dataset layer, manual hide). |
| **Hide sites with fewer than N connections** (N defaults to 2, adjustable 1 to 10) | Site nodes whose number of **visible** connections is below N. |
| **Also hide what is left stranded** (on by default when either option above is on) | Non-site nodes (apex domains, ASNs, TLS issuers, reverse DNS, technologies and so on) whose visible neighbours have all been hidden, repeated until nothing more changes. |

Define "connections" precisely and write it in the UI help text:

- A connection is an edge to a **currently visible** node, so the filters compose with the existing ones
  (hiding a noisy IP can make a site drop below two connections, and that should take effect).
- Count **distinct neighbour nodes**, not parallel edges (the graph allows several edges between the same
  pair).
- Imported datasets: a site from a CSV with only a site column has one connection to its apex domain.
  With N = 2 it would vanish. Make that obvious: show the count of hidden sites in the status text and let
  me keep any node by **pinning** it (see below). Do not special-case imports silently.

### Behaviour requirements

- Compute with a **fixed-point loop** over the graph in `refreshVisibility` (or a helper it calls). It
  must stay fast: aim for under 150 ms on 17,000 nodes / 48,000 edges. Precompute neighbour lists once
  per refresh rather than calling `forEachNeighbor` per node repeatedly. Cap the loop at a sensible
  number of passes.
- Selected nodes, search matches (the find box) and **pinned** nodes are never hidden by the declutter
  filter. Add a **Pin** / **Unpin** button to the node detail panel; pinned nodes get a visible ring or
  marker and are saved in cases (`snapshot` / `loadSnapshot`) and the nodes CSV (`pinned` column).
- Show what the filter is doing: the top-bar button shows the hidden count, and the drawer lists the
  count per rule ("23 orphaned IPs, 14 sites with fewer than 2 connections, 6 stranded nodes").
- A **Reveal hidden** toggle turns the filter off and back on without losing its settings, so I can
  check what it removed.
- Persist the settings for the session only (not `localStorage`, to avoid surprises on the next case).
  Save them inside a case file so a loaded case looks the same. Bump `schema_version` only if the case
  shape changes incompatibly; older case files must still load.
- Exports: add a `hidden_by` note column to the nodes CSV (`declutter`, `noise`, `time`, `type`,
  `layer`, `manual`, or blank) so an analyst can see why something was left out when "only nodes
  currently shown" is off.

## Part 2: organise the bubbles

Work through these in order, measuring each against the same test graphs before and after (see
Verification). Keep what helps; drop what does not and say so.

### 2.1 Layout

The current layout is ForceAtlas2 in a worker (`titaneye.js:runLayout`, settings from
`inferSettings`). It tends to produce hairballs and sends disconnected pieces far apart.

- **Tune the force settings** for readability: a higher `scalingRatio`, `gravity` just strong enough to
  keep components near each other, `linLogMode` on for large graphs, `adjustSizes` or a post-pass that
  nudges overlapping circles apart, and a higher `slowDown` so it settles. Pick values by experiment, not
  guesswork, and record them in the docs.
- **Pack disconnected components.** Find connected components (visible nodes only), lay each out on its
  own, then arrange the components in a tidy grid or spiral ordered by size, instead of letting gravity
  sling them around. The biggest component sits in the middle.
- **Layout presets** in a small dropdown next to the Declutter button:
  1. **Organic** (default; the improved force layout).
  2. **Grouped by cluster**: one region per cluster from the scale view's `findClusters`, with sites
     inside and shared indicators between them.
  3. **Rings by type**: concentric rings (apex domains and sites outside, hosting infrastructure in the
     middle, wallets and contacts at the centre) so the structure reads at a glance.
  4. **Hierarchy**: ASN → IP → site, top to bottom, for hosting questions.
- A **Tidy** button re-runs the current preset on the **visible** nodes only. Positions of hidden nodes
  are kept so they return to a sensible place when revealed. Layout must stay cancelable and run in the
  worker; never block the page.
- **Stable positions.** Expanding a node should not rearrange the whole graph. New nodes appear near
  their anchor and the layout runs with existing nodes pinned loosely (low mass movement) unless I press
  Tidy.
- **Fan-out leaves.** When one hub has many leaf neighbours (degree-1 sites hanging off one IP or apex
  domain), arrange them evenly in a ring or arc around the hub instead of a clump.

### 2.2 Labels and sizes

- Show labels only for hubs and the selected, highlighted or found nodes at normal zoom; reveal more
  labels as the camera zooms in (tune `labelDensity` and `labelRenderedSizeThreshold`, or compute label
  priority from degree). No label may overlap a higher-priority one.
- Keep long values short on the canvas (existing clipping) and show the full value on hover via a tooltip
  built with `textContent`.
- Re-check `sizeScale` so nodes do not touch at the default zoom for graphs of 500, 3,000 and 10,000+
  nodes.

### 2.3 Edges

- Make edges visually quieter by default: lower opacity, thinner, and drawn under nodes. Edges to a
  selected node stay prominent (already done).
- For multiple edges between the same pair, draw one line (with a count in the detail panel) instead of
  stacking them.
- Add an **Edges** control: Show all / Only for the selection and its neighbours / Hide. Large graphs
  should default to the quieter setting automatically above a node threshold you choose and document.

### 2.4 Optional, only if it is clean to do

- A **Collapse leaves** action on a hub: replace its degree-1 neighbours with one "N sites" badge node
  that expands again on click. Skip this if it complicates cases, exports or find; note why.

## Backend

None expected. This is frontend work in `static/js/titaneye.js`, `titaneye-scale.js`, `titaneye-cases.js`
(pinned, hidden_by, case shape) and `static/css/titaneye.css`, plus markup in `templates/index.html`.
If you need a new vendored layout helper (for example a packing or circular layout), build it into
`static/vendor/` with its licence, like the existing ForceAtlas2 files, and say how it was built.

## Verification (required)

Use headless Chrome as in earlier phases (`puppeteer-core` against `tests/stub_server.py`, fixtures in
`tests/fixtures/`, and a generated large stub for scale). Do not put API keys in any file; none are
needed for the stub.

1. **Rules.** Build small graphs and assert the exact hidden sets: an IP linked only to an ASN is hidden;
   an IP with one visible site is kept; hiding a site's only noisy IP makes the site drop below two
   connections and hide; stranded apex domains and ASNs go with them; pinned, selected and found nodes
   stay; turning the options off restores everything; parallel edges count once.
2. **Composition.** Declutter together with the time range, noise filter, dataset layers and manual hide
   gives the same result in any order of toggling.
3. **Performance.** Time `refreshVisibility` with Declutter on at 1,000, 5,000 and 17,000 nodes and
   report the milliseconds.
4. **Layout.** For the fixtures and a generated graph of about 3,000 nodes with many singletons and
   several clusters, take before and after screenshots and report: number of overlapping node pairs,
   number of labels drawn on top of other labels, and the bounding-box area the components occupy.
   Look at the screenshots yourself and say honestly whether it looks better.
5. **Regression.** All 161 tests pass; the earlier headless checks (find, import, wallet intel with a
   stubbed provider, scale view, crawl, cases round-trip, exports) still pass; no console errors or CSP
   violations.
6. **Cases.** Save a case with Declutter on and pins set, reload the page, load it, and confirm the same
   nodes are hidden and the same nodes are pinned. Load an older case file (made before this change)
   and confirm it still opens.

## Deliverables

1. The Declutter filter (drawer group plus top-bar toggle with a hidden count), Pin/Unpin, and the layout
   presets, Tidy, label and edge improvements.
2. Updated `docs/TITANEYE.md` (rules, definitions, presets, settings chosen and why, measurements) and
   `CHANGELOG.md`.
3. A short summary of what changed, what you tried and dropped, the before/after numbers, and anything
   you decided without me.

Then **stop and wait for my review**.
