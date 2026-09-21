# Integration guide

How the result analyzer attaches to the contact-sheet dashboard, and how to attach it to something
else. Read `README.md` first for what the analyzer does; this is about the seams.

---

## The shape of it

The analyzer is not a separate page. It is a fixed overlay in the same document, driven by
`static/js/analyzer.js`, which exposes one global and talks only to this app's own `/api/*`
endpoints.

```
templates/index.html
├── contact sheet markup            ← static/js/app.js
└── <section id="analyzer" hidden>  ← static/js/analyzer.js
    └── <div id="an-panel" hidden>     slide-over for file and hash detail
```

Two scripts, one page, no framework and no build step. They meet in exactly two places: `app.js`
calls `URLScanAnalyzer.init()` once at startup, and the analyzer calls back through `onPivot` when a
click should become a search.

Load order matters — `analyzer.js` must be parsed before `app.js` so the global exists. Both use
`defer`, which executes them in document order:

```html
<script src="{{ url_for('static', filename='js/analyzer.js') }}" defer></script>
<script src="{{ url_for('static', filename='js/app.js') }}" defer></script>
```

---

## The JavaScript API

```js
URLScanAnalyzer.init({ getKey, onPivot });  // wire it up, once
URLScanAnalyzer.open(uuid);                 // open, and load that scan (null = just open)
URLScanAnalyzer.close();                    // back to the host page
URLScanAnalyzer.clearCache();               // drop cached results for this tab
URLScanAnalyzer.isOpen();                   // boolean
```

### `init(options)`

| Option | Type | What it is for |
|---|---|---|
| `getKey` | `() => string` | Returns the current urlscan.io API key. Defaults to reading `#api-key`. |
| `onPivot` | `(query) => void` | Called when the user clicks something that should become a search. |

`getKey` is a callback rather than a field reference so the analyzer never owns the key or decides
where it lives. Return an empty string when the server holds its own key
(`FORCE_SERVER_KEY=true`) — the header is simply omitted.

`onPivot` receives a ready-made urlscan query string: `page.domain:"cdn.example.com"`,
`page.asn:AS15169`, `hash:9f2c1b…`. What you do with it is yours. The contact sheet closes the
panel, fills the search field and runs the search:

```js
window.URLScanAnalyzer.init({
  getKey: currentKey,
  onPivot: function (query) {
    window.URLScanAnalyzer.close();
    el.query.value = query;
    el.filter.value = "";
    runSearch(false);
  }
});
```

Leave `onPivot` unset and pivot clicks show a short "not available" toast instead. Everything else
still works.

### Opening it from a result

```js
analyzeButton.addEventListener("click", function () {
  window.URLScanAnalyzer.open(result.uuid);
});
```

`open()` validates the UUID, checks `sessionStorage`, and fetches only on a miss. Calling it again
with the UUID already loaded just re-shows the panel. Hide your own entry point when `result.uuid` is
missing — `app.js` does this, since a scan with no ID has nothing to pull.

### Cache invalidation

Results are cached in `sessionStorage` under `urlscan-analyzer.result.<uuid>` and
`urlscan-analyzer.analysis.<uuid>`. They are scoped to the tab, and the server scopes its own cache
to a digest of the API key — but the browser cache is not key-aware, so clear it when the key
changes:

```js
el.key.addEventListener("change", function () { window.URLScanAnalyzer.clearCache(); });
el.keyForget.addEventListener("click", function () { window.URLScanAnalyzer.clearCache(); });
```

---

## Putting it in a different frontend

The module needs four things:

1. **The markup shell.** Copy the `<section id="analyzer">` and `<div id="an-panel">` blocks from
   `templates/index.html` verbatim. The IDs are the contract; everything inside them is built at
   runtime.
2. **Both stylesheets.** `analyzer.css` uses tokens defined in `styles.css` (`--paper`, `--mono`,
   `--ink-faint`, the `.btn` and `.field` classes). Load `styles.css` first, or redefine those
   tokens.
3. **The endpoints**, same-origin: `/api/result/<uuid>`, `/api/dom/<uuid>`, `/api/keywords`, and `/api/search`
   for hash correlation. If your app serves them under a prefix, change the three `request(...)`
   calls in `analyzer.js`.
4. **`init()` with a `getKey`** that suits your auth.

If you only want the data, skip the module: the endpoints below are the whole interface.

---

## Backend endpoints

All take the key as an `X-URLScan-Key` request header, unless the server holds its own. All return
`{"ok": false, "error": {"code", "message"}}` on failure, with the HTTP status to match.

### `GET /api/result/<uuid>`

One `GET /api/v1/result/{uuid}/` upstream, flattened. The browser never walks the raw document.

```jsonc
{
  "ok": true,
  "summary": {
    "uuid": "…", "title": "…", "url": "…", "domain": "…", "apex_domain": "…",
    "ip": "…", "ptr": "…", "asn": "AS64500", "asn_name": "…", "country": "US", "city": "…",
    "server": "nginx", "status": 200, "mime_type": "text/html",
    "scan_time": "2026-09-14T09:12:44.123Z", "visibility": "public", "tags": ["…"],
    "report_url": "…", "screenshot_url": "…",
    "tls": { "issuer": "R11", "valid_days": 62, "age_days": 28,
             "certificate": { "subject": "…", "issuer": "…", "valid_from": 0, "valid_to": 0 } },
    "counts": { "requests": 6, "domains": 6, "ips": 3, "asns": 3, "links": 14,
                "cookies": 1, "ads_blocked": 2, "secure_percentage": 83,
                "unique_countries": 3, "transfer_bytes": 163124 },
    "technologies": [{ "name": "Nginx", "confidence": 100, "categories": ["Web servers"] }]
  },
  "verdicts": {
    "threat_score": 85, "band": "malicious", "malicious": true, "has_verdicts": true,
    "overall":   { "score": 85, "categories": [], "brands": [], "tags": [] },
    "urlscan":   { "score": 75, "detection_details": ["…"] },
    "engines":   { "score": 66, "malicious_total": 2, "benign_total": 1, "engines_total": 3,
                   "rows": [{ "engine": "…", "malicious": true, "score": 100,
                              "categories": ["phishing"], "verdict": "malicious" }] },
    "community": { "score": 0, "votes_total": 2, "votes_malicious": 2, "votes_benign": 0 }
  },
  "files": [{
    "index": 1, "url": "…", "filename": "invest", "domain": "…", "apex_domain": "…",
    "is_first_party": true, "category": "first_party", "category_label": "First party",
    "service": null, "mime_type": "text/html", "resource_type": "Document", "method": "GET",
    "status": 200, "size_bytes": 48210, "protocol": "h2", "ip": "…", "country": "United States",
    "asn": "AS64500", "asn_name": "…",
    "hashes": [{ "algorithm": "sha256", "value": "…" }],
    "from_download_processor": false, "failed": false, "error": null,
    "initiator": "other", "security_state": "secure",
    "headers": [{ "name": "content-type", "value": "text/html", "truncated": false }],
    "request_headers": [ … ]
  }],
  "domains": [{
    "domain": "…", "apex_domain": "…", "requests": 3, "size_bytes": 0, "encoded_bytes": 0,
    "ips": ["…"], "country": "United States", "country_code": "US",
    "asn": "AS64500", "asn_name": "…", "category": "analytics", "category_label": "Analytics",
    "service": "Google Analytics", "is_first_party": false, "redirects": 0
  }],
  "file_stats":   { "total": 6, "first_party": 2, "third_party": 4, "with_hashes": 3,
                    "failed": 1, "truncated": 0, "total_bytes": 4400308 },
  "domain_stats": { "total": 4, "third_party": 3,
                    "categories": [{ "category": "analytics", "requests": 2, "domains": 1 }] },
  "meta": { "uuid": "…", "cached": false, "fetch_ms": 412,
            "content_analysis_available": true, "keyword_database": { … } }
}
```

Notes that matter if you consume this directly:

- Every field is present on every response; missing upstream data comes back as `null`, `[]` or `0`.
  There is no need to guard each access.
- `files` keeps failed and response-less requests, flagged with `failed` and `error`.
- `hashes` only ever contains validated hex digests of 32, 40 or 64 characters. A garbage value
  upstream produces an empty list, not a bad badge.
- `files` is capped at 1,500 rows; `file_stats.truncated` says how many were dropped.
- `category` / `service` come from the local table, never from urlscan.

**Errors:** `invalid_uuid` (400), `missing_api_key` (401), `invalid_api_key` (401), `not_found` (404,
also returned for a scan still processing), `rate_limited` (429, urlscan's), `local_rate_limited`
(429, this server's), `network_error` (504).

### `GET /api/dom/<uuid>`

Fetches the stored DOM from `{URLSCAN_SITE_URL}/dom/<uuid>/`. The browser extracts visible text and
scores it locally using the definitions from `/api/keywords`.

```jsonc
{
  "ok": true, "uuid": "…", "html": "<html>…</html>",
  "meta": { "dom_bytes": 1642 }
}
```

The HTML is attacker-controlled. Parse it as a document and never render it as markup in the app.
The browser-side scorer returns the same analysis shape used by the analyzer UI.

**Extra errors:** `response_too_large` (413) when the DOM exceeds `MAX_DOM_BYTES`,
and `keyword_db_unavailable` (503) when the CSV could not be loaded.

### `GET /api/keywords`

`{"ok": true, "keyword_count": 507, "category_count": 22, "keywords": [{"keyword": "…",
"category": "…", "weight": 5}], ...}`. Useful for reproducing the browser-side score.

### `GET /api/search?q=hash:<value>&size=25`

Not new — the existing search endpoint. Hash correlation is a search like any other, which is why
the analyzer does not need a dedicated endpoint for it and why a hash click can hand the same query
to the main dashboard.

---

## Extending the databases

Both are plain CSV, read once at startup. Restart after editing.

**`database/crypto_scam_keywords.csv`** — `keyword,category,weight`.

- Keywords are matched case-insensitively, with alphanumeric-boundary checks. Punctuation inside a
  keyword is fine (`1.5% daily`, `gh/s plan`, `don't miss out`).
- Weight 1 is context: reported, never scored. Use it for topic vocabulary.
- Weights 2–5 score. Reserve 5 for claims that are close to definitional — a fixed daily return, a
  guarantee of profit, a promise that something is risk-free.
- Category names are free text and appear in the UI with underscores turned into spaces. New
  categories need no code change, but remember that breadth saturates at five, so splitting one
  concept across several categories inflates scores.
- Longer phrases win over shorter ones at the same position, so adding `get rich quick` alongside
  `get rich` is safe.

**`database/domain_categories.csv`** — `pattern,category,label`.

- A pattern without a slash matches a host exactly or as a suffix on a label boundary.
- A pattern with a slash matches against host + path, and is tried first.
- Longer patterns win, so a specific subdomain can override its parent.
- Unknown categories still render; `CATEGORY_LABELS` in `domain_intel.py` only supplies the display
  name and the pill colour for the ones it knows.

Point `KEYWORD_DB_PATH` and `DOMAIN_TABLE_PATH` elsewhere to keep your edits outside the repo.

---

## Working on it

```bash
python3 tests/stub_server.py 8010     # whole dashboard against canned data, no key needed
python3 -m unittest discover -s tests # 54 tests, no network
```

The stub serves `tests/fixture_result.json` for every scan ID and a canned scam page for content
analysis. The fixture is deliberately awkward — a failed request, a request with no response, a
malformed hash, a download with three digests, a wildcard certificate — so rendering edge cases show
up during development rather than against a live scan.
