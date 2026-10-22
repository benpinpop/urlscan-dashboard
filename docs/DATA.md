# Data files (`database/`)

Three CSVs, all UTF-8 (a BOM is tolerated: loaded with `utf-8-sig`), all read once when `app.py` is
imported. **Restart the server after editing.** Each path can be overridden by env var to keep
edits outside the repo.

| File | Loader | Env override | Rows (current) | Served by |
|---|---|---|---|---|
| `crypto_scam_keywords.csv` | `keyword_db.KeywordDatabase.load` | `KEYWORD_DB_PATH` | 529 keywords, 22 categories | `/api/keywords` (+ summary in `/api/result` meta, `/api/config`) |
| `domain_categories.csv` | `domain_intel.DomainTable.load` | `DOMAIN_TABLE_PATH` | 198 patterns | used server-side in `shape_result` |
| `query_terms.csv` | `query_terms.QueryTerms.load` | `QUERY_TERMS_PATH` | 114 fields (65 free, 49 pro) | `/api/query-terms` |

Counts drift as rows are added; recompute rather than trusting this table.

## `crypto_scam_keywords.csv`

Columns: `keyword,category,weight`

| Rule (in `KeywordDatabase.load`) | Effect |
|---|---|
| keyword lowercased, trimmed, `TRANSLATIONS` applied (curly quotes, NBSP, dashes, fullwidth %), whitespace collapsed | stored form must match normalised page text |
| empty or duplicate keyword | skipped (first wins) |
| blank category | `uncategorised` |
| weight not an int | 1; clamped to 1..5 |
| no usable rows | `ValueError`; app sets `KEYWORD_DB = None`, content analysis disabled, `/api/keywords` 503 |

Scoring semantics (constants in `keyword_db.py`, shipped to the browser by `browser_data()`):

| Constant | Value | Meaning |
|---|---|---|
| `TIER_VALUE` | `{1: 0.0, 2: 0.2, 3: 0.5, 4: 1.25, 5: 1.5}` | points per distinct keyword by weight; weight 1 = context, never scored |
| `OCCURRENCE_CAP` | 5 | occurrences past this do not count |
| `REPEAT_BONUS` / `REPEAT_BONUS_CAP` | 0.1 / 4 | repetition adds at most +40% |
| `SIGNAL_MIDPOINT` | 2.2 | `base = 100 * (1 - exp(-points / 2.2))` |
| `BREADTH_FLOOR` / `BREADTH_FULL_AT` | 0.55 / 5 | multiplier rises linearly to 1.0 at 5 scoring categories |

Bands differ between the two scorers (see GOTCHAS): Python `band_for` uses 15 / 40 / 70; the live
browser scorer `analyzer.js:scoreClientText` uses 20 / 50 / 75.

Matching: case-insensitive, boundary = no ASCII letter/digit on either side
(`(?<![a-z0-9])...(?![a-z0-9])`), longest alternative first, so `get rich quick` beats `get rich`.

Extending: add rows; categories are free text (underscores shown as spaces in the UI). Splitting one
concept across several categories inflates the breadth multiplier. Run
`python -m unittest discover -s tests -p "test_analyzer.py"` afterwards: calibration tests (`test_scam_page_scores_high`,
`test_benign_page_scores_minimal`, `test_a_legitimate_crypto_page_stays_out_of_the_high_band`) guard
against drift.

## `domain_categories.csv`

Columns: `pattern,category,label`

| Rule (in `DomainTable`) | Effect |
|---|---|
| pattern and category lowercased; label kept as written (defaults to pattern) | |
| rows missing pattern or category | skipped |
| file missing | empty table, no error (everything classifies as `unknown`) |
| patterns sorted longest first | specific subdomain beats parent |
| pattern without `/` | matches host equal to it or ending in `.` + pattern |
| pattern with `/` (`google.com/recaptcha`, `gstatic.com/recaptcha`) | tried first; **substring** test against `host + path` |
| host shares `registrable_domain` with the scan apex | forced to `first_party`, label kept or `Scanned site` |

Known categories (`domain_intel.CATEGORY_LABELS`): `first_party analytics ads tracker cdn fonts
captcha social chat payment crypto platform hosting unknown`. Any other category is displayed as
`category.title()` (the shipped file has one `framework` row). Pill colours are CSS classes in
`analyzer.css`, not driven by `CATEGORY_LABELS`.

`registrable_domain` is a heuristic over `MULTI_LABEL_SUFFIXES` (a short list, includes hosting
suffixes like `github.io`, `pages.dev`, `vercel.app`). Add a suffix there if apex grouping is wrong
for a hosting platform. It is not a Public Suffix List.

## `query_terms.csv`

Columns (all required, else `ValueError`): `field,group,type,plan,regex,description,example`

| Rule (in `QueryTerms.load`) | Effect |
|---|---|
| `field` must match `^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*$` | else row skipped |
| duplicate field (case-insensitive) | first row wins |
| `plan` | `pro` if the cell is `pro` (any case/spacing), else `free` |
| `regex` | `"true"` if `true`/`1`/`yes`, else `"false"` (strings, not booleans) |
| `group`, `type`, `description` | whitespace collapsed, clipped to 300 chars |
| `example` | only trimmed at the ends (quoted phrases keep inner spacing), clipped to 300 |
| no usable rows / missing file | exception; app logs it, `QUERY_TERMS = None`, route 503, autocomplete silently off |

Quote cells containing commas and double inner quotes, e.g.
`"asnname.keyword:""CLOUDFLARENET, US"""`. The browser renders every value via `textContent`.

## `static/js/examples.js` (not CSV, but data)

`window.URLSCAN_EXAMPLES` is a plain array of urlscan query strings shown in the empty state
(`#example-list`) and the Pivot Library (`#pivots-list`). Append strings; keep it valid JS.

## Test fixture

`tests/fixture_result.json` is a raw urlscan result document used by `tests/test_analyzer.py`,
`tests/test_routes.py` and `tests/stub_server.py`. It is deliberately awkward (failed request,
request without response, malformed hash, download with three digests). Tests assert exact counts
from it (6 files, threat score 85), so editing it means updating those assertions.
