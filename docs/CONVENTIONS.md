# Conventions

## Security rules (non-negotiable)

| Rule | How it is done today |
|---|---|
| Everything from a scan, a CSV, or Scambusters is hostile | Build nodes with `document.createElement` and fill with `textContent` (helpers: `analyzer.js:node`, `scambusters.js:node`, `autocomplete.js:make`). No `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `eval`, `document.write`. |
| Strict CSP, no `unsafe-inline` | No inline `<script>`, no `on*=` attributes, no `style="..."` in templates. Dynamic sizing uses the CSSOM (`el.style.width = ...`), which CSP allows. New script/style files go under `static/` and are linked from `index.html`. |
| Browser talks to its own origin | New third-party calls go through a Flask route, not `fetch` to another host. The only exception is Cloudflare DoH (`connect-src` lists it). Adding a host means editing the CSP in `app.py:security_headers`. |
| Scanned URLs are never links | Resource and scanned URLs render as text with a copy button. Only urlscan report links, VirusTotal / MalwareBazaar lookups and the frame domain (to the urlscan report) are `<a>`, always `target="_blank" rel="noopener noreferrer"`. |
| Keys never logged, echoed or put in URLs | urlscan key: `X-URLScan-Key` -> `API-Key` header. Scambusters key: `X-Scambusters-Key` -> `Authorization: Bearer`. Never include a key in an error message (`scambusters.js:redact` masks to last 4). `ScrubSecrets` is a backstop, not a licence to log. |
| Validate server-side before any upstream call | UUIDs (`UUID_SHAPE`), queries, sizes, cursors, wallet addresses, site URLs. Browser checks are convenience only. |
| Upstream-controlled hosts are never trusted | The DOM host comes from `URLSCAN_SITE_URL`, not from a response field; Scambusters requests use `allow_redirects=False`. |
| Bounded resources | `MAX_DOM_BYTES` streaming cap, `MAX_FILES`, header value cap, `MAX_CONTENT_LENGTH`, clipped CSV text. |
| `/api/*` is `no-store` | Automatic in `security_headers`; keep new API routes under `/api/`. |

## Error envelope

- urlscan-style routes: `return fail(message, status, code, **extra)` from `app.py`. Codes are
  `snake_case`; messages are user-facing sentences.
- Upstream failures: raise/catch `UrlscanError` subclasses; map with
  `fail(exc.message, exc.status, exc.code)`.
- Scambusters routes keep Scambusters' own shapes (`{"error"}` / `{"errors": [...]}`) and add
  `"source": "local" | "proxy"` for locally generated ones. Local 400s use Scambusters field paths
  (`site_url ...`, `wallets[3].xrp_dest_tag ...`) so `scambusters.js:applyValidationErrors` can map
  them.
- Frontend `request()` helpers throw an `Error` whose `.code` is the envelope code.

## JavaScript style

- One IIFE per file with `"use strict"`. Public modules return an object assigned to one
  `window.*` global; private helpers stay inside.
- ES5 syntax only: `var`, `function`, string concatenation. No arrow functions, `let`/`const`,
  template literals, classes, `async`/`await`, or ES modules. (Modern runtime APIs are fine.)
- DOM lookups happen once into an `el` object; mutable data lives in a `state` object.
- Optional cross-module features are feature-detected (`if (window.URLScanAnalyzer)`), never assumed.
- Toggle UI with the `hidden` attribute; CSS forces `[hidden] { display: none !important; }`.
- Toggle buttons expose state with `aria-pressed` / `aria-expanded` and read it back from there.
- Async UI guards against stale responses with tokens (`state.sbToken`, row `data-token`,
  `keyValidationToken`).
- Storage access is always in `try/catch`; the page must work with storage blocked.

## Python style

- Most modules start with `from __future__ import annotations` (`config.py` and `rate_limit.py` do
  not, which is why Python 3.10+ is required).
- Defensive accessors in `result_shaper.py` (`_dict`, `_list`, `_text`, `_int`): every output field
  exists on every response (`null`, `[]` or `0` when missing).
- No network in `result_shaper.py`, `keyword_db.py`, `domain_intel.py`, `query_terms.py`,
  `wallet_validation/`.
- `wallet_validation/`: do not edit outside blocks marked `XRP ADDITION`. `codecs.py` is a
  byte-identical copy of the ScamHunt CTF file; when the CTF changes, re-copy and re-apply XRP blocks.
- Dependencies are pinned in `requirements.txt` (Flask, requests, gunicorn, python-dotenv). Keep it
  that small; `pycryptodome` is optional (Keccak has a pure-Python fallback).

## Tests

- Framework: stdlib `unittest` (no pytest). No network, no API key.
- Each test file prepends the repo root to `sys.path` and imports `app as application`.
- Stubbing pattern: replace the module-level singleton, restore in `tearDown`.
  - urlscan: `application.client = Stub()` (see `tests/test_routes.py:Stub`).
  - Scambusters routes: `application.scambusters_client = StubScambusters()`.
  - Scambusters HTTP client: replace `client._session` with a `mock.Mock`.
  - Reset state per test: `application.RESULT_CACHE.clear()`, `application.limiter._hits.clear()`,
    `application.scambusters_limiter._hits.clear()`.
  - Unavailable tables: set `application.QUERY_TERMS = None` (or `KEYWORD_DB`) and restore.
- Flask: `application.app.config["TESTING"] = True`; `application.app.test_client()`.

Commands (repo root):

```
python -m unittest discover -s tests            # all, quiet
python -m unittest discover -s tests -v         # verbose
python -m unittest discover -s tests -p "test_routes.py"   # one module
python -m unittest discover -s tests -k test_bands        # tests matching a name
python tests/stub_server.py 8010                # UI against canned data, any 16+ char key
```

Do not use dotted names like `python -m unittest tests.test_routes`: `tests/` has no
`__init__.py`, and on the maintainer's Windows machine a third-party `tests` package in
site-packages shadows it (`ModuleNotFoundError`). `discover -s tests` avoids that.

On Linux/macOS use `python3` if `python` is not Python 3. There are no JS tests; frontend changes are
verified by hand against the stub server.

## Documentation

- `README.md` is user-facing; `INTEGRATION.md` describes the analyzer/reporter seams and endpoint
  contracts; `CHANGELOG.md` has an "Unreleased" section per feature. These have drifted from the
  code in places (see `docs/GOTCHAS.md`), so the code is the source of truth.
- `docs/` (this folder) is internal developer documentation.
