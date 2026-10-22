# Internal developer docs

For people and coding agents changing this repo. User-facing docs are `../README.md`,
`../INTEGRATION.md` and `../CHANGELOG.md`; where they disagree with the code, these docs and the
code win (drift is listed in `GOTCHAS.md`).

| Doc | Read it when you are... |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | getting oriented: module map, request flows, caching, rate limiting, key handling, CSP |
| [BACKEND.md](BACKEND.md) | touching `app.py` or any Python module: every route, validation order, error codes, config vars |
| [FRONTEND.md](FRONTEND.md) | touching `static/js/*`, `templates/index.html` or CSS: functions, globals, storage keys, DOM ids, CSS ownership |
| [DATA.md](DATA.md) | editing `database/*.csv`, `examples.js` or the test fixture: schemas, load rules, scoring constants |
| [CONVENTIONS.md](CONVENTIONS.md) | writing any code: security rules, error envelopes, JS/Python style, how tests are written and run |
| [GOTCHAS.md](GOTCHAS.md) | before debugging or "fixing" something odd: scoring constants, dual scorers, doc drift, Windows notes |

`screenshots/` exists but is currently empty (README images are hosted on GitHub).

References use `file:function` rather than line numbers. Verify against the code before relying on
a detail; these docs were checked against the working tree on 2026-10-22 (113 tests, all passing).
