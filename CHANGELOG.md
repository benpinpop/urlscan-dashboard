# Changelog

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
