# Contact sheet — a urlscan.io search dashboard

Search the [urlscan.io](https://urlscan.io) archive and read the results as a wall of screenshot
frames. Each frame shows the domain, the IP that was actually contacted during that scan, the HTTP
status, how the TLS certificate looked at the time, and when the scan ran.

Click **Analyze result** on any frame and a second dashboard opens over the sheet: the full scan
record for that one result — every resource it fetched with their hashes, every domain it talked to,
the security-engine verdicts, and a keyword risk score for the page's own text.

Python backend (Flask), plain HTML/CSS/JS frontend, no build step.

---

## How it works

The browser sends urlscan requests to this app, which forwards them with the `API-Key` request header
and returns a trimmed JSON payload. DOM extraction and keyword scoring run in the browser. Optional
live DNS status uses Cloudflare DNS-over-HTTPS and never sends the urlscan key. That means:

- the key is never in a URL, so it cannot leak through proxy logs, browser history or `Referer`
- the browser only ever fetches same-origin, so the Content-Security-Policy can stay strict
- rate limiting and input validation happen somewhere a user cannot bypass

### Notes on the data

**IP addresses come from the scan record, not a live lookup.** The `page.ip` field is the address
urlscan actually contacted at scan time. Resolving the domain now would often give a different
answer — which is exactly the wrong answer when you are looking at a scan from eight months ago.

**Pagination is cursor-based.** urlscan does not take a page number or an offset. Each result carries
a `sort` array; to get the next page you send the `sort` array of the last (oldest) result back as
`search_after`. The backend builds that cursor and returns it as `meta.next_cursor`; the frontend
sends it back when you press "Load the next page".

**`total` is exact only up to 10,000.** Past that, urlscan stops counting precisely and sets
`has_more: true`. The status line says "more than N matches" in that case rather than pretending to a
number it does not have.

**Domain links go to the urlscan report, not to the scanned site.** A lot of what is in this archive
is phishing and malware. The scanned URL is shown as plain, unlinked text in the enlarged view so you
can copy it deliberately rather than click it by accident.

---

## Quick start

You need an API key from <https://urlscan.io/user/profile>. The free tier is enough to try this.

```bash
git clone <your-repo> urlscan-dashboard
cd urlscan-dashboard
./run.sh
```

Open <http://127.0.0.1:8000>, paste your key into the field at the top right, and search.

`run.sh` creates a virtualenv, installs dependencies, copies `.env.example` to `.env` on first run,
and starts gunicorn.

### Manual setup

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
gunicorn -c gunicorn.conf.py wsgi:application
```

For a development server with reload instead: `DEBUG=true python3 app.py`.

---

## Configuration

All settings are environment variables; `.env` is read automatically if `python-dotenv` is installed.

| Variable | Default | What it does |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address. Use `0.0.0.0` only if nothing is proxying in front. |
| `PORT` | `8000` | Bind port. |
| `DEBUG` | `false` | Flask debug mode. Never enable in production. |
| `URLSCAN_API_KEY` | unset | Optional shared key. If unset, each user supplies their own. |
| `FORCE_SERVER_KEY` | `false` | Ignore browser-supplied keys and always use `URLSCAN_API_KEY`. |
| `URLSCAN_BASE_URL` | `https://urlscan.io/api/v1` | Override for testing. |
| `REQUEST_TIMEOUT` | `30` | Seconds to wait on urlscan.io. |
| `RATE_LIMIT_PER_MINUTE` | `30` | Backend limit per client address. |
| `RATE_LIMIT_PER_HOUR` | `400` | Backend limit per client address. |
| `TRUST_PROXY` | `false` | Read `X-Forwarded-For` for the client address. |
| `MAX_DOM_BYTES` | `4194304` | Refuse to download a stored DOM larger than this. |
| `RESULT_CACHE_TTL` | `600` | Seconds a fetched result stays in server memory. `0` disables it. |
| `RESULT_CACHE_MAX_ENTRIES` | `64` | Cached results per worker. |
| `KEYWORD_DB_PATH` | `database/crypto_scam_keywords.csv` | Risk keyword database. |
| `DOMAIN_TABLE_PATH` | `database/domain_categories.csv` | Third-party domain classification table. |
| `URLSCAN_SITE_URL` | `https://urlscan.io` | Where stored DOMs are fetched from. |
| `WEB_CONCURRENCY` / `WEB_THREADS` | `4` / `4` | Gunicorn workers and threads. |

**Two ways to run this.** Leave `URLSCAN_API_KEY` unset for a shared instance where every analyst
pastes their own key and spends their own quota — that is the better default. Set it, plus
`FORCE_SERVER_KEY=true`, for a single-team instance where one account pays for everything; then the
key field disappears from the workflow entirely.

**`TRUST_PROXY` matters.** Turn it on only behind a proxy you control that overwrites
`X-Forwarded-For`. Turn it on while directly exposed and anyone can forge the header and walk past the
rate limiter.

---

## Deploying on Linux with systemd

```bash
sudo useradd --system --home /opt/urlscan-dashboard --shell /usr/sbin/nologin urlscan
sudo mkdir -p /opt/urlscan-dashboard
sudo cp -r . /opt/urlscan-dashboard
cd /opt/urlscan-dashboard

sudo -u urlscan python3 -m venv venv
sudo -u urlscan venv/bin/pip install -r requirements.txt

# Secrets live here, not in the unit file.
sudo cp .env.example /etc/urlscan-dashboard.env
sudo chown root:urlscan /etc/urlscan-dashboard.env
sudo chmod 640 /etc/urlscan-dashboard.env
sudo nano /etc/urlscan-dashboard.env

sudo chown -R urlscan:urlscan /opt/urlscan-dashboard
sudo cp deploy/urlscan-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now urlscan-dashboard
sudo systemctl status urlscan-dashboard
```

Logs: `journalctl -u urlscan-dashboard -f`

### Putting it on a website

`deploy/nginx.conf.example` is a working reverse-proxy config. Edit the hostname, then:

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
sudo cp deploy/nginx.conf.example /etc/nginx/sites-available/urlscan-dashboard
sudo ln -s /etc/nginx/sites-available/urlscan-dashboard /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d scans.example.com
```

Then set `TRUST_PROXY=true` and keep `HOST=127.0.0.1` so gunicorn is not reachable except through
nginx.

**Serve this over HTTPS.** Users type an API key into it. Over plain HTTP that key crosses the network
in cleartext on every single search.

### Docker

```bash
cp .env.example .env
docker compose up -d --build
docker compose logs -f
```

The container runs as a non-root user with a read-only filesystem and all capabilities dropped, and
publishes only on `127.0.0.1:8000` — put nginx in front of it the same way.

---

## Using it

**Queries** use Elasticsearch query string syntax:

| Query | Finds |
|---|---|
| `page.domain:example.com` | Scans of that exact domain |
| `page.domain:*.example.com` | Subdomains |
| `page.ip:"203.0.113.10"` | Everything seen on one address |
| `page.asnname:cloudflare AND page.status:200` | Live pages behind one network |
| `task.tags:phishing AND date:>now-7d` | Recently tagged phishing |
| `page.tlsIssuer:"Let's Encrypt"` | By certificate issuer |

Full field list: <https://urlscan.io/docs/search/>

**Results per page** goes up to 10,000, urlscan's hard ceiling for one request. Large sizes pull a lot
of screenshots, so start at 100 and work up.

**Frames per row** switches between 4, 6 and 10 columns. At 10 the field labels drop away and the
frames tighten up for fast scanning; the layout collapses further on narrow screens regardless.

**Order** and **Filter these results** both work on the frames already loaded, client-side, with no
extra API calls. To sort across the whole result set instead, put the constraint in the query.

**Check quota** reads `/api/v1/quotas` and reports how many searches your key has left this minute,
hour and day. urlscan meters each action type separately, so a search quota and a scan-submission
quota are different budgets.

---

## The result analyzer

A search tells you a scan exists. The analyzer tells you what happened during it.

Open it from **Analyze result** on any frame, or from **Open result analyzer** in the status bar if
you already have a scan ID. It is a panel over the same page, not a separate app, so the key, the
search state and the back button all still work. Every section collapses.

### Result summary

Title, domain, IP, ASN, reverse DNS, server, HTTP status, content type, location, scan date,
visibility, certificate issuer and remaining validity, and whatever technology urlscan fingerprinted.
Values that get pasted into tickets — domain, IP, ASN, certificate subject, the URL — have a copy
button. Underneath are the scan-wide counts: requests, domains, unique IPs, countries, networks,
bytes transferred, links, cookies, ad requests blocked.

The scanned URL is shown as unlinked text, deliberately. So are the resource URLs in the file table.
This archive is full of live phishing kits and malware droppers; nothing in this panel is one
mis-click away from loading in your browser.

### Files and resources

Every request the scan recorded: filename, content type, size, HTTP status, source domain, and the
hashes urlscan stored for the body. Failed and blocked requests are kept and marked rather than
dropped, because "the page tried to load Stripe and something blocked it" is a finding.

- **Filter** searches filenames, URLs, domains, types and hashes at once.
- **Order** includes *Hash (groups identical files)*, which puts byte-identical resources next to
  each other — the quick way to see one file served from four different CDNs.
- **Show only apex domain files** hides everything that is not on the scanned site's registrable
  domain, so the ads, analytics and CDN noise drops away and the site's own code is left.
- **Clicking a filename** opens a detail panel: response and request headers, the network facts,
  the classification, the hashes, and a content snippet where one exists.
- **Clicking a domain** runs `page.domain:"…"` back in the contact sheet.

**On content snippets.** urlscan's result API does not return response bodies, so there is no
snippet to show for a script or an image — the panel says so rather than showing an empty box. The
main document is the exception: its text comes from the stored DOM once you have run the content
analysis.

### Hashes

Each resource shows its stored digests as separate badges — SHA-256 always, SHA-1 and MD5 when
urlscan's download processor recorded them. Badges are truncated to 12 characters, with the full
value on hover and a copy button on each.

Clicking a hash opens a side panel that searches the urlscan corpus for `hash:<value>` and lists the
other scans that fetched the same bytes: date, domain, URL, status, and a **View details** button
that loads that scan into this analyzer. That is the correlation move — the same dropper on nine
domains, or the same phishing kit reskinned. The panel also offers **Search this hash in the
dashboard**, which pivots the main grid to that query. Once a hash has been looked up, its badge
carries the number of scans that have seen it.

**On "flagged as malicious".** This dashboard does not query VirusTotal or any other malware
database, so it never labels a hash malicious — a claim like that with nothing behind it is worse
than no claim. The hash panel links out to VirusTotal and MalwareBazaar for that file so you can
check deliberately, and says plainly that absence from those services is not evidence of safety.
Corpus prevalence is shown as what it is: a count, not a verdict.

### Domains and connections

Every domain the page contacted, ranked by request count, with type, country, network and bytes.
Types come from `database/domain_categories.csv`, a local table of about 180 patterns covering
analytics, advertising, trackers, CDNs, fonts, CAPTCHA, social, live chat, payments, crypto services,
site platforms and hosting. It is a plain CSV; add your own rows.

A pattern matches a host when the host equals it or ends with `.` + the pattern, so `cloudfront.net`
covers `d1abc.cloudfront.net` and never `notcloudfront.net`. Patterns with a slash
(`google.com/recaptcha`) match against host plus path. Anything unmatched is reported as
**Unclassified** rather than guessed at.

Clicking a domain pivots the main dashboard to it; **show its files** filters the table above
instead, without leaving the panel.

### Security engines and threat score

urlscan's verdicts, laid out: the overall score, its own classifier, the engines it queries, and
community votes, with each engine's own verdict and categories as a card.

The **threat score** is the strongest opinion on record rather than an average, floored by engine
consensus — one confident detection should not be diluted by the engines that stayed silent. Bands
are clean / low / suspicious / malicious, and every colour is paired with the word, never used alone.

When nothing has an opinion the panel says so explicitly. No verdict is not a clean bill of health;
most scans are never reviewed by anything.

---

## Content analysis and risk scoring

**Analyze page content** fetches the DOM urlscan stored for the scan, strips scripts, styles and
markup, and scores the visible text against `database/crypto_scam_keywords.csv` — 507 keywords in 22
categories, each with a weight from 1 to 5.

Matching is case-insensitive and boundary-aware. `pass` does not match inside `password`, and phrases
that start or end in punctuation (`3% daily`, `100% safe`, `gh/s plan`) still match, which a plain
`\b` word boundary would not manage. Curly apostrophes are normalised first, so `don't miss out`
matches however the page typed it.

### How the score is calculated

```
points = Σ over distinct keywords of  tier_value(weight) × repeat_bonus
score  = 100 × (1 − e^(−points / 4)) × breadth
```

| Weight | Meaning | Contributes |
|---|---|---|
| 1 | topic vocabulary — `bitcoin`, `blockchain`, `apy` | **nothing** |
| 2 | low | 0.2 |
| 3 | moderate | 0.5 |
| 4 | high | 1.0 |
| 5 | severe | 1.25 |

Four decisions worth knowing about, because they are what make the number usable:

**Weight-1 rows never score.** They are what the page is *about*, not what is wrong with it. A
regulated exchange's homepage is full of them. They are counted and reported as context, and kept out
of the arithmetic.

**Distinct keywords, not occurrences.** "Guaranteed profit" said once is the signal; said forty times
it is the same signal, louder. Repetition adds at most 40% of a keyword's value back, and stops
counting after five occurrences.

**Page length is not an input.** A promise of fixed daily returns means the same thing on a 60-word
splash page and a 6,000-word one. Dividing by word count — the obvious approach — turns every short
page into a false positive and lets a long one bury its claims in filler.

**Breadth matters.** The multiplier runs from 0.55 to 1.0 as matches spread across five or more
categories. Real investment fraud promises yields *and* presses for deposits *and* manufactures
urgency *and* fabricates endorsements. One category on its own is usually vocabulary.

### What the numbers look like

Measured against the shipped database:

| Page | Score | Band |
|---|---|---|
| Retail bank homepage | 0 | minimal |
| Neutral article about crypto staking | 8 | minimal |
| Mild cloud-mining marketing | 12 | minimal |
| Regulated exchange homepage (mentions seed phrases, staking rewards) | 19 | low |
| Short HYIP pitch | 90 | high |
| Full fake cloud-mining site | 100 | high |

Bands: minimal under 15, low 15–39, elevated 40–69, high 70+.

### Reading the output

The panel shows the score, the signal points behind it, the words analysed, the category breadth and
the multiplier, then two charts — weighted share by category, and the distribution of matched
keywords by severity — then the matched keywords themselves, strongest first, each with the sentence
it appeared in. The full extracted text sits in a collapsible block below, and can be copied.

Showing the quote next to every match is the point. The score is an index into the page, not a
verdict on it, and two minutes reading the excerpts settles most cases.

### What it cannot do

- It reads the DOM urlscan captured, not the page as it is now, and not content rendered after
  capture. A page that builds itself from script after load may analyse as nearly empty.
- It is a crypto-investment-fraud vocabulary. It knows nothing about credential phishing, tech
  support scams or malware distribution unless they happen to use the same words.
- It cannot read intent. A news article about a scam, a regulator's warning page and a security
  vendor's write-up all use the vocabulary of the thing they are describing.
- A low score is not a clean bill of health. Non-English pages, image-only pages and unknown scam
  patterns all score low for reasons that have nothing to do with being safe.

Every response carries that caveat, and the UI prints it under every score.

---

## Tests

Fixture-driven, no network and no API key:

```bash
python3 -m unittest discover -s tests -v
```

`tests/test_analyzer.py` covers text extraction, scoring behaviour and calibration, domain
classification and result shaping — including a deliberately awkward fixture with a failed request, a
request with no response at all, a malformed hash and a download with three digests.
`tests/test_routes.py` covers the endpoints with urlscan.io stubbed out: validation, error mapping,
per-key caching and rate limiting.

For frontend work without spending API credits:

```bash
python3 tests/stub_server.py 8010
```

That serves the whole dashboard against canned data. Any key-shaped string is accepted.

---

## Security

- The API key is used for the duration of one request and never written to disk. The log formatter
  drops query strings, and a scrubbing filter masks anything UUID-shaped that reaches a log line.
- Responses under `/api/` are sent `Cache-Control: no-store` so a shared proxy cannot serve one
  analyst's results to another.
- CSP allows scripts and styles from this origin only, and images from this origin plus urlscan.io.
  There is no inline JavaScript anywhere, so the policy needs no `unsafe-inline` escape hatch.
- Queries, page sizes and pagination cursors are validated server-side; the browser's checks are a
  convenience, not the control.
- The built-in rate limiter is per-process and in-memory. With four workers the real ceiling is four
  times the configured number. That is enough to stop casual abuse of a small team instance. If this
  is public, put a limit in nginx too, or move the counters into Redis.

For the analyzer specifically:

- **Everything it renders came from a scanned page, so it is treated as hostile.** Nodes are built
  with `createElement` and filled with `textContent`; there is no `innerHTML` anywhere in the
  frontend. A title of `<img src=x onerror=…>` renders as those characters.
- **Resource URLs are never turned into links.** Filenames open the detail panel; the URL is text
  with a copy button beside it.
- **Scan IDs are validated as UUIDs** before any upstream request, both in the route and again in the
  shaper, which builds the two urlscan.io URLs the browser loads.
- **The stored DOM is streamed with a hard ceiling** (`MAX_DOM_BYTES`). Page content is
  attacker-controlled and unbounded; the fetch aborts rather than filling memory.
- **Cached results are scoped to a digest of the key that fetched them**, so two analysts sharing one
  instance cannot read each other's private scans out of the cache. Switching or forgetting the key
  clears the browser-side cache too.
- **Content analysis has its own rate limit** on top of the shared one, because it fetches and parses
  a whole document per call.

### The localStorage option

Ticking "Keep this key in this browser" writes the key to `localStorage`. It survives a reload, and it
is readable by any JavaScript running on the page and by anyone who can get at the browser profile on
disk. On your own workstation that is a reasonable trade. On a shared or untrusted machine, leave it
off — "Forget" clears both the field and the stored copy.

---

## API

| Endpoint | Purpose |
|---|---|
| `GET /` | The dashboard |
| `GET /api/health` | Liveness check |
| `GET /api/config` | Allowed page sizes and whether a server key is configured |
| `GET /api/search?q=&size=&search_after=` | Proxied search |
| `GET /api/quotas` | Remaining search quota for the key |
| `GET /api/result/<uuid>` | Full scan result, flattened into summary / files / domains / verdicts |
| `GET /api/dom/<uuid>` | Fetches the stored DOM for browser-side extraction and scoring |
| `GET /api/keywords` | What is in the keyword database, by category |

Send the key as `X-URLScan-Key` on the request unless the server holds its own.

```bash
curl -s 'http://127.0.0.1:8000/api/search?q=page.domain:example.com&size=10' \
     -H "X-URLScan-Key: $URLSCAN_API_KEY" | jq '.meta'
```

Errors come back as `{"ok": false, "error": {"code": "...", "message": "..."}}`. Codes worth handling:
`missing_api_key`, `invalid_api_key`, `invalid_query`, `rate_limited` (urlscan's quota),
`local_rate_limited` (this server's limit), `network_error`.

## Layout

```
app.py                 Flask routes, validation, security headers
config.py              Environment configuration
urlscan_client.py      urlscan.io client, error types, search-result flattening
result_shaper.py       Turns one result document into the analyzer's payload
keyword_db.py          Keyword database, HTML-to-text, risk scoring
domain_intel.py        Third-party domain classification
rate_limit.py          In-memory sliding-window limiter
wsgi.py                Gunicorn entrypoint
templates/index.html   Markup for both dashboards
static/css/styles.css  Contact sheet styles
static/css/analyzer.css  Analyzer styles
static/js/app.js       Search, sorting, filtering, pagination, lightbox
static/js/analyzer.js  The result analyzer
database/              Keyword database and domain classification table (both CSV, both editable)
tests/                 Fixture-driven tests and a stub server for UI work
deploy/                systemd unit and nginx example
INTEGRATION.md         How the two dashboards connect, and the endpoint contracts
```
