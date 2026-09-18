# Contact sheet — a urlscan.io search dashboard

Search the [urlscan.io](https://urlscan.io) archive and read the results as a wall of screenshot
frames. Each frame shows the domain, the IP that was actually contacted during that scan, the HTTP
status, how the TLS certificate looked at the time, and when the scan ran.

Python backend (Flask), plain HTML/CSS/JS frontend, no build step.

---

## How it works

The browser never talks to urlscan.io directly. It sends your query to this app, which forwards it
with the `API-Key` request header and returns a trimmed JSON payload. That means:

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
| `DNS_CACHE_MAX_ENTRIES` | `10000` | Maximum resolved domains held in each worker's memory. |
| `RATE_LIMIT_PER_MINUTE` | `30` | Backend limit per client address. |
| `RATE_LIMIT_PER_HOUR` | `400` | Backend limit per client address. |
| `TRUST_PROXY` | `false` | Read `X-Forwarded-For` for the client address. |
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
urlscan_client.py      urlscan.io client, error types, result flattening
rate_limit.py          In-memory sliding-window limiter
wsgi.py                Gunicorn entrypoint
templates/index.html   Markup
static/css/styles.css  Styles
static/js/app.js       Search, sorting, filtering, pagination, lightbox
deploy/                systemd unit and nginx example
```
