"""Flatten a urlscan.io result document into what the analyzer renders.

The result API returns a deeply nested document whose shape varies with what
the scanner managed to capture: a failed request has no response, an old scan
has no verdict engines, a scan of an IP has no certificate. Every accessor here
is defensive for that reason, and every field the frontend reads is produced
exactly once, here, so the browser never has to walk the raw document.

Nothing in this module makes a network call.
"""

from __future__ import annotations

import posixpath
import re
from urllib.parse import urlsplit

from domain_intel import DomainTable, registrable_domain

# urlscan's own shorthand for a body hash is SHA-256. Other processors may
# report additional digests; we surface whichever are present.
HASH_FIELDS = (
    ("sha256", ("sha256", "hash")),
    ("sha1", ("sha1",)),
    ("md5", ("md5",)),
)

HASH_LENGTHS = {64: "sha256", 40: "sha1", 32: "md5"}

# The uuid in the document decides two urlscan.io URLs the browser will load,
# so it is re-validated here rather than trusted because the route matched.
UUID_SHAPE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

# Response headers worth showing by default. Everything else is still returned,
# just after these, so the panel can show the interesting ones first.
HEADER_PRIORITY = (
    "content-type",
    "content-length",
    "content-encoding",
    "content-disposition",
    "server",
    "location",
    "cache-control",
    "set-cookie",
    "x-powered-by",
    "strict-transport-security",
    "content-security-policy",
    "access-control-allow-origin",
)

MAX_HEADER_VALUE = 400
MAX_FILES = 1500


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _text(value) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    value = str(value).strip()
    return value or None


def _int(value) -> int | None:
    try:
        if isinstance(value, bool):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _host_of(url: str | None) -> str:
    if not url:
        return ""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _filename_of(url: str | None) -> str:
    """Last path segment, or the host for a bare root URL."""
    if not url:
        return "(no url)"
    try:
        parts = urlsplit(url)
    except ValueError:
        return url[:120]
    name = posixpath.basename(parts.path or "")
    if not name:
        return (parts.hostname or url)[:120] + ("/" if parts.path in ("", "/") else "")
    return name[:180]


def _normalise_hash(value) -> tuple[str, str] | None:
    """Return (algorithm, value) for a hex digest of a recognised length."""
    text = _text(value)
    if not text:
        return None
    text = text.strip().lower()
    algorithm = HASH_LENGTHS.get(len(text))
    if not algorithm:
        return None
    if any(char not in "0123456789abcdef" for char in text):
        return None
    return algorithm, text


def _collect_hashes(*sources) -> list[dict]:
    """Pull every recognisable digest out of the given mappings, deduped."""
    found: dict[str, str] = {}
    for source in sources:
        source = _dict(source)
        for _, keys in HASH_FIELDS:
            for key in keys:
                if key not in source:
                    continue
                pair = _normalise_hash(source.get(key))
                if pair:
                    found.setdefault(pair[0], pair[1])
    order = {"sha256": 0, "sha1": 1, "md5": 2}
    return [
        {"algorithm": algorithm, "value": value}
        for algorithm, value in sorted(found.items(), key=lambda kv: order.get(kv[0], 9))
    ]


def _shape_headers(raw) -> list[dict]:
    headers = _dict(raw)
    rows = []
    for name, value in headers.items():
        text = _text(value) or ""
        truncated = len(text) > MAX_HEADER_VALUE
        rows.append({
            "name": str(name),
            "value": text[:MAX_HEADER_VALUE] + ("…" if truncated else ""),
            "truncated": truncated,
        })

    def rank(row: dict) -> tuple[int, str]:
        lowered = row["name"].lower()
        return (
            HEADER_PRIORITY.index(lowered) if lowered in HEADER_PRIORITY else len(HEADER_PRIORITY),
            lowered,
        )

    return sorted(rows, key=rank)


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------


def _certificate(document: dict, domain: str | None) -> dict | None:
    """The certificate for the scanned host, falling back to the first one."""
    certificates = _list(_dict(document.get("lists")).get("certificates"))
    if not certificates:
        return None

    chosen = None
    if domain:
        wildcard = "*." + registrable_domain(domain)
        for entry in certificates:
            subject = (_text(_dict(entry).get("subjectName")) or "").lower()
            if subject in {domain.lower(), wildcard}:
                chosen = entry
                break
    chosen = _dict(chosen or certificates[0])

    return {
        "subject": _text(chosen.get("subjectName")),
        "issuer": _text(chosen.get("issuer")),
        "valid_from": _int(chosen.get("validFrom")),
        "valid_to": _int(chosen.get("validTo")),
        "certificate_count": len(certificates),
    }


def summarise(document: dict) -> dict:
    page = _dict(document.get("page"))
    task = _dict(document.get("task"))
    stats = _dict(document.get("stats"))
    lists = _dict(document.get("lists"))
    meta = _dict(document.get("meta"))

    uuid = _text(task.get("uuid")) or _text(document.get("_id"))
    link_uuid = uuid if uuid and UUID_SHAPE.match(uuid) else None
    domain = _text(page.get("domain"))
    apex = _text(page.get("apexDomain")) or (registrable_domain(domain) if domain else None)

    technologies = []
    for app in _list(_dict(_dict(meta.get("processors")).get("wappa")).get("data")):
        app = _dict(app)
        name = _text(app.get("app")) or _text(app.get("name"))
        if not name:
            continue
        categories = [
            _text(_dict(category).get("name")) or _text(category)
            for category in _list(app.get("categories"))
        ]
        technologies.append({
            "name": name,
            "confidence": _int(app.get("confidence")),
            "categories": [c for c in categories if c],
        })

    return {
        "uuid": uuid,
        "title": _text(page.get("title")),
        "url": _text(page.get("url")) or _text(task.get("url")),
        "submitted_url": _text(task.get("url")),
        "domain": domain,
        "apex_domain": apex,
        "ip": _text(page.get("ip")),
        "ptr": _text(page.get("ptr")),
        "asn": _text(page.get("asn")),
        "asn_name": _text(page.get("asnname")),
        "country": _text(page.get("country")),
        "city": _text(page.get("city")),
        "server": _text(page.get("server")),
        "status": _int(page.get("status")) or _text(page.get("status")),
        "mime_type": _text(page.get("mimeType")),
        "umbrella_rank": _int(page.get("umbrellaRank")),
        "redirected": _text(page.get("redirected")),
        "scan_time": _text(task.get("time")),
        "visibility": _text(task.get("visibility")),
        "method": _text(task.get("method")),
        "source": _text(task.get("source")),
        "tags": [t for t in (_text(tag) for tag in _list(task.get("tags"))) if t],
        "report_url": f"https://urlscan.io/result/{link_uuid}/" if link_uuid else None,
        "screenshot_url": f"https://urlscan.io/screenshots/{link_uuid}.png" if link_uuid else None,
        "tls": {
            "issuer": _text(page.get("tlsIssuer")),
            "valid_days": _int(page.get("tlsValidDays")),
            "age_days": _int(page.get("tlsAgeDays")),
            "certificate": _certificate(document, domain),
        },
        "counts": {
            "requests": len(_list(_dict(document.get("data")).get("requests"))),
            "ips": len(_list(lists.get("ips"))),
            "countries": len(_list(lists.get("countries"))),
            "domains": len(_list(lists.get("domains"))),
            "asns": len(_list(lists.get("asns"))),
            "servers": len(_list(lists.get("servers"))),
            "urls": len(_list(lists.get("urls"))),
            "links": _int(stats.get("totalLinks")) or len(_list(_dict(document.get("data")).get("links"))),
            "cookies": len(_list(_dict(document.get("data")).get("cookies"))),
            "console_messages": len(_list(_dict(document.get("data")).get("console"))),
            "ads_blocked": _int(stats.get("adBlocked")) or 0,
            "malicious_requests": _int(stats.get("malicious")) or 0,
            "secure_requests": _int(stats.get("secureRequests")),
            "secure_percentage": _int(stats.get("securePercentage")),
            "ipv6_percentage": _int(stats.get("IPv6Percentage")),
            "unique_countries": _int(stats.get("uniqCountries")),
            "transfer_bytes": sum(
                _int(_dict(entry).get("encodedSize")) or 0
                for entry in _list(stats.get("resourceStats"))
            ),
        },
        "technologies": technologies[:24],
        "countries": [c for c in (_text(v) for v in _list(lists.get("countries"))) if c],
    }


def _engine_rows(engines: dict) -> list[dict]:
    """One row per engine that expressed an opinion."""
    rows: dict[str, dict] = {}

    for entry in _list(engines.get("verdicts")):
        entry = _dict(entry)
        name = _text(entry.get("engine"))
        if not name:
            continue
        categories = [c for c in (_text(v) for v in _list(entry.get("categories"))) if c]
        rows[name.lower()] = {
            "engine": name,
            "malicious": bool(entry.get("malicious")),
            "score": _int(entry.get("score")),
            "categories": categories,
            "verdict": "malicious" if entry.get("malicious") else "benign",
        }

    # Older scans only carry the name lists, with no per-engine detail.
    for name in (_text(v) for v in _list(engines.get("malicious"))):
        if name and name.lower() not in rows:
            rows[name.lower()] = {
                "engine": name, "malicious": True, "score": None,
                "categories": [], "verdict": "malicious",
            }
    for name in (_text(v) for v in _list(engines.get("benign"))):
        if name and name.lower() not in rows:
            rows[name.lower()] = {
                "engine": name, "malicious": False, "score": None,
                "categories": [], "verdict": "benign",
            }

    return sorted(rows.values(), key=lambda row: (not row["malicious"], row["engine"].lower()))


def shape_verdicts(document: dict) -> dict:
    verdicts = _dict(document.get("verdicts"))
    overall = _dict(verdicts.get("overall"))
    urlscan = _dict(verdicts.get("urlscan"))
    engines = _dict(verdicts.get("engines"))
    community = _dict(verdicts.get("community"))

    def strings(source: dict, key: str) -> list[str]:
        return [v for v in (_text(item) for item in _list(source.get(key))) if v]

    engine_rows = _engine_rows(engines)
    malicious_engines = sum(1 for row in engine_rows if row["malicious"])
    engines_total = _int(engines.get("enginesTotal")) or len(engine_rows)

    overall_score = _int(overall.get("score"))
    urlscan_score = _int(urlscan.get("score"))
    engines_score = _int(engines.get("score"))
    community_score = _int(community.get("score"))

    # urlscan's own scores already run 0-100. Take the strongest opinion on
    # record rather than averaging, so one confident engine is not diluted by
    # the silence of the others, and add a floor for engine consensus.
    candidates = [score for score in (overall_score, urlscan_score, engines_score, community_score)
                  if isinstance(score, int)]
    threat_score = max(candidates) if candidates else 0
    if engines_total and malicious_engines:
        consensus = round(100 * malicious_engines / engines_total)
        threat_score = max(threat_score, min(100, consensus))
    threat_score = max(0, min(100, threat_score))

    malicious = bool(overall.get("malicious") or urlscan.get("malicious") or malicious_engines)
    if malicious:
        threat_score = max(threat_score, 60)

    if threat_score >= 70 or malicious:
        band = "malicious"
    elif threat_score >= 30:
        band = "suspicious"
    elif threat_score > 0:
        band = "low"
    else:
        band = "clean"

    return {
        "threat_score": threat_score,
        "band": band,
        "malicious": malicious,
        "has_verdicts": bool(_int(overall.get("hasVerdicts")) or engine_rows or community_score),
        "overall": {
            "score": overall_score,
            "malicious": bool(overall.get("malicious")),
            "categories": strings(overall, "categories"),
            "brands": [
                _text(_dict(brand).get("name")) or _text(brand)
                for brand in _list(overall.get("brands"))
            ],
            "tags": strings(overall, "tags"),
        },
        "urlscan": {
            "score": urlscan_score,
            "malicious": bool(urlscan.get("malicious")),
            "categories": strings(urlscan, "categories"),
            "tags": strings(urlscan, "tags"),
            "brands": [
                _text(_dict(brand).get("name")) or _text(brand)
                for brand in _list(urlscan.get("brands"))
            ],
            "detection_details": strings(urlscan, "detectionDetails"),
        },
        "engines": {
            "score": engines_score,
            "malicious_total": _int(engines.get("maliciousTotal")) or malicious_engines,
            "benign_total": _int(engines.get("benignTotal")) or sum(
                1 for row in engine_rows if not row["malicious"]
            ),
            "engines_total": engines_total,
            "rows": engine_rows,
        },
        "community": {
            "score": community_score,
            "malicious": bool(community.get("malicious")),
            "votes_total": _int(community.get("votesTotal")) or 0,
            "votes_malicious": _int(community.get("votesMalicious")) or 0,
            "votes_benign": _int(community.get("votesBenign")) or 0,
        },
    }


def _download_index(document: dict) -> dict[str, dict]:
    """Downloads processor entries, keyed by every digest they report."""
    index: dict[str, dict] = {}
    entries = _list(_dict(_dict(_dict(document.get("meta")).get("processors")).get("download")).get("data"))
    for entry in entries:
        entry = _dict(entry)
        for pair in _collect_hashes(entry):
            index[pair["value"]] = entry
    return index


def shape_files(document: dict, table: DomainTable, apex: str | None) -> list[dict]:
    requests = _list(_dict(document.get("data")).get("requests"))
    downloads = _download_index(document)
    files: list[dict] = []

    for position, entry in enumerate(requests[:MAX_FILES], start=1):
        entry = _dict(entry)
        request_wrapper = _dict(entry.get("request"))
        request = _dict(request_wrapper.get("request"))
        response_wrapper = _dict(entry.get("response"))
        response = _dict(response_wrapper.get("response"))

        url = (
            _text(response.get("url"))
            or _text(request.get("url"))
            or _text(request_wrapper.get("documentURL"))
        )
        host = _host_of(url)
        try:
            path = urlsplit(url or "").path or ""
        except ValueError:
            path = ""

        classification = table.classify(host, path, apex)

        hashes = _collect_hashes(response_wrapper, entry)
        download = None
        for item in hashes:
            if item["value"] in downloads:
                download = _dict(downloads[item["value"]])
                break
        if download:
            hashes = _collect_hashes(response_wrapper, entry, download) or hashes

        size = (
            _int(response_wrapper.get("size"))
            or _int(response_wrapper.get("dataLength"))
            or _int(response_wrapper.get("encodedDataLength"))
            or _int(response.get("encodedDataLength"))
        )

        geoip = _dict(response_wrapper.get("geoip"))
        asn = _dict(response_wrapper.get("asn"))
        failure = _text(response_wrapper.get("failed")) or _text(_dict(response_wrapper.get("failed")).get("errorText"))

        mime = _text(response.get("mimeType")) or _text(response_wrapper.get("mimeType"))
        status = _int(response.get("status"))

        files.append({
            "index": position,
            "url": url,
            "filename": _text(download.get("filename")) if download else _filename_of(url),
            "domain": host or None,
            "apex_domain": classification["apex"] or None,
            "is_first_party": classification["is_first_party"],
            "category": classification["category"],
            "category_label": classification["category_label"],
            "service": classification["service"],
            "mime_type": mime,
            "resource_type": _text(request_wrapper.get("type")) or _text(entry.get("type")),
            "method": _text(request.get("method")),
            "status": status,
            "status_text": _text(response.get("statusText")),
            "size_bytes": size,
            "protocol": _text(response.get("protocol")),
            "ip": _text(response.get("remoteIPAddress")) or _text(response_wrapper.get("remoteIPAddress")),
            "country": _text(geoip.get("country_name")) or _text(geoip.get("country")),
            "country_code": _text(geoip.get("country")),
            "asn": _text(asn.get("asn")),
            "asn_name": _text(asn.get("name")) or _text(asn.get("description")),
            "hashes": hashes,
            "from_download_processor": download is not None,
            "failed": bool(failure),
            "error": failure,
            "initiator": _text(_dict(request_wrapper.get("initiator")).get("type")),
            "initiator_url": _text(_dict(request_wrapper.get("initiator")).get("url")),
            "headers": _shape_headers(response.get("headers")),
            "request_headers": _shape_headers(request.get("headers")),
            "security_state": _text(response.get("securityState")),
        })

    return files


def shape_domains(document: dict, table: DomainTable, apex: str | None) -> list[dict]:
    stats = _dict(document.get("stats"))
    domain_stats = _list(stats.get("domainStats"))

    # Country per IP, so a domain can report where it was actually reached.
    ip_country: dict[str, dict] = {}
    for entry in _list(stats.get("ipStats")):
        entry = _dict(entry)
        ip = _text(entry.get("ip"))
        if not ip:
            continue
        geoip = _dict(entry.get("geoip"))
        asn = _dict(entry.get("asn"))
        ip_country[ip] = {
            "country": _text(geoip.get("country_name")) or _text(geoip.get("country")),
            "country_code": _text(geoip.get("country")),
            "asn": _text(asn.get("asn")),
            "asn_name": _text(asn.get("name")) or _text(asn.get("description")),
        }

    rows = []
    for entry in domain_stats:
        entry = _dict(entry)
        domain = _text(entry.get("domain"))
        if not domain:
            continue
        ips = [ip for ip in (_text(v) for v in _list(entry.get("ips"))) if ip]
        countries = [c for c in (_text(v) for v in _list(entry.get("countries"))) if c]
        geo = ip_country.get(ips[0], {}) if ips else {}
        classification = table.classify(domain, "", apex)

        rows.append({
            "domain": domain,
            "apex_domain": classification["apex"] or None,
            "requests": _int(entry.get("count")) or 0,
            "size_bytes": _int(entry.get("size")) or 0,
            "encoded_bytes": _int(entry.get("encodedSize")) or 0,
            "ips": ips,
            "countries": countries or ([geo.get("country_code")] if geo.get("country_code") else []),
            "country": geo.get("country") or (countries[0] if countries else None),
            "country_code": geo.get("country_code") or (countries[0] if countries else None),
            "asn": geo.get("asn"),
            "asn_name": geo.get("asn_name"),
            "category": classification["category"],
            "category_label": classification["category_label"],
            "service": classification["service"],
            "is_first_party": classification["is_first_party"],
            "initiators": [i for i in (_text(v) for v in _list(entry.get("initiators"))) if i],
            "redirects": _int(entry.get("redirects")) or 0,
        })

    rows.sort(key=lambda row: (-row["requests"], row["domain"]))
    return rows


def shape_result(document: dict, table: DomainTable) -> dict:
    """Full analyzer payload for one scan."""
    summary = summarise(document)
    apex = summary.get("apex_domain")
    files = shape_files(document, table, apex)
    domains = shape_domains(document, table, apex)

    hash_count = sum(1 for item in files if item["hashes"])
    first_party_files = sum(1 for item in files if item["is_first_party"])

    return {
        "summary": summary,
        "verdicts": shape_verdicts(document),
        "files": files,
        "domains": domains,
        "file_stats": {
            "total": len(files),
            "first_party": first_party_files,
            "third_party": len(files) - first_party_files,
            "with_hashes": hash_count,
            "failed": sum(1 for item in files if item["failed"]),
            "truncated": max(0, len(_list(_dict(document.get("data")).get("requests"))) - len(files)),
            "total_bytes": sum(item["size_bytes"] or 0 for item in files),
        },
        "domain_stats": {
            "total": len(domains),
            "third_party": sum(1 for row in domains if not row["is_first_party"]),
            "categories": _category_totals(domains),
        },
    }


def _category_totals(domains: list[dict]) -> list[dict]:
    totals: dict[str, dict] = {}
    for row in domains:
        bucket = totals.setdefault(
            row["category"],
            {
                "category": row["category"],
                "category_label": row["category_label"],
                "domains": 0,
                "requests": 0,
            },
        )
        bucket["domains"] += 1
        bucket["requests"] += row["requests"]
    return sorted(totals.values(), key=lambda row: (-row["requests"], row["category"]))
