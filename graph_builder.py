"""TitanEye graph model: node ids, expansion transforms and result shaping.

The browser never sends a raw urlscan field name. It sends a transform id and
a value; this module checks the value against the node type and builds the
query from a fixed table, so a hostile node label cannot add clauses.
See docs/TITANEYE.md for the node/edge contract.
"""

from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from domain_intel import registrable_domain
from wallet_validation import CHAINS, detect_chain, validate_wallet

MAX_VALUE_LENGTH = 300
MAX_SCANS_PER_SITE = 5

NODE_TYPES = (
    "site", "apex_domain", "ip", "cidr", "asn", "ptr", "tls_cert", "file_hash",
    "filename", "text_string", "third_party", "tech", "brand", "contact",
    "wallet", "tag", "case",
)

EDGE_TYPES = (
    "hosted_on", "resolves_to", "same_apex", "uses_cert", "serves_file",
    "contains_text", "loads_third_party", "uses_tech", "impersonates",
    "links_to_contact", "pays_to", "tagged", "redirects_to", "uploaded_link",
    "analyst_link",
)

_UNSAFE = re.compile(r'[\x00-\x1f\x7f"\\]')
_HOST = re.compile(r"^[a-z0-9]([a-z0-9._-]{0,251}[a-z0-9])?$")
_ASN = re.compile(r"^AS\d{1,10}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HANDLE = re.compile(r"^[A-Za-z0-9_]{3,64}$")


class GraphInputError(ValueError):
    """A value that does not fit the node type it was sent for."""


# -- value checks: each returns the canonical value or raises ----------------


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise GraphInputError("That is not a valid IP address.")


def _cidr(value: str) -> str:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise GraphInputError("That is not a valid CIDR range.")
    floor = 16 if net.version == 4 else 48
    if net.prefixlen < floor:
        raise GraphInputError(f"CIDR ranges larger than /{floor} are not allowed.")
    return str(net)


def _host(value: str) -> str:
    value = value.lower().rstrip(".")
    if not _HOST.match(value):
        raise GraphInputError("That is not a valid hostname.")
    return value


def _asn(value: str) -> str:
    value = value.upper()
    if value.isdigit():
        value = "AS" + value
    if not _ASN.match(value):
        raise GraphInputError("That is not a valid AS number, for example AS15169.")
    return value


def _sha256(value: str) -> str:
    value = value.lower()
    if not _SHA256.match(value):
        raise GraphInputError("Hashes must be 64 hex characters (SHA-256).")
    return value


def _handle(value: str) -> str:
    value = value.lstrip("@")
    if not _HANDLE.match(value):
        raise GraphInputError("Handles are 3-64 letters, digits or underscores.")
    return value


def _wallet(value: str) -> str:
    detection = detect_chain(value)
    chain = detection.chain
    if not chain:
        raise GraphInputError("That does not look like a supported wallet address.")
    check = validate_wallet(chain, value)
    if not check.valid:
        raise GraphInputError("That wallet address failed validation.")
    return check.canonical


def _text(value: str) -> str:
    if _UNSAFE.search(value):
        raise GraphInputError("That value contains quotes, backslashes or control characters.")
    return value


def _query(value: str) -> str:
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", value):
        raise GraphInputError("The query contains characters that are not allowed.")
    return value


_CHECKS = {
    "ip": _ip, "cidr": _cidr, "apex_domain": _host, "third_party": _host,
    "ptr": _host, "asn": _asn, "file_hash": _sha256, "contact": _handle,
    "wallet": _wallet, "filename": _text, "text_string": _text,
    "tls_cert": _text, "tech": _text, "brand": _text, "tag": _text,
    "query": _query,
}


def canonical_value(node_type: str, value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise GraphInputError("Enter a value.")
    if len(value) > MAX_VALUE_LENGTH:
        raise GraphInputError("That value is too long.")
    return _CHECKS[node_type](value)


def node_id(node_type: str, value: str) -> str:
    return f"{node_type}:{value}"


def edge_id(source: str, relation: str, target: str) -> str:
    return f"{source}|{relation}|{target}"


# -- transforms ---------------------------------------------------------------


@dataclass(frozen=True)
class Transform:
    id: str
    label: str
    node_type: str
    field: str
    template: str
    plan: str
    relation: str  # edge from each returned site to the seed node


# Every ``field`` here must exist in database/query_terms.csv (a test checks).
TRANSFORMS: tuple[Transform, ...] = (
    Transform("ip_sites", "Sites on this IP", "ip", "page.ip", "page.ip:{v}", "free", "resolves_to"),
    Transform("ip_contacted", "Scans that contacted this IP", "ip", "ip", "ip:{v}", "free", "resolves_to"),
    Transform("cidr_sites", "Sites in this range", "cidr", "page.ip", "page.ip:{v}", "free", "hosted_on"),
    Transform("apex_sites", "Sites on this apex domain", "apex_domain", "page.apexDomain", "page.apexDomain:{v}", "free", "same_apex"),
    Transform("asn_sites", "Sites in this ASN", "asn", "page.asn", "page.asn:{v}", "free", "hosted_on"),
    Transform("ptr_sites", "Sites with this reverse DNS", "ptr", "page.ptr", "page.ptr:{v}", "free", "resolves_to"),
    Transform("cert_sites", "Sites with this TLS issuer", "tls_cert", "page.tlsIssuer", 'page.tlsIssuer:"{v}"', "free", "uses_cert"),
    Transform("hash_sites", "Sites serving this file hash", "file_hash", "hash", "hash:{v}", "free", "serves_file"),
    Transform("dom_hash_sites", "Sites with this DOM hash", "file_hash", "dom.hash", "dom.hash:{v}", "pro", "serves_file"),
    Transform("text_hash_sites", "Sites with this text hash", "file_hash", "text.hash", "text.hash:{v}", "pro", "contains_text"),
    Transform("filename_sites", "Sites requesting this path", "filename", "filename", 'filename:"{v}"', "free", "serves_file"),
    Transform("text_sites", "Sites showing this text", "text_string", "text.content", 'text.content:"{v}"', "pro", "contains_text"),
    Transform("third_party_sites", "Sites loading this domain", "third_party", "domain", 'domain:"{v}"', "free", "loads_third_party"),
    Transform("server_sites", "Sites with this server header", "tech", "page.server", 'page.server:"{v}"', "free", "uses_tech"),
    Transform("tech_sites", "Sites using this technology", "tech", "content.technologies", 'content.technologies:"{v}"', "pro", "uses_tech"),
    Transform("brand_sites", "Sites impersonating this brand", "brand", "brand.name", 'brand.name:"{v}"', "pro", "impersonates"),
    Transform("contact_sites", "Sites linking to this Telegram handle", "contact", "links.urls", "links.urls:/https:\\/\\/t\\.me\\/{v}.*/", "pro", "links_to_contact"),
    Transform("wallet_sites", "Sites mentioning this wallet", "wallet", "text.content", 'text.content:"{v}"', "pro", "contains_text"),
    Transform("tag_sites", "Sites with this tag", "tag", "task.tags", 'task.tags:"{v}"', "free", "tagged"),
)

_BY_ID = {t.id: t for t in TRANSFORMS}

SEARCH_TRANSFORM = "query"  # free-form urlscan query, no seed node

def get_transform(transform_id: str) -> Transform | None:
    return _BY_ID.get(transform_id)


def catalog() -> list[dict]:
    return [
        {"id": t.id, "label": t.label, "node_type": t.node_type, "field": t.field,
         "plan": t.plan, "template": t.template}
        for t in TRANSFORMS
    ]


def build_query(transform_id: str, value: str) -> tuple[str, Transform | None, str]:
    """Return ``(query, transform, canonical_value)``; raises GraphInputError."""
    if transform_id == SEARCH_TRANSFORM:
        canonical = canonical_value("query", value)
        return canonical, None, canonical
    transform = get_transform(transform_id)
    if transform is None:
        raise GraphInputError("Unknown transform.")
    canonical = canonical_value(transform.node_type, value)
    return transform.template.replace("{v}", canonical), transform, canonical


# -- shaping ------------------------------------------------------------------


class _Fragment:
    def __init__(self, source: str):
        self.source = source
        self.nodes: dict[str, dict] = {}
        self.edges: dict[str, dict] = {}

    def node(self, node_type: str, value: str, label: str | None = None, **attrs) -> str:
        nid = node_id(node_type, value)
        existing = self.nodes.get(nid)
        if existing is None:
            existing = {"id": nid, "type": node_type, "label": label or value, "attrs": {}}
            self.nodes[nid] = existing
        for key, val in attrs.items():
            if val is not None:
                existing["attrs"][key] = val
        return nid

    def edge(self, source: str, relation: str, target: str, seen: str | None = None) -> None:
        eid = edge_id(source, relation, target)
        edge = self.edges.get(eid)
        if edge is None:
            edge = {
                "id": eid, "source": source, "target": target, "type": relation,
                "attrs": {"source": self.source, "first_seen": seen, "last_seen": seen},
            }
            self.edges[eid] = edge
        elif seen:
            attrs = edge["attrs"]
            if not attrs["first_seen"] or seen < attrs["first_seen"]:
                attrs["first_seen"] = seen
            if not attrs["last_seen"] or seen > attrs["last_seen"]:
                attrs["last_seen"] = seen


def strip_www(host: str) -> str:
    """``www.example.com`` is the same site as ``example.com``; drop the prefix.

    Only when something that still looks like a domain is left, so ``www.com`` and
    other odd names are not mangled.
    """
    if host.startswith("www.") and "." in host[4:]:
        return host[4:]
    return host


def _host_value(value) -> str | None:
    if not value:
        return None
    try:
        return _host(str(value))
    except GraphInputError:
        return None


def _ip_value(value) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def shape_expansion(rows: list[dict], query: str, transform: Transform | None, value: str) -> dict:
    """Turn normalised search rows into nodes and edges.

    ``rows`` come from ``urlscan_client.normalise_result``. Infrastructure that
    search hits expose (apex, IP, ASN, PTR, TLS issuer, server) becomes linked
    nodes; the seed node, if any, is linked to every site returned.
    """
    frag = _Fragment(f"urlscan:{query}")
    seed = None
    if transform is not None:
        seed = frag.node(transform.node_type, value)

    for row in rows:
        host = _host_value(row.get("domain"))
        if host:
            host = strip_www(host)
        if not host:
            continue
        seen = row.get("time")
        site = frag.node("site", host)
        node = frag.nodes[site]
        scans = node["attrs"].setdefault("scans", [])
        if row.get("uuid") and row["uuid"] not in scans and len(scans) < MAX_SCANS_PER_SITE:
            scans.append(row["uuid"])
        attrs = node["attrs"]
        if seen and (not attrs.get("last_seen") or seen > attrs["last_seen"]):
            attrs.update(last_seen=seen, scanned_url=row.get("scanned_url"),
                         screenshot=row.get("screenshot"), status=row.get("status"),
                         domain_age_days=row.get("domain_age_days"),
                         country=row.get("country"))
        if seen and (not attrs.get("first_seen") or seen < attrs["first_seen"]):
            attrs["first_seen"] = seen

        if seed:
            frag.edge(site, transform.relation, seed, seen)

        apex = _host_value(row.get("apex_domain"))
        if apex:
            frag.edge(site, "same_apex", frag.node("apex_domain", apex), seen)

        ip = _ip_value(row.get("ip"))
        if ip:
            ip_node = frag.node("ip", ip, country=row.get("country"))
            frag.edge(site, "resolves_to", ip_node, seen)
            if row.get("asn") and _ASN.match(str(row["asn"]).upper()):
                asn = str(row["asn"]).upper()
                asn_node = frag.node("asn", asn, label=asn, name=row.get("asn_name"))
                frag.edge(ip_node, "hosted_on", asn_node, seen)
            ptr = _host_value(row.get("ptr"))
            if ptr:
                frag.edge(ip_node, "resolves_to", frag.node("ptr", ptr), seen)

        issuer = row.get("tls_issuer")
        if issuer and not _UNSAFE.search(issuer) and len(issuer) <= MAX_VALUE_LENGTH:
            frag.edge(site, "uses_cert", frag.node("tls_cert", issuer), seen)

        server = row.get("server")
        if server and not _UNSAFE.search(server) and len(server) <= MAX_VALUE_LENGTH:
            frag.edge(site, "uses_tech", frag.node("tech", server), seen)

    return {"nodes": list(frag.nodes.values()), "edges": list(frag.edges.values())}


# -- one full scan -------------------------------------------------------------
#
# ``shape_scan`` turns a full urlscan result (``/api/v1/result/<uuid>/``) into the
# same {nodes, edges} fragment as a search expansion, but with the detail a search
# hit does not carry: file hashes, requested filenames, third-party domains and the
# IPs behind them, the certificate, technologies, contacts, brands and tags.
# Every node and edge carries a ``category`` so the browser can offer a checklist
# before anything is added. ``core`` (the site, its apex, IP, ASN and reverse DNS)
# is always included.

SCAN_CATEGORIES = (
    "hashes", "filenames", "domains", "ips", "cert", "tech", "contacts",
    "wallets", "brands", "tags", "redirects",
)

MAX_SCAN_HASHES = 100
MAX_SCAN_FILENAMES = 100
MAX_SCAN_DOMAINS = 100
MAX_SCAN_IPS = 100
MAX_SCAN_TAGS = 20
MAX_SCAN_REDIRECTS = 10
MAX_SCAN_LINKS = 400

# Names that tell an investigator nothing because nearly every site has them.
GENERIC_FILENAMES = frozenset({
    "index.html", "index.htm", "index.php", "favicon.ico", "robots.txt", "sitemap.xml",
    "style.css", "styles.css", "main.css", "main.js", "app.js", "script.js", "jquery.js",
    "jquery.min.js", "logo.png", "logo.svg", "manifest.json", "blank.html",
})

_HEXISH_STEM = re.compile(r"^[0-9a-f]{16,}$", re.I)
_TELEGRAM_LINK = re.compile(r"^https?://(?:www\.)?(?:t|telegram)\.me/(?:s/)?@?([A-Za-z0-9_]{3,64})(?:[/?#]|$)", re.I)
_WALLET_CANDIDATE = re.compile(
    r"\b(0x[0-9a-fA-F]{40}|T[1-9A-HJ-NP-Za-km-z]{33}|bc1[0-9a-z]{25,60}|[13][1-9A-HJ-NP-Za-km-z]{25,34})\b"
)


def _s(value) -> str | None:
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    text = str(value).strip()
    return text or None


def _safe_text(value, limit: int = MAX_VALUE_LENGTH) -> str | None:
    text = _s(value)
    if not text or len(text) > limit or _UNSAFE.search(text):
        return None
    return text


def _dicts(value) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _sub(value, *keys):
    """Walk nested dicts; anything that is not a dict on the way gives None."""
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _url_host(url) -> str | None:
    try:
        return _host_value(urlsplit(str(url)).hostname) if url else None
    except ValueError:
        return None


def _filename_from(url) -> str | None:
    try:
        path = urlsplit(str(url)).path
    except ValueError:
        return None
    name = posixpath.basename(path or "").strip()
    if not name or "." not in name.strip("."):
        return None
    name = _safe_text(name, 120)
    if not name or name.lower() in GENERIC_FILENAMES:
        return None
    if _HEXISH_STEM.match(name.rsplit(".", 1)[0]):
        return None
    return name


def shape_scan(document: dict, scan_id: str) -> dict:
    """Nodes and edges for one full scan. Raises ``GraphInputError`` if it has no usable site."""
    if not isinstance(document, dict):
        raise GraphInputError("The scan result could not be read.")
    task = document.get("task") if isinstance(document.get("task"), dict) else {}
    page = document.get("page") if isinstance(document.get("page"), dict) else {}
    lists = document.get("lists") if isinstance(document.get("lists"), dict) else {}
    data = document.get("data") if isinstance(document.get("data"), dict) else {}
    stats = document.get("stats") if isinstance(document.get("stats"), dict) else {}
    verdicts = document.get("verdicts") if isinstance(document.get("verdicts"), dict) else {}
    overall = verdicts.get("overall") if isinstance(verdicts.get("overall"), dict) else {}

    scan_id = scan_id.lower()
    seen = _s(task.get("time"))
    host = _host_value(page.get("domain")) or _url_host(page.get("url")) or _url_host(task.get("url"))
    if not host:
        raise GraphInputError("The scan has no usable website address.")
    host = strip_www(host)
    apex = _host_value(page.get("apexDomain")) or registrable_domain(host)

    frag = _Fragment(f"urlscan:scan:{scan_id}")
    cats: dict[str, str] = {}
    skipped: dict[str, int] = {}
    counts: dict[str, int] = {name: 0 for name in SCAN_CATEGORIES}

    def put(category: str, node_type: str, value: str, **attrs) -> str:
        nid = frag.node(node_type, value, **attrs)
        if nid not in cats:
            cats[nid] = category
            if category in counts:
                counts[category] += 1
        return nid

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    score = overall.get("score")
    site = put(
        "core", "site", host,
        scans=[scan_id], first_seen=seen, last_seen=seen,
        scanned_url=_safe_text(page.get("url") or task.get("url"), 2000),
        screenshot=f"https://urlscan.io/screenshots/{scan_id}.png",
        status=page.get("status") if isinstance(page.get("status"), int) else None,
        country=_safe_text(page.get("country"), 8),
        title=_safe_text(page.get("title"), 200),
        verdict_score=score if isinstance(score, int) and not isinstance(score, bool) else None,
        verdict_malicious=bool(overall.get("malicious")) if "malicious" in overall else None,
    )
    if apex:
        frag.edge(site, "same_apex", put("core", "apex_domain", apex), seen)

    page_ip = _ip_value(page.get("ip"))
    if page_ip:
        ip_node = put("core", "ip", page_ip, country=_safe_text(page.get("country"), 8))
        frag.edge(site, "resolves_to", ip_node, seen)
        asn = str(page.get("asn") or "").upper()
        if _ASN.match(asn):
            asn_node = put("core", "asn", asn, label=asn, name=_safe_text(page.get("asnname"), 120))
            frag.edge(ip_node, "hosted_on", asn_node, seen)
        ptr = _host_value(page.get("ptr"))
        if ptr:
            frag.edge(ip_node, "resolves_to", put("core", "ptr", ptr), seen)

    # Certificate: keyed by issuer so it merges with search hits; subjects ride on the node.
    issuer = _safe_text(page.get("tlsIssuer"))
    if issuer:
        cert = put("cert", "tls_cert", issuer)
        frag.edge(site, "uses_cert", cert, seen)
        subjects = frag.nodes[cert]["attrs"].setdefault("subjects", [])
        for item in _dicts(lists.get("certificates")):
            subject = _safe_text(item.get("subjectName"), 200)
            if subject and _safe_text(item.get("issuer")) == issuer and subject not in subjects and len(subjects) < 10:
                subjects.append(subject)

    # Technologies.
    tech_names: dict[str, str] = {}
    server = _safe_text(page.get("server"))
    if server:
        tech_names[server.lower()] = server
    for item in _dicts(_sub(document, "meta", "processors", "wappa", "data"))[:60]:
        app_name = _safe_text(item.get("app"), 100)
        if app_name:
            tech_names.setdefault(app_name.lower(), app_name)
    for name in tech_names.values():
        frag.edge(site, "uses_tech", put("tech", "tech", name), seen)

    # Response hashes and filenames.
    requests_in = _dicts(data.get("requests"))
    hash_rows: dict[str, dict] = {}
    names: dict[str, int] = {}
    for entry in requests_in:
        response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        url = _sub(entry, "request", "request", "url")
        size = response.get("size") if isinstance(response.get("size"), int) else 0
        digest = _s(response.get("hash"))
        if digest and _SHA256.match(digest.lower()):
            digest = digest.lower()
            if size > 0:
                row = hash_rows.setdefault(digest, {
                    "size": size, "url": url,
                    "mime": _sub(response, "response", "mimeType"),
                })
                row["size"] = max(row["size"], size)
            else:
                skip("empty_body_hash")
        elif digest:
            skip("unrecognised_hash")
        name = _filename_from(url)
        if name:
            names[name] = names.get(name, 0) + 1

    # Files urlscan saved: real file names and a SHA-256 for each.
    for item in _dicts(_sub(document, "meta", "processors", "download", "data")):
        digest = (_s(item.get("sha256")) or "").lower()
        fname = _safe_text(item.get("filename"), 120)
        if _SHA256.match(digest):
            row = hash_rows.setdefault(digest, {
                "size": item.get("fileSize") if isinstance(item.get("fileSize"), int) else 1,
                "url": None, "mime": item.get("mimeType"),
            })
            row["download"] = True
            if fname:
                row["filename"] = fname
        if fname and fname.lower() not in GENERIC_FILENAMES:
            names[fname] = names.get(fname, 0) + 1000

    ranked = sorted(hash_rows.items(), key=lambda kv: (not kv[1].get("download"), -kv[1]["size"]))
    if len(ranked) > MAX_SCAN_HASHES:
        skip("hashes_over_cap")
    for digest, row in ranked[:MAX_SCAN_HASHES]:
        attrs = {
            "kind": "download" if row.get("download") else "response",
            "mime_type": _safe_text(row.get("mime"), 100),
            "size": row["size"],
            "sample_url": _safe_text(row.get("url"), 500),
            "filename": row.get("filename"),
        }
        frag.edge(site, "serves_file", put("hashes", "file_hash", digest, **attrs), seen)

    top_names = sorted(names.items(), key=lambda kv: (-kv[1], kv[0]))
    if len(top_names) > MAX_SCAN_FILENAMES:
        skip("filenames_over_cap")
    for name, _count in top_names[:MAX_SCAN_FILENAMES]:
        frag.edge(site, "serves_file", put("filenames", "filename", name), seen)

    # Third-party domains and the IPs behind them.
    third: list[str] = []
    for raw in lists.get("domains") or []:
        other = _host_value(raw)
        if not other:
            skip("bad_domain")
            continue
        if other == host or (apex and registrable_domain(other) == apex):
            continue
        if other not in third:
            third.append(other)
    if len(third) > MAX_SCAN_DOMAINS:
        skip("domains_over_cap")
    third = third[:MAX_SCAN_DOMAINS]
    for other in third:
        frag.edge(site, "loads_third_party", put("domains", "third_party", other), seen)
    ip_budget = MAX_SCAN_IPS
    for item in _dicts(stats.get("domainStats")):
        other = _host_value(item.get("domain"))
        if not other or other not in third:
            continue
        for raw_ip in item.get("ips") or []:
            value = _ip_value(raw_ip)
            if not value or value == page_ip:
                continue
            if ip_budget <= 0:
                skip("ips_over_cap")
                break
            ip_budget -= 1
            frag.edge(put("domains", "third_party", other), "resolves_to", put("ips", "ip", value), seen)

    # Links on the page: Telegram contacts and wallet addresses.
    handles: list[str] = []
    wallets: list[str] = []
    for link in _dicts(data.get("links"))[:MAX_SCAN_LINKS]:
        href = _s(link.get("href")) or ""
        match = _TELEGRAM_LINK.match(href)
        if match and match.group(1).lower() not in handles:
            handles.append(match.group(1).lower())
        for source in (href, _s(link.get("text")) or ""):
            for candidate in _WALLET_CANDIDATE.findall(source[:500]):
                try:
                    canonical = _wallet(candidate)
                except GraphInputError:
                    skip("wallet_failed_validation")
                    continue
                if canonical not in wallets:
                    wallets.append(canonical)
    for handle in handles[:20]:
        frag.edge(site, "links_to_contact", put("contacts", "contact", handle), seen)
    for address in wallets[:20]:
        frag.edge(site, "contains_text", put("wallets", "wallet", address), seen)

    # Brands and tags.
    brands: list[str] = []
    for source in (overall, verdicts.get("urlscan")):
        for brand in (source.get("brands") if isinstance(source, dict) else None) or []:
            name = _safe_text(brand.get("name") if isinstance(brand, dict) else brand, 100)
            if name and name not in brands:
                brands.append(name)
    for name in brands[:10]:
        frag.edge(site, "impersonates", put("brands", "brand", name), seen)
    tags: list[str] = []
    for raw in list(task.get("tags") or []) + list(overall.get("tags") or []):
        tag = _safe_text(raw, 100)
        if tag and tag not in tags:
            tags.append(tag)
    for tag in tags[:MAX_SCAN_TAGS]:
        frag.edge(site, "tagged", put("tags", "tag", tag), seen)

    # Redirects: request host -> Location host.
    hops = 0
    for entry in requests_in:
        inner = _sub(entry, "response", "response")
        status = inner.get("status") if isinstance(inner, dict) else None
        headers = inner.get("headers") if isinstance(inner, dict) and isinstance(inner.get("headers"), dict) else {}
        target = next((v for k, v in headers.items() if str(k).lower() == "location"), None)
        if not isinstance(status, int) or not 300 <= status < 400 or not target:
            continue
        origin = _url_host(inner.get("url"))
        try:
            destination = _url_host(urljoin(str(inner.get("url") or ""), str(target)))
        except ValueError:
            destination = None
        if not origin or not destination or strip_www(origin) == strip_www(destination):
            continue
        if hops >= MAX_SCAN_REDIRECTS:
            skip("redirects_over_cap")
            break
        hops += 1
        a = put("redirects", "site", strip_www(origin))
        b = put("redirects", "site", strip_www(destination))
        frag.edge(a, "redirects_to", b, seen)
        frag.edges[edge_id(a, "redirects_to", b)]["attrs"]["hop"] = hops

    nodes = list(frag.nodes.values())
    for node in nodes:
        node["category"] = cats.get(node["id"], "core")
    edges = list(frag.edges.values())
    for edge in edges:
        edge["category"] = next(
            (c for c in (cats.get(edge["target"]), cats.get(edge["source"])) if c and c != "core"), "core"
        )
    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {"scan_id": scan_id, "site": site, "categories": counts, "skipped": skipped},
    }


# -- dataset ingestion ----------------------------------------------------------
# Uploaded rows are parsed in the browser; only the values that need the
# server's rules (registrable domains, wallet checksums) come here.

MAX_INGEST_BATCH = 200
MAX_SITE_INPUT = 2048
MAX_ADDRESS_INPUT = 200
MAX_CHAIN_LABEL = 120

_BAD_HOST_CHARS = re.compile(r"[\x00-\x20\x7f\"'<>\\]")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_LABEL_CODE = re.compile(r"\(([A-Za-z]{2,6})\)\s*$")


def normalise_site(raw) -> dict:
    """``{host, apex}`` for a URL or hostname, or ``{error}``.

    Tolerates the usual dataset mess: defanged ``hxxps://`` and ``[.]``, a missing
    scheme, a protocol-relative ``//host``, ports, paths and credentials.
    """
    text = str(raw if raw is not None else "").strip().strip("\"'<>")
    if not text:
        return {"error": "Empty value."}
    if len(text) > MAX_SITE_INPUT:
        return {"error": "Too long to be a URL."}
    text = text.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
    if text[:4].lower() == "hxxp":
        text = "http" + text[4:]
    if text.startswith("//"):
        text = "https:" + text
    if not _SCHEME.match(text):
        text = "https://" + text
    try:
        parts = urlsplit(text)
        host = parts.hostname
    except ValueError:
        return {"error": "Not a valid URL."}
    if _BAD_HOST_CHARS.search(parts.netloc):
        return {"error": "Contains characters that cannot be in a hostname."}
    if not host:
        return {"error": "No hostname found."}
    host = host.lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return {"error": "Not a valid hostname."}
    try:
        ipaddress.ip_address(host)
        return {"host": host, "apex": None}
    except ValueError:
        pass
    if "." not in host or not _HOST.match(host):
        return {"error": "Not a valid hostname."}
    host = strip_www(host)
    return {"host": host, "apex": registrable_domain(host)}


def chain_from_label(label: str) -> str | None:
    """Chain code from labels like ``Tether (USDT) - Arbitrum One (arb)`` or ``ETH``."""
    label = (label or "").strip()
    match = _LABEL_CODE.search(label)
    if match and match.group(1).lower() in CHAINS:
        return match.group(1).lower()
    if label.lower() in CHAINS:
        return label.lower()
    return None


def normalise_wallet(address, chain_label="") -> dict:
    """Validate one uploaded wallet. The labelled chain wins, detection is the fallback."""
    address = str(address if address is not None else "").strip()[:MAX_ADDRESS_INPUT]
    if not address:
        return {"valid": False, "error": "Empty address."}
    labelled = chain_from_label(str(chain_label or "")[:MAX_CHAIN_LABEL])
    detected = detect_chain(address).chain
    for chain in (labelled, detected):
        if not chain:
            continue
        check = validate_wallet(chain, address)
        if check.valid:
            return {"valid": True, "chain": chain, "canonical": check.canonical}
    if labelled:
        check = validate_wallet(labelled, address)
        return {"valid": False, "error": check.errors[0] if check.errors else "Failed validation."}
    return {"valid": False, "error": "Unrecognised address format."}


def ingest(sites, wallets) -> dict:
    """Normalise a batch. Results line up with the inputs by index."""
    return {
        "sites": [normalise_site(item) for item in sites],
        "wallets": [
            normalise_wallet(item.get("address"), item.get("chain")) if isinstance(item, dict)
            else {"valid": False, "error": "Not an object."}
            for item in wallets
        ],
    }
