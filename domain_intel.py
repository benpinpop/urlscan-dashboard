"""Classify third-party domains seen during a scan.

The table lives in ``database/domain_categories.csv`` so an analyst can extend
it without touching code. A pattern matches a host when the host equals it or
ends with ``.`` + pattern, so ``cloudfront.net`` covers ``d1abc.cloudfront.net``
but never ``notcloudfront.net``. Patterns containing a slash are matched against
``host + path`` instead, which is how ``google.com/recaptcha`` stays distinct
from the rest of google.com.

Anything not in the table is reported as ``unknown`` rather than guessed at.
The registrable-domain logic is a heuristic over a short list of multi-label
suffixes, not a full Public Suffix List; it is used for grouping and for the
apex filter, never for a security decision.
"""

from __future__ import annotations

import csv
import pathlib

DEFAULT_TABLE_PATH = pathlib.Path(__file__).with_name("database") / "domain_categories.csv"

CATEGORY_LABELS = {
    "first_party": "First party",
    "analytics": "Analytics",
    "ads": "Advertising",
    "tracker": "Tracker",
    "cdn": "CDN",
    "fonts": "Fonts",
    "captcha": "CAPTCHA",
    "social": "Social",
    "chat": "Live chat",
    "payment": "Payments",
    "crypto": "Crypto service/widget",
    "platform": "Site platform",
    "hosting": "Hosting",
    "unknown": "Unclassified",
}

# Two-label public suffixes common enough to matter when deriving an apex.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "net.za", "web.za",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "ne.kr",
    "com.mx", "com.ar", "com.co", "com.pe", "com.tr", "com.tw", "com.hk",
    "com.sg", "com.my", "com.ph", "com.vn", "com.ua", "com.pl", "com.ru",
    "co.in", "net.in", "org.in", "gov.in",
    "co.il", "org.il", "net.il",
    "com.es", "com.pt", "com.gr", "com.sa", "com.eg", "com.ng", "com.gh",
    "github.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app",
    "ngrok-free.app", "duckdns.org", "s3.amazonaws.com", "web.app",
    "firebaseapp.com", "blob.core.windows.net",
}


def registrable_domain(host: str) -> str:
    """Best-effort apex for a hostname. Returns the host itself for IPs."""
    host = (host or "").strip().strip(".").lower()
    if not host or host.replace(".", "").isdigit() or ":" in host:
        return host

    labels = host.split(".")
    if len(labels) <= 2:
        return host

    for size in (3, 2):
        candidate = ".".join(labels[-size:])
        if candidate in MULTI_LABEL_SUFFIXES and len(labels) > size:
            return ".".join(labels[-(size + 1):])

    return ".".join(labels[-2:])


class DomainTable:
    def __init__(self, rows: list[tuple[str, str, str]]):
        # Longest pattern first: challenges.cloudflare.com must win over
        # cloudflare.com, and google.com/recaptcha over google.com.
        self._rows = sorted(rows, key=lambda row: len(row[0]), reverse=True)
        self._host_rows = [row for row in self._rows if "/" not in row[0]]
        self._path_rows = [row for row in self._rows if "/" in row[0]]
        self._cache: dict[tuple[str, str], tuple[str, str | None]] = {}

    @classmethod
    def load(cls, path: pathlib.Path | str = DEFAULT_TABLE_PATH) -> "DomainTable":
        path = pathlib.Path(path)
        rows: list[tuple[str, str, str]] = []
        if path.is_file():
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                for row in csv.DictReader(handle):
                    pattern = (row.get("pattern") or "").strip().lower()
                    category = (row.get("category") or "").strip().lower()
                    label = (row.get("label") or "").strip()
                    if pattern and category:
                        rows.append((pattern, category, label or pattern))
        return cls(rows)

    @property
    def size(self) -> int:
        return len(self._rows)

    def classify(self, host: str, path: str = "", apex: str | None = None) -> dict:
        """Categorise one host, with ``apex`` marking the scanned site itself."""
        host = (host or "").strip().strip(".").lower()
        path = path or ""
        key = (host, path.split("?")[0][:80])
        cached = self._cache.get(key)

        if cached is None:
            category, label = "unknown", None
            haystack = host + key[1]
            for pattern, pattern_category, pattern_label in self._path_rows:
                if pattern in haystack:
                    category, label = pattern_category, pattern_label
                    break
            if category == "unknown":
                for pattern, pattern_category, pattern_label in self._host_rows:
                    if host == pattern or host.endswith("." + pattern):
                        category, label = pattern_category, pattern_label
                        break
            self._cache[key] = cached = (category, label)
            if len(self._cache) > 20000:  # pragma: no cover - long-running guard
                self._cache.clear()

        category, label = cached
        host_apex = registrable_domain(host)
        is_first_party = bool(apex) and host_apex == registrable_domain(apex)

        if is_first_party:
            # First-party wins over a platform match: a shop's own
            # shop.example.com is not "Shopify" from the analyst's point of view.
            category, label = "first_party", label or "Scanned site"

        return {
            "category": category,
            "category_label": CATEGORY_LABELS.get(category, category.title()),
            "service": label,
            "apex": host_apex,
            "is_first_party": is_first_party,
        }
