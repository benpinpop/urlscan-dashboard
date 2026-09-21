"""Risk keyword database and page-content scorer.

The database is a three-column CSV (``keyword,category,weight``) shipped in
``database/``. Matching is case-insensitive and boundary-aware: ``pass`` does
not match ``password``, and a phrase like ``1.5% daily`` still matches even
though it starts with a digit and contains punctuation.

Nothing here touches the network. ``extract_text`` takes HTML that was fetched
elsewhere and ``score_text`` turns text into a score, so both halves can be
tested without an API key.

Scoring is deliberately explainable rather than clever — see ``score_text``
for the formula and its calibration. It is a triage signal, not a verdict.
"""

from __future__ import annotations

import csv
import math
import pathlib
import re
from dataclasses import dataclass
from html.parser import HTMLParser

DEFAULT_DB_PATH = pathlib.Path(__file__).with_name("database") / "crypto_scam_keywords.csv"

# Keywords may begin or end with punctuation ("100% safe", "gh/s plan"), so \b
# is unreliable. Look for an alphanumeric neighbour instead: that is what makes
# "pass" inside "password" a non-match while "100% apy" still matches.
BOUNDARY_LEFT = r"(?<![a-z0-9])"
BOUNDARY_RIGHT = r"(?![a-z0-9])"

# Occurrences past this count stop adding to the score. A page that repeats one
# phrase is insistent, not twenty times more fraudulent.
OCCURRENCE_CAP = 5

# What one distinct keyword is worth, by its weight in the database. Weight 1 is
# deliberately worth nothing: those rows are topic vocabulary ("bitcoin",
# "blockchain", "apy") and a page is not suspicious for being about crypto.
# They are still counted and reported, as context.
TIER_VALUE = {1: 0.0, 2: 0.2, 3: 0.5, 4: 1.0, 5: 1.25}

# Repeating a scoring keyword adds up to 40% of its value back.
REPEAT_BONUS = 0.1
REPEAT_BONUS_CAP = 4

# Signal points that should read as "clearly bad". At 4.0 a page needs roughly
# four distinct severe claims, or a wider spread of weaker ones, to saturate.
SIGNAL_MIDPOINT = 4.0

# Floor of the breadth multiplier. One category on its own is usually
# vocabulary or a single unlucky phrase; fraud pages promise yields *and* press
# for deposits *and* manufacture urgency.
BREADTH_FLOOR = 0.55
BREADTH_FULL_AT = 5

SEVERITY_LABELS = {
    1: "context",
    2: "low",
    3: "moderate",
    4: "high",
    5: "severe",
}


@dataclass(frozen=True)
class Keyword:
    keyword: str
    category: str
    weight: int


class _TextExtractor(HTMLParser):
    """Collect visible text, dropping script, style and template contents."""

    SKIP = {"script", "style", "noscript", "template", "svg", "iframe"}
    BREAK_AFTER = {
        "p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6",
        "section", "article", "header", "footer", "td", "th", "button", "option",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._chunks: list[str] = []
        self.title: str | None = None
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skip_depth += 1
        if tag == "title":
            self._in_title = True
        # Alt text and input values are visible to a reader even though they
        # are attributes, and scam pages hide a lot of their copy in buttons.
        if self._skip_depth == 0:
            for name, value in attrs:
                if name in {"alt", "title", "placeholder", "value", "aria-label"} and value:
                    self._chunks.append(" " + str(value) + " ")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag in self.SKIP:
            self._skip_depth = max(0, self._skip_depth - 1)

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            self._skip_depth = max(0, self._skip_depth - 1)
        if tag == "title":
            self._in_title = False
        if tag in self.BREAK_AFTER:
            self._chunks.append("\n")

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._in_title and self.title is None:
            stripped = data.strip()
            if stripped:
                self.title = stripped
        self._chunks.append(data)

    def text(self) -> str:
        return "".join(self._chunks)


# Curly quotes and non-breaking spaces would otherwise stop "don't miss out"
# and other phrases from matching.
TRANSLATIONS = str.maketrans({
    "‘": "'", "’": "'", "‛": "'", "´": "'", "′": "'",
    "“": '"', "”": '"',
    " ": " ", " ": " ", " ": " ", "​": "",
    "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-",
    "％": "%",
})

WHITESPACE = re.compile(r"\s+")
WORD = re.compile(r"[a-z0-9][a-z0-9'%./-]*", re.IGNORECASE)


def extract_text(html: str, max_chars: int = 400_000) -> dict:
    """Turn raw HTML into normalised visible text.

    Returns the cleaned text, the document title if one was present, and the
    number of characters that were dropped by the cap.
    """
    parser = _TextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        # A malformed DOM should degrade to whatever was parsed before the
        # error rather than failing the whole analysis.
        pass

    text = parser.text().translate(TRANSLATIONS)
    # Keep paragraph breaks (they make the excerpt readable) but collapse runs.
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n\s*", "\n\n", text)
    text = re.sub(r" ?\n ?", "\n", text).strip()

    truncated = max(0, len(text) - max_chars)
    if truncated:
        text = text[:max_chars]

    return {"text": text, "title": parser.title, "truncated_chars": truncated}


class KeywordDatabase:
    """Compiled keyword set plus the scorer that uses it."""

    def __init__(self, keywords: list[Keyword]):
        self.keywords = keywords
        self._by_keyword = {k.keyword: k for k in keywords}
        self.categories = sorted({k.category for k in keywords})
        self._pattern = self._compile(keywords)

    # -- construction -----------------------------------------------------

    @staticmethod
    def _compile(keywords: list[Keyword]) -> re.Pattern | None:
        if not keywords:
            return None
        # Longest first so "get rich quick" wins over "get rich" at the same
        # position; Python's alternation takes the first branch that matches.
        ordered = sorted({k.keyword for k in keywords}, key=len, reverse=True)
        body = "|".join(re.escape(word) for word in ordered)
        return re.compile(f"{BOUNDARY_LEFT}(?:{body}){BOUNDARY_RIGHT}", re.IGNORECASE)

    @classmethod
    def load(cls, path: pathlib.Path | str = DEFAULT_DB_PATH) -> "KeywordDatabase":
        path = pathlib.Path(path)
        keywords: list[Keyword] = []
        seen: set[str] = set()

        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                keyword = (row.get("keyword") or "").strip().lower()
                category = (row.get("category") or "uncategorised").strip() or "uncategorised"
                if not keyword or keyword in seen:
                    continue
                try:
                    weight = int(str(row.get("weight") or "1").strip())
                except ValueError:
                    weight = 1
                weight = min(5, max(1, weight))
                # Normalise the stored phrase the same way page text is
                # normalised, or a two-space entry would never match.
                keyword = WHITESPACE.sub(" ", keyword.translate(TRANSLATIONS))
                seen.add(keyword)
                keywords.append(Keyword(keyword, category, weight))

        if not keywords:
            raise ValueError(f"No usable keywords found in {path}")
        return cls(keywords)

    # -- reporting --------------------------------------------------------

    def summary(self) -> dict:
        per_category: dict[str, int] = {}
        for keyword in self.keywords:
            per_category[keyword.category] = per_category.get(keyword.category, 0) + 1
        return {
            "keyword_count": len(self.keywords),
            "category_count": len(self.categories),
            "categories": [
                {"category": name, "keywords": count}
                for name, count in sorted(per_category.items(), key=lambda kv: -kv[1])
            ],
        }

    def browser_data(self) -> dict:
        """Return the immutable scoring inputs needed by the browser scorer."""
        return {
            **self.summary(),
            "keywords": [
                {"keyword": item.keyword, "category": item.category, "weight": item.weight}
                for item in self.keywords
            ],
            "occurrence_cap": OCCURRENCE_CAP,
            "tier_value": TIER_VALUE,
            "repeat_bonus": REPEAT_BONUS,
            "repeat_bonus_cap": REPEAT_BONUS_CAP,
            "signal_midpoint": SIGNAL_MIDPOINT,
            "breadth_floor": BREADTH_FLOOR,
            "breadth_full_at": BREADTH_FULL_AT,
            "severity_labels": SEVERITY_LABELS,
        }

    # -- scoring ----------------------------------------------------------

    def score_text(self, text: str, context_chars: int = 90, max_matches: int = 400) -> dict:
        """Score page text and explain the score.

        The formula, in order:

        1. Count occurrences of every keyword. Weight-1 rows are set aside as
           *context*: they say what the page is about, not that anything is
           wrong with it, so they are reported but never scored. Without that
           split a regulated exchange's own homepage scores like a scam.
        2. Each remaining distinct keyword contributes ``TIER_VALUE[weight]``,
           plus up to 40% again for repetition. Distinct keywords rather than
           raw counts, because "guaranteed profit" said once is the signal.
        3. ``points`` is the sum of those contributions. It does not divide by
           page length: a promise of fixed daily returns means the same on a
           short page and a long one.
        4. Saturate: ``base = 100 * (1 - exp(-points / SIGNAL_MIDPOINT))``,
           which stays inside 0-100 without a hard clamp.
        5. Scale by how many categories the scoring matches spread across.

        Word count and keyword density are reported for context but are
        deliberately not inputs. ``score_text`` is length-independent.
        """
        words = WORD.findall(text)
        total_words = len(words)

        occurrences: dict[str, int] = {}
        locations: dict[str, list[dict]] = {}

        if self._pattern is not None and text:
            lowered = text.lower()
            for match in self._pattern.finditer(lowered):
                word = match.group(0)
                occurrences[word] = occurrences.get(word, 0) + 1
                bucket = locations.setdefault(word, [])
                if len(bucket) < 3 and sum(len(v) for v in locations.values()) < max_matches:
                    start = max(0, match.start() - context_chars // 2)
                    end = min(len(text), match.end() + context_chars // 2)
                    bucket.append({
                        "offset": match.start(),
                        "line": lowered.count("\n", 0, match.start()) + 1,
                        "excerpt": ("\u2026" if start else "")
                        + WHITESPACE.sub(" ", text[start:end]).strip()
                        + ("\u2026" if end < len(text) else ""),
                    })

        matches: list[dict] = []
        context_matches: list[dict] = []
        points = 0.0
        per_category: dict[str, dict] = {}
        severity_counts = {level: 0 for level in SEVERITY_LABELS}

        for word, count in occurrences.items():
            meta = self._by_keyword.get(word)
            if meta is None:  # pragma: no cover - pattern is built from the map
                continue
            counted = min(count, OCCURRENCE_CAP)
            repeat = 1.0 + REPEAT_BONUS * min(counted - 1, REPEAT_BONUS_CAP)
            contribution = TIER_VALUE.get(meta.weight, 0.0) * repeat

            severity_counts[meta.weight] += 1
            row = {
                "keyword": word,
                "category": meta.category,
                "weight": meta.weight,
                "severity": SEVERITY_LABELS[meta.weight],
                "occurrences": count,
                "counted_occurrences": counted,
                "contribution": round(contribution, 2),
                "scored": contribution > 0,
                "locations": locations.get(word, []),
            }

            if contribution <= 0:
                # Context vocabulary: shown to the analyst, kept out of the score.
                context_matches.append(row)
                continue

            points += contribution
            matches.append(row)
            bucket = per_category.setdefault(
                meta.category,
                {"category": meta.category, "hits": 0, "unique_keywords": 0, "points": 0.0},
            )
            bucket["hits"] += count
            bucket["unique_keywords"] += 1
            bucket["points"] += contribution

        matches.sort(key=lambda m: (-m["contribution"], -m["weight"], m["keyword"]))
        context_matches.sort(key=lambda m: (-m["occurrences"], m["keyword"]))

        breadth_ratio = min(1.0, len(per_category) / BREADTH_FULL_AT)
        breadth = BREADTH_FLOOR + (1.0 - BREADTH_FLOOR) * breadth_ratio
        base = 100.0 * (1.0 - math.exp(-points / SIGNAL_MIDPOINT)) if points else 0.0
        score = min(100.0, base * breadth)

        categories = sorted(per_category.values(), key=lambda c: -c["points"])
        for entry in categories:
            entry["points"] = round(entry["points"], 2)
            entry["share"] = round(100.0 * entry["points"] / points, 1) if points else 0.0

        scoring_hits = sum(match["occurrences"] for match in matches)

        return {
            "score": round(score, 1),
            "band": band_for(score),
            "total_words": total_words,
            "unique_keywords": len(matches),
            "total_hits": scoring_hits,
            "signal_points": round(points, 2),
            "context_keywords": len(context_matches),
            "context_hits": sum(match["occurrences"] for match in context_matches),
            "context_matches": context_matches[:40],
            "density_percent": round(100.0 * scoring_hits / total_words, 3) if total_words else 0.0,
            "category_breadth": len(per_category),
            "breadth_multiplier": round(breadth, 3),
            "categories": categories,
            "severity": [
                {
                    "weight": level,
                    "label": SEVERITY_LABELS[level],
                    "unique_keywords": severity_counts[level],
                    "scored": TIER_VALUE.get(level, 0.0) > 0,
                }
                for level in sorted(SEVERITY_LABELS)
            ],
            "matches": matches[:max_matches],
            "matches_truncated": max(0, len(matches) - max_matches),
            "formula": (
                "score = 100 x (1 - e^(-points / 4)) x breadth. Each distinct keyword of "
                "weight 2 or more contributes 0.2 to 1.25 points (plus up to 40% for "
                "repetition); weight-1 rows are topic vocabulary and score nothing. Breadth "
                f"rises from {BREADTH_FLOOR} to 1.0 as scoring matches spread across "
                f"{BREADTH_FULL_AT} or more categories. Page length is not an input."
            ),
        }


def band_for(score: float) -> str:
    """Bucket a 0-100 score into the label the UI colours by."""
    if score >= 70:
        return "high"
    if score >= 40:
        return "elevated"
    if score >= 15:
        return "low"
    return "minimal"
