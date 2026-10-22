"""urlscan search fields for the query bar's autocomplete.

The list is a seven-column CSV shipped in ``database/``:
``field,group,type,plan,regex,description,example``. It is read once at
startup and served as-is to the browser, which does all of the matching.

The file is editable, so it is treated like any other untrusted input: rows
without a usable field name are skipped, duplicate fields keep their first
row, ``plan`` and ``regex`` are normalised to two known values each, and long
text is clipped. The browser renders every value with ``textContent``.
"""

from __future__ import annotations

import csv
import pathlib
import re
from dataclasses import asdict, dataclass

DEFAULT_PATH = pathlib.Path(__file__).with_name("database") / "query_terms.csv"

COLUMNS = ("field", "group", "type", "plan", "regex", "description", "example")

# Field names are dotted identifiers (page.domain, domain.keyword, _exists_).
# Anything else is a typo or junk and would never complete to a valid query.
FIELD_SHAPE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*$")

# Generous for the shipped rows (the longest example is under 90 characters),
# small enough that an edited file cannot bloat every page load.
MAX_TEXT = 300


@dataclass(frozen=True)
class QueryTerm:
    field: str
    group: str
    type: str
    plan: str     # "free" or "pro"
    regex: str    # "true" or "false", kept as text to match the CSV
    description: str
    example: str


def _clip(value: str | None) -> str:
    return " ".join((value or "").split())[:MAX_TEXT]


class QueryTerms:
    def __init__(self, terms: list[QueryTerm]):
        self.terms = tuple(terms)

    @classmethod
    def load(cls, path: pathlib.Path | str = DEFAULT_PATH) -> "QueryTerms":
        path = pathlib.Path(path)
        terms: list[QueryTerm] = []
        seen: set[str] = set()

        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            missing = [name for name in COLUMNS if name not in (reader.fieldnames or [])]
            if missing:
                raise ValueError(f"{path} is missing column(s): {', '.join(missing)}")
            for row in reader:
                field = (row.get("field") or "").strip()
                if not FIELD_SHAPE.match(field) or field.lower() in seen:
                    continue
                seen.add(field.lower())
                plan = "pro" if (row.get("plan") or "").strip().lower() == "pro" else "free"
                regex = (row.get("regex") or "").strip().lower() in {"true", "1", "yes"}
                terms.append(
                    QueryTerm(
                        field=field,
                        group=_clip(row.get("group")),
                        type=_clip(row.get("type")),
                        plan=plan,
                        regex="true" if regex else "false",
                        description=_clip(row.get("description")),
                        # Examples are queries; whitespace inside quotes matters,
                        # so only the ends are trimmed.
                        example=(row.get("example") or "").strip()[:MAX_TEXT],
                    )
                )

        if not terms:
            raise ValueError(f"No usable query terms found in {path}")
        return cls(terms)

    @property
    def size(self) -> int:
        return len(self.terms)

    def browser_data(self) -> list[dict]:
        return [asdict(term) for term in self.terms]
