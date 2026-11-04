"""Backend-neutral YARA matches for local files and archive members.

Only rule IDs, metadata and tags are retained; no matched payload bytes
or sensitive source content is logged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """One matched rule from classic YARA or the optional YARA-X backend."""

    rule: str
    namespace: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    tags: tuple[str, ...] = ()


def normalized_classic(matches: Iterable[Any]) -> list[RuleMatch]:
    """Convert yara-python match objects into the common representation."""
    return [
        RuleMatch(
            rule=str(item.rule),
            namespace=str(getattr(item, "namespace", "")),
            meta=dict(getattr(item, "meta", None) or {}),
            tags=tuple(str(x) for x in (getattr(item, "tags", ()) or ())),
        ) for item in matches
    ]


def normalized_yarax(result: Any) -> list[RuleMatch]:
    """Convert official yara_x.ScanResults using its documented Rule API."""
    return [
        RuleMatch(
            rule=str(item.identifier),
            namespace=str(getattr(item, "namespace", "")),
            meta=dict(getattr(item, "metadata", ()) or ()),
            tags=tuple(str(x) for x in (getattr(item, "tags", ()) or ())),
        ) for item in result.matching_rules
    ]
