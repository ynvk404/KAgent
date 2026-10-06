"""Immutable source and presentation values, and centralized V1 budgets."""
from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from pathlib import Path
from typing import Any

MAX_RECORDS = 10_000
MAX_RESULTS = 20_000
MAX_COVERAGE = 5_000
MAX_FINDINGS = 100
MAX_SCAN = 2_000
MAX_INTAKE = 32 * 1024 * 1024
MAX_COVERAGE_BYTES = 16 * 1024 * 1024
MAX_TEXT_INTAKE = 64 * 1024
MAX_TITLE = 240
MAX_ID = 512
MAX_REASON = 500
MAX_PROSE = 2_000
MAX_REFS = 20
MAX_DOCUMENT = 2 * 1024 * 1024
MAX_PDF = 16 * 1024 * 1024
MAX_PAGES = 200


class ReportError(Exception):
    """Only fixed, safe messages may be passed by report code."""


@dataclass(frozen=True, slots=True)
class Record:
    values: tuple[tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if any(not isinstance(key, str) for key, _ in self.values):
            raise ReportError("Unsupported report record key.")
        object.__setattr__(self, "values", tuple((key, freeze(value)) for key, value in self.values))

    def get(self, key: str, default: Any = None) -> Any:
        return next((value for name, value in self.values if name == key), default)


def freeze(value: Any) -> Any:
    """Detach allowlisted primitive trees, rejecting unsupported objects."""
    if isinstance(value, Record):
        return value
    if isinstance(value, dict):
        return Record(tuple((key, freeze(item)) for key, item in sorted(value.items())))
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(freeze(item) for item in value)
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise ReportError("Unsupported report source. Run /report again after restoring valid state.")


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    target: str
    target_name: str = ""
    scope: tuple[str, ...] = ()
    objective: Record = Record()
    candidates: tuple[Record, ...] = ()
    results: tuple[Record, ...] = ()
    inputs: tuple[Record, ...] = ()
    evidence: tuple[Record, ...] = ()
    phases: tuple[Record, ...] = ()
    coverage: tuple[Record, ...] | None = None
    session: str = ""
    provider: str = ""
    backend: str = ""
    model: str = ""
    version: str = ""
    exported_at: str = ""
    running: bool = False
    restored: bool = False
    foreign_records: bool = False
    endpoint_conflict_count: int = 0


    def __post_init__(self) -> None:
        for field in fields(self):
            object.__setattr__(self, field.name, freeze(getattr(self, field.name)))


@dataclass(frozen=True, slots=True)
class Resources:
    project: Path
    finding_roots: tuple[Path, ...]
    evidence_root: Path
    coverage_paths: tuple[Path, ...] = ()


@dataclass(frozen=True, slots=True)
class ReportFinding:
    candidate_id: str
    title: str
    severity: str
    details: tuple[tuple[str, str], ...]


    def __post_init__(self) -> None:
        for field in fields(self):
            object.__setattr__(self, field.name, freeze(getattr(self, field.name)))


@dataclass(frozen=True, slots=True)
class ReportDocument:
    metadata: tuple[tuple[str, str], ...]
    status: str
    summary: tuple[str, ...]
    findings: tuple[ReportFinding, ...]
    evidence: tuple[tuple[str, str], ...]
    inventory: tuple[tuple[str, str], ...]
    validations: tuple[tuple[str, str], ...]
    coverage: tuple[tuple[str, str], ...]
    goals: tuple[tuple[str, str], ...]
    phases: tuple[tuple[str, str], ...]
    limitations: tuple[str, ...]
    severity_counts: tuple[tuple[str, int], ...]
    finding_count: int
    unfinalized_count: int
    unavailable_count: int
    omitted_count: int = 0

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if field.name == "findings":
                if any(not isinstance(item, ReportFinding) for item in value):
                    raise ReportError("Unsupported report finding value.")
                value = tuple(value)
            else:
                value = freeze(value)
            object.__setattr__(self, field.name, value)

    def text_values(self) -> tuple[str, ...]:
        def walk(item: Any):
            if isinstance(item, str):
                yield item
            elif is_dataclass(item):
                for field in fields(item):
                    yield from walk(getattr(item, field.name))
            elif isinstance(item, tuple):
                for child in item:
                    yield from walk(child)
        return tuple(walk(self))
