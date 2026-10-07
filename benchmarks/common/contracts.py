"""Small v1 contracts. Operational envelopes deliberately have no truth fields."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any, TypeVar

SCHEMA = 1
PROTOCOL = "supplied-input-v1"
SCENARIO = "scenario1"
SELECTION = "sha256-rank-v1"
MAPPING = "benchmarkjava-request-v1"
DEFAULT_SEED = 1729
CLASSES = ("sql-injection", "cross-site-scripting")
STATUSES = {"scheduled", "started", "completed", "timeout", "runtime-error", "provider-error",
            "budget-exhausted", "crashed", "setup-error", "not-run"}
PARTITIONS = ("evaluable", "unresolved", "execution-failed", "invalid-result", "not-run")


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_json(text: str | bytes) -> Any:
    def distinct(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('nonfinite JSON number')
    return json.loads(text, object_pairs_hook=distinct, parse_constant=constant)


def read_json(path: Path, *, maximum=32 * 1024 * 1024) -> Any:
    if path.is_symlink() or path.stat().st_size > maximum:
        raise ValueError('untrusted/oversized JSON artifact')
    return parse_json(path.read_bytes())


def identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}", value):
        raise ValueError("invalid artifact identifier")
    return value


def write_new(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


T = TypeVar("T")


def decode(cls: type[T], raw: dict) -> T:
    if not isinstance(raw, dict) or set(raw) != {f.name for f in fields(cls)}:  # type: ignore[arg-type]
        raise ValueError(f"malformed {cls.__name__} fields")
    if raw.get("schema_version") != SCHEMA or type(raw.get("schema_version")) is not int:
        raise ValueError("unsupported schema version")
    return cls(**raw)


@dataclass(frozen=True)
class OperationalCaseInput:
    case_id: str
    vulnerability_class: str
    method: str
    servlet_path: str
    query: list[list[str]]
    body: list[list[str]]
    headers: dict[str, str]
    cookies: dict[str, str]
    input_location: str
    input_name: str
    input_component: str = "value"
    content_type: str | None = None
    schema_version: int = SCHEMA

    def __post_init__(self):
        identifier(self.case_id)
        if self.vulnerability_class not in CLASSES or self.method not in {"GET", "POST"}:
            raise ValueError("unsupported operational class/method")
        if (not self.servlet_path.startswith("/") or self.servlet_path.startswith("//")
                or any(x in self.servlet_path for x in ("?", "#", "..", "\\"))):
            raise ValueError("invalid servlet path")
        if self.input_location not in {"query", "body", "header", "cookie"} or self.input_component not in {"name", "value"}:
            raise ValueError("invalid operational input")
        if not self.input_name or len(json.dumps(asdict(self))) > 12000:
            raise ValueError("invalid or oversized operational input")
        for pairs in (self.query, self.body):
            if not isinstance(pairs, list) or any(not isinstance(p, list) or len(p) != 2 or
                                                 any(not isinstance(v, str) for v in p) for p in pairs):
                raise ValueError("invalid request pairs")
        for mapping in (self.headers, self.cookies):
            if not isinstance(mapping, dict) or any(not isinstance(k, str) or not isinstance(v, str) or
                                                   '\n' in k + v or '\r' in k + v for k, v in mapping.items()):
                raise ValueError("invalid request headers/cookies")
        names = ({p[0] for p in self.query} if self.input_location == "query" else
                 {p[0] for p in self.body} if self.input_location == "body" else
                 set(self.headers) if self.input_location == "header" else set(self.cookies))
        if self.input_name not in names:
            raise ValueError("selected input absent from operational fixture")


@dataclass(frozen=True)
class GroundTruth:
    case_id: str
    vulnerability_class: str
    expected_vulnerable: bool
    cwe: int
    source_ref: str
    schema_version: int = SCHEMA

    def __post_init__(self):
        identifier(self.case_id)
        if self.vulnerability_class not in CLASSES or type(self.expected_vulnerable) is not bool or type(self.cwe) is not int:
            raise ValueError("invalid truth")
        if self.cwe != {"sql-injection": 89, "cross-site-scripting": 79}[self.vulnerability_class]:
            raise ValueError("truth CWE mismatch")


@dataclass(frozen=True)
class RuntimeSettings:
    target: str
    context_path: str
    authorized_lab: bool
    target_state: str
    timeout_seconds: float = 180
    http_requests: int = 24
    tool_calls: int = 80
    agent_calls: int = 24
    deployment_metadata: str | None = None
    schema_version: int = SCHEMA

    def __post_init__(self):
        from urllib.parse import urlsplit
        from src.target.origin import HTTPOrigin
        origin = HTTPOrigin.from_url(self.target)
        parsed = urlsplit(self.target)
        if parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("target must be an exact credential-free origin; use context_path")
        if (not isinstance(self.context_path, str) or (self.context_path and not self.context_path.startswith('/'))
                or any(x in self.context_path for x in ("..", "?", "#", "\\", "//"))):
            raise ValueError("invalid deployment context path")
        if type(self.authorized_lab) is not bool or self.target_state not in {"confirmation-only", "external-reset"}:
            raise ValueError("invalid authorization/state declaration")
        if type(self.timeout_seconds) not in {float, int} or not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout must be finite and positive")
        if any(type(v) is not int or v <= 0 for v in (self.http_requests, self.tool_calls, self.agent_calls)):
            raise ValueError("budgets must be finite positive integers")


@dataclass(frozen=True)
class RunManifest:
    run_id: str
    dataset: dict[str, Any]
    truth: list[dict]
    operational: list[dict]
    execution_order: list[str]
    seed: int
    mode: str
    runtime: dict | None = None
    reproducibility: dict = field(default_factory=dict)
    selection_version: str = SELECTION
    mapping_version: str = MAPPING
    protocol_version: str = PROTOCOL
    scenario: str = SCENARIO
    schema_version: int = SCHEMA

    def __post_init__(self):
        identifier(self.run_id)
        if (self.selection_version, self.mapping_version, self.protocol_version, self.scenario) != (SELECTION, MAPPING, PROTOCOL, SCENARIO):
            raise ValueError("unsupported manifest protocol")
        if self.mode not in {"default", "reduced", "smoke", "single"} or type(self.seed) is not int:
            raise ValueError("invalid selection settings")
        truths = [decode(GroundTruth, r) for r in self.truth]
        ops = [decode(OperationalCaseInput, r) for r in self.operational]
        ids = [t.case_id for t in truths]
        if not ids or len(set(ids)) != len(ids) or len(self.execution_order) != len(ids) or len(set(self.execution_order)) != len(ids) or set(self.execution_order) != set(ids):
            raise ValueError("duplicate/missing execution schedule")
        if [o.case_id for o in ops] != ids or any(t.vulnerability_class != o.vulnerability_class for t, o in zip(truths, ops)):
            raise ValueError("operational/truth identity mismatch")
        if self.mode != "single":
            n = {"default": 20, "reduced": 10, "smoke": 3}[self.mode]
            if any(sum(t.vulnerability_class == c and t.expected_vulnerable == v for t in truths) != n for c in CLASSES for v in (True, False)):
                raise ValueError("manifest strata counts mismatch")
        elif len(ids) != 1:
            raise ValueError("single selection requires one case")
        if not isinstance(self.dataset, dict) or not isinstance(self.dataset.get("version"), str) or not self.dataset.get("artifacts"):
            raise ValueError("missing dataset identity")
        for ref, hashed in self.dataset["artifacts"].items():
            if Path(ref).is_absolute() or '..' in Path(ref).parts or not re.fullmatch('[0-9a-f]{64}', hashed):
                raise ValueError("invalid dataset artifact hash/reference")
        if self.runtime is not None:
            decode(RuntimeSettings, self.runtime)


@dataclass(frozen=True)
class RuntimeMetrics:
    agent_seconds: float | None
    setup_seconds: float | None
    teardown_seconds: float | None
    first_terminal_seconds: float | None
    llm: dict
    tools: dict
    http_admitted: int | None
    schema_version: int = SCHEMA

    def __post_init__(self):
        for value in (self.agent_seconds, self.setup_seconds, self.teardown_seconds, self.first_terminal_seconds):
            if value is not None and (type(value) not in {float, int} or not math.isfinite(value) or value < 0):
                raise ValueError('invalid runtime duration')
        if self.first_terminal_seconds is not None and (self.agent_seconds is None or self.first_terminal_seconds > self.agent_seconds):
            raise ValueError('terminal time outside execution interval')


@dataclass(frozen=True)
class CanonicalResultExport:
    run_id: str
    case_id: str
    execution_id: str
    session_id: str
    candidate_id: str
    objective_id: str | None
    target: dict
    epoch: str
    workflow: dict
    result_id: str | None
    latest_position: int | None
    accepted_at_freeze: bool
    candidate_binding: str
    protocol_version: str = PROTOCOL
    schema_version: int = SCHEMA

    def __post_init__(self):
        for value in (self.run_id, self.case_id, self.execution_id, self.session_id, self.candidate_id, self.epoch):
            identifier(value)
        if self.objective_id is not None:
            identifier(self.objective_id)
        if self.result_id is not None:
            identifier(self.result_id)
        if self.protocol_version != PROTOCOL or type(self.accepted_at_freeze) is not bool:
            raise ValueError('invalid canonical protocol/acceptance projection')
        if (not isinstance(self.workflow, dict) or not isinstance(self.target, dict)
                or set(self.target) != {'base_url', 'origin', 'revision'}
                or type(self.target['revision']) is not int or self.target['revision'] < 0):
            raise ValueError('invalid canonical frozen state')
        if self.latest_position is not None and (type(self.latest_position) is not int or self.latest_position < 0):
            raise ValueError('invalid canonical result position')
        if not isinstance(self.candidate_binding, str) or not re.fullmatch('[0-9a-f]{64}', self.candidate_binding):
            raise ValueError('invalid canonical Candidate binding')


@dataclass(frozen=True)
class CaseExecution:
    run_id: str
    case_id: str
    execution_id: str
    status: str
    stop_reason: str | None
    result: dict | None
    metrics: dict | None
    runtime_metadata: dict
    error: str | None = None
    schema_version: int = SCHEMA

    def __post_init__(self):
        for value in (self.run_id, self.case_id, self.execution_id):
            identifier(value)
        if self.status not in STATUSES:
            raise ValueError("invalid execution status")
        if not isinstance(self.runtime_metadata, dict) or len(json.dumps(self.runtime_metadata)) > 32000:
            raise ValueError('invalid/oversized runtime metadata')
        if self.result is not None:
            decode(CanonicalResultExport, self.result)
        if self.metrics is not None:
            decode(RuntimeMetrics, self.metrics)


@dataclass(frozen=True)
class EvaluationRecord:
    case_id: str
    partition: str
    reason: str
    confusion: str | None
    schema_version: int = SCHEMA
