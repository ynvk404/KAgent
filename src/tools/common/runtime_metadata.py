"""Bounded controller diagnostics, never evidence, source rights or authority.

Missing metadata means unknown. Session decoding is archival only; tool text,
headers and MCP payloads are never decoded through this contract.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, replace
from typing import Any, Callable, Literal
import re

ProcessState = Literal["unknown", "not_started", "exit", "timeout", "cancelled"]
DeliveryState = Literal["unknown", "complete", "elided", "unavailable"]
RetentionState = Literal["unknown", "complete", "partial", "unavailable"]
PersistenceState = Literal["unknown", "persisted", "memory-only", "failed"]
HashBasis = Literal["unknown", "bounded-rendered-envelope-utf8"]


def _counter(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 2**63 - 1


@dataclass(frozen=True, slots=True)
class StreamCapture:
    observed_bytes: int
    retained_bytes: int
    eof: bool

    def __post_init__(self) -> None:
        if (not _counter(self.observed_bytes) or not _counter(self.retained_bytes)
                or self.retained_bytes > self.observed_bytes or type(self.eof) is not bool):
            raise ValueError("invalid stream capture counters")

    @property
    def complete(self) -> bool:
        return self.eof and self.retained_bytes == self.observed_bytes


@dataclass(frozen=True, slots=True)
class BrokerHTTPMetadata:
    """Fixed-size invocation totals; no URLs, headers, bodies or authority.

    A successful socket write does not prove that the consumer read the body.
    consumer_disconnects counts only disconnects actually observed by the broker.
    Observation totals describe HTTP captures, separately from shell retention.
    """
    requests: int = 0
    complete: int = 0
    truncated: int = 0
    interrupted: int = 0
    transport_failed: int = 0
    cancelled: int = 0
    consumer_disconnects: int = 0
    observation_persisted: int = 0
    observation_memory_only: int = 0
    observation_failed: int = 0
    observation_unknown: int = 0
    observation_partial: int = 0

    def __post_init__(self) -> None:
        values = asdict(self)
        if (any(not _counter(value) or value > self.requests for value in values.values())
                or self.complete + self.truncated + self.interrupted != self.requests
                or sum((self.observation_persisted, self.observation_memory_only,
                        self.observation_failed, self.observation_unknown)) > self.requests):
            raise ValueError("invalid broker HTTP counters")


@dataclass(frozen=True, slots=True)
class RuntimeMetadata:
    process: ProcessState = "unknown"
    exit_code: int | None = None
    # Only an actually observed negative subprocess return code establishes it.
    termination_signal: int | None = None
    stdout: StreamCapture | None = None
    stderr: StreamCapture | None = None
    # UTF-8 bytes of the bounded rendered envelope, including stream framing
    # and truncation markers, before evidence redaction and observation capping.
    capture_envelope_bytes: int | None = None
    delivery: DeliveryState = "unknown"
    # Bytes of the current representation, including framing/markers and any
    # runtime summary added at the Agent representation boundary.
    delivered_bytes: int | None = None
    # Completeness of the *redacted bounded envelope*, not evidence eligibility
    # or completeness of the raw process streams.
    retention: RetentionState = "unknown"
    retention_input_bytes: int | None = None
    retained_bytes: int | None = None
    observation_id: str | None = None
    # Persistence of this observation, independent of session saves and the
    # token-saving ToolResultStore cache (which never supplies evidence).
    persistence: PersistenceState = "unknown"
    response_hash_basis: HashBasis = "unknown"
    # None on historical records and executions without this broker collector.
    http: BrokerHTTPMetadata | None = None

    def __post_init__(self) -> None:
        for value, allowed in (
            (self.process, {"unknown", "not_started", "exit", "timeout", "cancelled"}),
            (self.delivery, {"unknown", "complete", "elided", "unavailable"}),
            (self.retention, {"unknown", "complete", "partial", "unavailable"}),
            (self.persistence, {"unknown", "persisted", "memory-only", "failed"}),
            (self.response_hash_basis, {"unknown", "bounded-rendered-envelope-utf8"}),
        ):
            if not isinstance(value, str) or value not in allowed:
                raise ValueError("invalid runtime metadata state")
        for value in (self.exit_code, self.termination_signal, self.capture_envelope_bytes,
                      self.delivered_bytes, self.retention_input_bytes, self.retained_bytes):
            if value is not None and not _counter(value):
                raise ValueError("invalid runtime metadata counter")
        if any(value is not None and type(value) is not StreamCapture for value in (self.stdout, self.stderr)):
            raise ValueError("invalid runtime stream metadata")
        if self.http is not None and type(self.http) is not BrokerHTTPMetadata:
            raise ValueError("invalid broker HTTP metadata")
        if self.observation_id is not None and (
                not isinstance(self.observation_id, str)
                or len(self.observation_id) != 36
                or re.fullmatch(r"obs_[0-9a-f]{32}", self.observation_id) is None):
            raise ValueError("invalid runtime observation reference")

    @classmethod
    def from_dict(cls, data: Any) -> RuntimeMetadata | None:
        """Private session compatibility only. Malformed/absent means unknown."""
        if not isinstance(data, dict) or set(data) - set(cls.__dataclass_fields__):
            return None
        try:
            fields = dict(data)
            if fields.get("http") is not None:
                if not isinstance(fields["http"], dict):
                    return None
                fields["http"] = BrokerHTTPMetadata(**fields["http"])
            for key in ("stdout", "stderr"):
                if fields.get(key) is not None:
                    row = fields[key]
                    if not isinstance(row, dict) or set(row) != {"observed_bytes", "retained_bytes", "eof"}:
                        return None
                    fields[key] = StreamCapture(**row)
            return cls(**fields)
        except (ValueError, TypeError):
            return None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Presence flags, not event counts. Union is idempotent across repeated
# compactions/resumes and bounded by this closed vocabulary, never by history.
_RUNTIME_LIMITATION_FLAGS = (
    "process=unknown", "process=not_started", "process=timeout", "process=cancelled",
    "process_exit_nonzero=1", "capture=unknown", "capture=partial",
    "delivery=unknown", "delivery=elided", "delivery=unavailable",
    "observation=unknown", "observation=partial", "observation=unavailable",
    "persistence=unknown", "persistence=memory-only", "persistence=failed",
    "upstream_truncated=1", "upstream_interrupted=1", "transport_failed=1",
    "http_cancelled=1", "consumer_disconnects=1",
    "http_observation_memory_only=1", "http_observation_failed=1",
    "http_observation_unknown=1", "http_observation_partial=1",
)


def load_runtime_limitations(data: Any) -> list[str]:
    """Archival compatibility: accept only fixed flags, never free-form text."""
    if not isinstance(data, list):
        return []
    flags = {item for item in data if isinstance(item, str) and item in _RUNTIME_LIMITATION_FLAGS}
    return [flag for flag in _RUNTIME_LIMITATION_FLAGS if flag in flags]


def collect_runtime_limitations(previous: Any, runtimes: Iterable[RuntimeMetadata | None]) -> list[str]:
    """Carry historical limitations without output, refs, or inferred rights.

    Missing legacy metadata is not reconstructed from tool/model prose. A
    complete later result cannot establish that an earlier limitation is fixed.
    """
    flags = set(load_runtime_limitations(previous))
    for metadata in runtimes:
        if type(metadata) is not RuntimeMetadata:
            continue
        flags.update((f"process={metadata.process}", f"delivery={metadata.delivery}",
                      f"observation={metadata.retention}", f"persistence={metadata.persistence}"))
        if metadata.process == "exit" and metadata.exit_code not in (None, 0):
            flags.add("process_exit_nonzero=1")
        if metadata.stdout is None or metadata.stderr is None:
            flags.add("capture=unknown")
        if any(stream is not None and not stream.complete for stream in (metadata.stdout, metadata.stderr)):
            flags.add("capture=partial")
        if metadata.http is not None:
            for counter, flag in (
                ("truncated", "upstream_truncated=1"), ("interrupted", "upstream_interrupted=1"),
                ("transport_failed", "transport_failed=1"), ("cancelled", "http_cancelled=1"),
                ("consumer_disconnects", "consumer_disconnects=1"),
                ("observation_memory_only", "http_observation_memory_only=1"),
                ("observation_failed", "http_observation_failed=1"),
                ("observation_unknown", "http_observation_unknown=1"),
                ("observation_partial", "http_observation_partial=1"),
            ):
                if getattr(metadata.http, counter) > 0:
                    flags.add(flag)
    return [flag for flag in _RUNTIME_LIMITATION_FLAGS if flag in flags]


def process_diagnostic(metadata: RuntimeMetadata | None) -> str | None:
    """Compact controller facts, never parsed output or inferred signal cause."""
    if type(metadata) is not RuntimeMetadata:
        return None
    if metadata.process == "exit" and metadata.exit_code not in (None, 0):
        return f"Shell exit {metadata.exit_code}"
    return {"not_started": "Shell executor not started", "timeout": "Shell timeout",
            "cancelled": "Shell cancelled"}.get(metadata.process)


def runtime_summary(metadata: RuntimeMetadata) -> str:
    def stream(value: StreamCapture | None) -> str:
        if value is None:
            return "unknown"
        return (f"{value.retained_bytes}/{value.observed_bytes}B"
                f",eof={str(value.eof).lower()}")
    code = f"({metadata.exit_code})" if metadata.exit_code is not None else ""
    ref = f"; ref={metadata.observation_id}" if metadata.observation_id else ""
    capture = ("unknown" if metadata.stdout is None or metadata.stderr is None else
               "complete" if metadata.stdout.complete and metadata.stderr.complete else "partial")
    http = ""
    if metadata.http is not None:
        h = metadata.http
        http = (f"; http_requests={h.requests} upstream_complete={h.complete}"
                f" upstream_truncated={h.truncated} upstream_interrupted={h.interrupted}"
                f" transport_failed={h.transport_failed} cancelled={h.cancelled}"
                f" consumer_disconnects={h.consumer_disconnects} consumer_read=unverified"
                f" http_observations=persisted:{h.observation_persisted},memory-only:{h.observation_memory_only},"
                f"failed:{h.observation_failed},unknown:{h.observation_unknown},partial:{h.observation_partial}")
    return (f"[Runtime: process={metadata.process}{code}; capture={capture} stdout={stream(metadata.stdout)}"
            f" stderr={stream(metadata.stderr)}; envelope={metadata.capture_envelope_bytes}B"
            f"; delivery={metadata.delivery}; observation={metadata.retention}"
            f" {metadata.retained_bytes}/{metadata.retention_input_bytes}B"
            f"; persistence={metadata.persistence}{ref}{http}]")


def runtime_view(content: str, metadata: RuntimeMetadata, *, delivery: DeliveryState,
                 budget: int | None = None,
                 render: Callable[[int], str] | None = None) -> tuple[str, RuntimeMetadata]:
    """Keep trusted limitations within the existing representation budget.

    Remove only an exact controller-generated summary matching this metadata;
    never derive process/stream state from arbitrary output or markers. A
    reference preview may put its reference header before the old summary.
    """
    current = replace(metadata, delivery=delivery)
    summary = runtime_summary(current) + "\n"
    body = render(max(0, budget - len(summary))) if render is not None and budget is not None else content
    for state in ("unknown", "complete", "elided", "unavailable"):
        previous = runtime_summary(replace(metadata, delivery=state)) + "\n"
        if body.startswith(previous) or "\n" + previous in body:
            body = body.replace(previous, "", 1)
            break
    if budget is not None:
        # Some existing renderers return their input when a tiny framing-only
        # budget cannot fit an omission marker. Charge the summary here too.
        body = body[:max(0, budget - len(summary))]
    text = summary + body
    return text, replace(current, delivered_bytes=len(text.encode("utf-8")))
