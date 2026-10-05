"""Runtime observations and explicit verifier contracts, never model assertions.

Observations attest captured bytes, not vulnerability truth. Unsupported class
verifiers remain unavailable. Raw artifacts remain usable as unverified proof.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import time
from typing import Any, Callable
from urllib.parse import urlsplit
import uuid
from pathlib import Path
import os

_pending_review: ContextVar[Any] = ContextVar("pending_operator_result", default=None)



@dataclass(frozen=True)
class Observation:
    id: str
    epoch: str
    method: str
    url: str
    transport: str
    request_hash: str
    response_hash: str
    status: int
    body: bytes
    complete: bool
    observed_at: float
    # Controller metadata for generic observations. Legacy/expert observations
    # have no such binding and cannot be borrowed by a generic attempt.
    candidate_id: str | None = None
    probe_binding: str | None = None


@dataclass(frozen=True)
class VerifiedResult:
    outcome: str
    observed_impact: str
    severity: str
    observation_ids: tuple[str, ...]
    response_excerpt: str = ""
    verification_source: str = "trusted-adapter"


class ObservationStore:
    def __init__(self):
        self._items: dict[str, Observation] = {}
        self._verifiers: dict[str, Callable[[Any, tuple[Observation, ...]], VerifiedResult | None]] = {}
        self._results: dict[str, tuple[str, tuple[str, ...], VerifiedResult, str]] = {}
        self.storage: Path | None = None
        self._historical: set[str] = set()
        self._reviews: dict[str, str] = {}
        from src.permission.runtime.verifiers import register_production_verifiers
        register_production_verifiers(self)

    def attach_storage(self, path: Path) -> None:
        self.storage = path
        if path.exists():
            raw = json.loads(path.read_text())
            for row in raw.get("observations", [])[-256:]:
                row["body"] = bytes.fromhex(row["body"])
                item = Observation(**row)
                self._items[item.id] = item
            for key, row in raw.get("results", {}).items():
                result = VerifiedResult(**{**row[2], "observation_ids": tuple(row[2]["observation_ids"])})
                self._results[key] = (row[0], tuple(row[1]), result, row[3])
                self._historical.add(key)

    def persist(self) -> None:
        if self.storage is None:
            return
        from src.redact.redact import apply_evidence
        self.storage.parent.mkdir(parents=True, exist_ok=True)
        rows = []
        for item in self._items.values():
            row = asdict(item)
            # Persist minimum redacted proof, never credentials/headers. Hash of
            # original response remains separate from this redacted derivative.
            row["url"] = apply_evidence(row["url"])
            row["body"] = apply_evidence(item.body.decode(errors="replace")).encode().hex()
            rows.append(row)
        results = {key: [epoch, refs, asdict(result), identity]
                   for key, (epoch, refs, result, identity) in self._results.items()}
        for row in results.values():
            for field in ('observed_impact', 'response_excerpt'):
                row[2][field] = apply_evidence(row[2][field])
        temp = self.storage.with_suffix(".tmp")
        with temp.open("w") as stream:
            # Opaque epochs/IDs/hashes are controller metadata, not secrets.
            # Blanket redaction here corrupts the binding needed on resume.
            stream.write(json.dumps({"observations": rows, "results": results}))
            stream.flush()
            os.fsync(stream.fileno())
        temp.chmod(0o600)
        temp.replace(self.storage)

    @staticmethod
    def candidate_identity(candidate) -> str:
        return hashlib.sha256(json.dumps([getattr(candidate, field, None) for field in
            ("candidate_class", "target", "endpoint", "method", "parameter", "location",
             "baseline_request_ref", "auth_context_ref", "content_type", "request_template")], default=str).encode()).hexdigest()

    def capture(self, action, status: int, body: bytes, *, complete: bool,
                validation_binding: tuple[str, str] | None = None) -> str:
        item = Observation("obs_" + uuid.uuid4().hex, action.epoch, action.method, action.url, action.transport_address,
                           action.digest, hashlib.sha256(body).hexdigest(), status, body, complete, time.time(),
                           *(validation_binding or (None, None)))
        self._items[item.id] = item
        while len(self._items) > 256:
            del self._items[next(iter(self._items))]
        self.persist()
        return item.id

    def register_verifier(self, candidate_class: str, verifier: Callable) -> None:
        """Trusted adapter startup only. This method is not a tool operation."""
        self._verifiers[candidate_class] = verifier

    def verify(self, candidate, references: tuple[str, ...], observation_ids: list[str], epoch: str,
               *, validation_binding: tuple[str, str] | None = None) -> VerifiedResult | None:
        verifier = self._verifiers.get(candidate.candidate_class)
        if verifier is None or not observation_ids or len(set(observation_ids)) != len(observation_ids):
            return None
        items = tuple(self._items[key] for key in observation_ids if key in self._items)
        if len(items) != len(observation_ids) or any(not item.complete or item.epoch != epoch for item in items):
            return None
        if validation_binding is not None and any(
            (item.candidate_id, item.probe_binding) != validation_binding for item in items
        ):
            return None
        endpoint = (candidate.endpoint or "").split(" ")[-1]
        path = urlsplit(endpoint).path
        from src.target.origin import HTTPOrigin
        for item in items:
            if candidate.target and HTTPOrigin.from_url(item.url) != HTTPOrigin.from_url(candidate.target):
                return None
            if path and urlsplit(item.url).path != path:
                return None
            if candidate.method and item.method != candidate.method:
                return None
        result = verifier(candidate, items)
        if result is not None and result.observation_ids == tuple(observation_ids) and result.outcome in {"confirmed", "not-confirmed"}:
            self._results[candidate.id] = (epoch, references, result, self.candidate_identity(candidate))
            self._historical.discard(candidate.id)
            self.persist()
            return result
        return None

    def invalidate_result(self, candidate_id: str) -> None:
        """A new trusted attempt cannot reuse an earlier conclusion certificate."""
        old_results, old_historical = self._results.copy(), self._historical.copy()
        self._results.pop(candidate_id, None)
        self._historical.discard(candidate_id)
        try:
            self.persist()
        except BaseException:
            self._results, self._historical = old_results, old_historical
            raise

    def result(self, candidate_id: str, references: tuple[str, ...], epoch: str, candidate=None) -> VerifiedResult | None:
        pending = _pending_review.get()
        if pending is not None and pending[:4] == (self, candidate_id, references, epoch):
            if candidate is not None and pending[4] == self.candidate_identity(candidate):
                return pending[5]
        entry = self._results.get(candidate_id)
        if entry is None or (entry[0] != epoch and candidate_id not in self._historical) or entry[1] != references:
            return None
        if candidate is not None and entry[3] != self.candidate_identity(candidate):
            return None
        if any(key not in self._items for key in entry[2].observation_ids):
            return None
        return entry[2]

    def begin_review(self, candidate_id: str) -> str:
        """Transient ticket: only the latest review may commit a conclusion."""
        ticket = uuid.uuid4().hex
        self._reviews[candidate_id] = ticket
        return ticket

    def review_is_current(self, candidate_id: str, ticket: str) -> bool:
        return self._reviews.get(candidate_id) == ticket

    def finish_review(self, candidate_id: str, ticket: str) -> None:
        if self.review_is_current(candidate_id, ticket):
            self._reviews.pop(candidate_id)

    @contextmanager
    def _staged_operator_result(self, candidate, references, outcome, severity, impact, epoch, *, ticket, guard):
        """Task-local certificate used during workflow commit; never persisted here."""
        if not self.review_is_current(candidate.id, ticket):
            raise ValueError("operator review is stale or superseded")
        if guard is None:
            raise ValueError("operator review must include its current-state guard")
        guard()
        result = self._operator_certificate(references, outcome, severity, impact)
        token = _pending_review.set((self, candidate.id, tuple(references), epoch,
                                     self.candidate_identity(candidate), result, guard))
        try:
            yield result
        finally:
            _pending_review.reset(token)

    def check_pending_review(self) -> None:
        pending = _pending_review.get()
        if pending is not None and pending[0] is self and pending[6] is not None:
            pending[6]()

    def _commit_review(self, state, candidate, references, result, ticket):
        """Publish the existing broad certificate after workflow/session commit."""
        latest = state.latest_result(candidate.id)
        if (not self.review_is_current(candidate.id, ticket) or latest is None
                or tuple(latest.evidence_refs) != tuple(references)
                or latest.outcome != result.outcome or latest.coverage_synced is False):
            raise ValueError("review has no consistent committed validation result")
        old_results, old_historical = self._results.copy(), self._historical.copy()
        self._results[candidate.id] = ("operator-reviewed", tuple(references), result, self.candidate_identity(candidate))
        self._historical.add(candidate.id)
        try:
            self.persist()
        except BaseException:
            self._results, self._historical = old_results, old_historical
            raise
        self.finish_review(candidate.id, ticket)

    @staticmethod
    def _operator_certificate(references, outcome, severity, impact):
        if outcome not in {"confirmed", "not-confirmed"} or not references or not impact.strip():
            raise ValueError("review requires proof, outcome and observed impact")
        return VerifiedResult(outcome, "Operator-reviewed: " + impact, severity, (), "Operator reviewed linked immutable evidence.", "operator-reviewed")
