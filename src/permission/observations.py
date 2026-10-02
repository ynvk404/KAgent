"""Runtime observations and explicit verifier contracts, never model assertions.

Observations attest captured bytes, not vulnerability truth. Unsupported class
verifiers remain unavailable. Raw artifacts remain usable as unverified proof.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import json
import time
from typing import Any, Callable
from urllib.parse import urlsplit
import uuid
from pathlib import Path
import os


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
        from src.permission.verifiers import register_production_verifiers
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
            ("candidate_class", "target", "endpoint", "method", "parameter", "location")], default=str).encode()).hexdigest()

    def capture(self, action, status: int, body: bytes, *, complete: bool) -> str:
        item = Observation("obs_" + uuid.uuid4().hex, action.epoch, action.method, action.url, action.transport_address,
                           action.digest, hashlib.sha256(body).hexdigest(), status, body, complete, time.time())
        self._items[item.id] = item
        while len(self._items) > 256:
            del self._items[next(iter(self._items))]
        self.persist()
        return item.id

    def register_verifier(self, candidate_class: str, verifier: Callable) -> None:
        """Trusted adapter startup only. This method is not a tool operation."""
        self._verifiers[candidate_class] = verifier

    def verify(self, candidate, references: tuple[str, ...], observation_ids: list[str], epoch: str) -> VerifiedResult | None:
        verifier = self._verifiers.get(candidate.candidate_class)
        if verifier is None or not observation_ids or len(set(observation_ids)) != len(observation_ids):
            return None
        items = tuple(self._items[key] for key in observation_ids if key in self._items)
        if len(items) != len(observation_ids) or any(not item.complete or item.epoch != epoch for item in items):
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

    def result(self, candidate_id: str, references: tuple[str, ...], epoch: str, candidate=None) -> VerifiedResult | None:
        entry = self._results.get(candidate_id)
        if entry is None or (entry[0] != epoch and candidate_id not in self._historical) or entry[1] != references:
            return None
        if candidate is not None and entry[3] != self.candidate_identity(candidate):
            return None
        if any(key not in self._items for key in entry[2].observation_ids):
            return None
        return entry[2]

    def operator_result(self, candidate, references, outcome, severity, impact):
        """Trusted UI callback after reviewing the exact immutable proof bundle.

        This is human-reviewed, not autonomous verification or authorization.
        No model-facing tool can call it.
        """
        if outcome not in {"confirmed", "not-confirmed"} or not references or not impact.strip():
            raise ValueError("review requires proof, outcome and observed impact")
        result = VerifiedResult(outcome, "Operator-reviewed: " + impact, severity, (), "Operator reviewed linked immutable evidence.", "operator-reviewed")
        self._results[candidate.id] = ("operator-reviewed", tuple(references), result, self.candidate_identity(candidate))
        self._historical.add(candidate.id)
        self.persist()
        return result
