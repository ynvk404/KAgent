"""Bounded producer evidence; retained hashes always describe the stored body.

Controller-admitted HTTP bodies may be raw under KAgent's lab-only storage
policy. Other producers and historical records keep their existing contract.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict, replace
import hashlib
import json
import time
from typing import Any, Callable, Literal
from urllib.parse import urlsplit
import uuid
from pathlib import Path
import os
import errno
import stat

_OWNER_UNSET = object()


class ObservationPersistenceError(OSError):
    """Expected storage failure; never contains output, paths or credentials."""

    def __init__(self, persistence: Literal["failed", "unknown"]):
        super().__init__("observation persistence " + persistence)
        self.persistence = persistence


def _owned_stream(fd: int, mode: str):
    try:
        return os.fdopen(fd, mode)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise



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
    source_kind: str | None = None
    producer: str | None = None
    session_id: str | None = None
    objective_id: str | None = None
    attempt_id: str | None = None
    candidate_binding: str | None = None
    retained_hash: str | None = None
    response_headers: tuple[tuple[str, str], ...] = ()
    elapsed_ms: float | None = None
    execution_status: str | None = None
    truncated: bool | None = None
    response_cap: int | None = None
    invocation_id: str | None = None
    source_details: dict[str, Any] | None = None


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
        self.owner_provider: Callable[[], dict | None] = lambda: None

    def attach_storage(self, path: Path) -> None:
        self.storage = path
        if path.exists():
            raw = json.loads(path.read_text())
            for row in raw.get("observations", [])[-256:]:
                row["body"] = bytes.fromhex(row["body"])
                row["response_headers"] = tuple(tuple(x) for x in row.get("response_headers", []))
                item = Observation(**row)
                self._items[item.id] = item
            for key, row in raw.get("results", {}).items():
                result = VerifiedResult(**{**row[2], "observation_ids": tuple(row[2]["observation_ids"])})
                self._results[key] = (row[0], tuple(row[1]), result, row[3])
                self._historical.add(key)

    def persist(self) -> None:
        self._persist_snapshot(self._items)

    def _persist_snapshot(self, items: dict[str, Observation]) -> None:
        """Persist a staged snapshot without publishing records or evictions.

        This transaction is synchronous: cancellation cannot leave an offloaded
        writer replacing the file after a caller has rolled back its state.
        """
        if self.storage is None:
            return
        from src.redaction.redact import apply_evidence
        rows = []
        for item in items.values():
            row = asdict(item)
            # Persist minimum redacted proof, never credentials/headers. Hash of
            # original response remains separate from this redacted derivative.
            if item.retained_hash is None:
                row["url"] = apply_evidence(row["url"])
                row["body"] = apply_evidence(item.body.decode(errors="replace")).encode().hex()
            else:
                # Preserve the exact already-redacted envelope that was hashed
                # at capture. Re-redaction must not change its resume identity.
                row["body"] = item.body.hex()
            rows.append(row)
        results = {key: [epoch, refs, asdict(result), identity]
                   for key, (epoch, refs, result, identity) in self._results.items()}
        for row in results.values():
            for field in ('observed_impact', 'response_excerpt'):
                row[2][field] = apply_evidence(row[2][field])
        # Serialization/redaction failures are programming/representation
        # failures, not expected filesystem failures to hide at the executor.
        data = json.dumps({"observations": rows, "results": results})
        temp = self.storage.with_suffix(".tmp")
        # Raw lab proof needs the same private mode during the temporary write,
        # not only after publication. Do not follow an incumbent temp symlink.
        created = False
        replacing = False
        try:
            self.storage.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
            created = True
            stream = _owned_stream(fd, "w")
            try:
                if hasattr(os, "fchmod"):
                    os.fchmod(stream.fileno(), 0o600)
                else:
                    temp.chmod(0o600)
                # Opaque epochs/IDs/hashes must retain their resume identity.
                if stream.write(data) != len(data):
                    raise OSError("incomplete observation snapshot write")
                stream.flush()
                os.fsync(stream.fileno())
            except BaseException:
                try:
                    stream.close()
                except OSError:
                    pass
                raise
            else:
                stream.close()
            temp.chmod(0o600)
            replacing = True
            temp.replace(self.storage)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                # O_NOFOLLOW is an integrity gate, not a storage outage.
                raise
            if replacing and self._snapshot_committed(data.encode()):
                return
            raise ObservationPersistenceError("unknown" if replacing else "failed") from exc
        finally:
            if created:
                try:
                    temp.unlink(missing_ok=True)
                except OSError:
                    # A leftover temp is never a published observation/receipt.
                    pass

    def _snapshot_committed(self, expected: bytes) -> bool:
        """Bounded verification of this exact snapshot after replace uncertainty."""
        assert self.storage is not None
        try:
            fd = os.open(self.storage, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with _owned_stream(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
                        or info.st_size != len(expected)):
                    return False
                return stream.read(len(expected) + 1) == expected
        except OSError:
            return False

    @staticmethod
    def candidate_identity(candidate) -> str:
        return hashlib.sha256(json.dumps([getattr(candidate, field, None) for field in
            ("candidate_class", "target", "endpoint", "method", "parameter", "location",
             "baseline_request_ref", "auth_context_ref", "content_type", "request_template")], default=str).encode()).hexdigest()

    def capture(self, action, status: int, body: bytes, *, complete: bool,
                validation_binding: tuple[str, str] | None = None, owner: Any = _OWNER_UNSET,
                response_headers=(), elapsed_ms=None, source_kind="native-http",
                producer="http", execution_status="completed", truncated=None, source_details=None,
                redact_text: Callable[[str], str] | None = None, retain_body: bool = False) -> str:
        from src.redaction.redact import apply_evidence
        from src.workflow.assessment import digest, source_row
        # Owner is snapshotted before execution, never assigned from proof prose.
        owner = self.owner_provider() if owner is _OWNER_UNSET else owner
        owner = owner or {}
        redact = redact_text or apply_evidence
        allowed_headers = {"location", "content-type", "content-length", "content-encoding",
                           "content-security-policy", "x-frame-options", "x-content-type-options",
                           "access-control-allow-origin", "access-control-allow-credentials",
                           "access-control-allow-methods", "vary", "cache-control"}
        headers = tuple((str(k).lower(), redact(str(v))[:2000])
                        for k, v in response_headers if str(k).lower() in allowed_headers)[:24]
        retained_body = body if retain_body else redact(body.decode(errors="replace")).encode()
        retained_truncated = len(retained_body) > 65536
        if source_kind == "tool-output":
            source_details = {**(source_details or {}), "retention_input_bytes": len(retained_body)}
        retained = retained_body[:65536]
        if not retain_body:
            # Redact the whole bounded envelope before byte capping. Avoid a
            # dangling UTF-8 sequence in this textual retained representation.
            retained = retained.decode("utf-8", errors="ignore").encode("utf-8")
        complete = complete and not retained_truncated
        item = Observation("obs_" + uuid.uuid4().hex, action.epoch, action.method,
            redact(action.url), action.transport_address, action.digest,
            hashlib.sha256(body).hexdigest(), status,
            retained, complete, time.time(),
            owner.get("candidate_id") or (validation_binding or (None, None))[0],
            (validation_binding or (None, None))[1], source_kind, producer,
            owner.get("session_id"), owner.get("objective_id"), owner.get("id"),
            owner.get("candidate_binding"), None, headers, elapsed_ms, execution_status,
            (not complete if truncated is None else truncated) or retained_truncated, getattr(action, "response_cap", None),
            getattr(action, "invocation_id", None), source_details)
        item = replace(item, retained_hash=digest(source_row(item)))
        staged = {**self._items, item.id: item}
        while len(staged) > 256:
            del staged[next(iter(staged))]
        self._persist_snapshot(staged)
        self._items = staged
        return item.id

    def capture_output(self, producer, output, *, owner, completed=True, truncated=False) -> str:
        from types import SimpleNamespace
        from src.permission.runtime.execution import _active
        active = _active.get()
        receipt = active[1] if active else None
        owner = owner or {}
        body = str(output).encode()
        truncated = truncated or len(body) > 65536
        action = SimpleNamespace(epoch=owner.get("epoch", ""), method="OUTPUT", url="",
                                 transport_address="process", digest=receipt.digest if receipt else "",
                                 response_cap=65536, invocation_id=receipt.id if receipt else None)
        key = self.capture(action, 0, body, complete=completed and not truncated,
                           owner=owner, source_kind="tool-output", producer=producer,
                           execution_status="completed" if completed else "failed", truncated=truncated,
                           source_details={"hash_basis": "bounded-rendered-envelope-utf8"})
        return key

    def import_capture(self, capture, *, owner, runtime_store=None) -> str:
        """Selected scoped bridge capture: import association, never native execution."""
        from types import SimpleNamespace
        from src.browser.redacted_view import request_view
        from src.workflow.assessment import digest
        from src.browser.scoped_store import ScopedCaptureStore
        from src.permission.runtime.execution import current_policy
        policy = current_policy()
        trusted = bool(policy is not None and policy.observations is self
            and type(runtime_store) is ScopedCaptureStore and runtime_store.policy is policy
            and policy.nested_allowed() and runtime_store.get_request(capture.id) is capture)
        view = request_view(capture)
        body = (view.get("response_body") or "").encode()[:65536]
        action = SimpleNamespace(epoch=(owner or {}).get("epoch", "") or (
            policy.engagement.http_permissions.epoch if trusted and policy is not None else ""), method=capture.method,
            url=capture.url, transport_address="import", digest=digest({"method": capture.method,
                "url": view.get("url"), "request_body": view.get("request_body")}), response_cap=65536)
        details = {"import_id": "import_" + uuid.uuid4().hex, "capture_id": capture.id,
            "bridge_source": capture.source, "received_at": capture.received_at,
            "time_basis": "local-import", "reported_elapsed_ms": capture.elapsed_ms,
            "original_owner": None, "receipt_id": None,
            "original_request_hash": None, "original_response_hash": None,
            "hash_basis": "bounded-capture-string-utf8" if trusted else "selected-redacted-import",
            "completeness": "source-reported" if capture.response_complete is not None else "unknown"}
        if trusted:
            assert policy is not None
            details["body_representation"] = "bounded-capture-string-utf8"
            details["analysis_session"] = policy.session_id or policy.engagement.http_permissions.session_id
        return self.capture(action, capture.status or 0, body,
            complete=capture.response_complete is True and capture.status is not None and len(body) < 65536,
            owner=owner or {}, source_kind="imported-capture", producer="scoped-capture-bridge",
            response_headers=[(h.name, h.value) for h in capture.response_headers or []],
            source_details=details, retain_body=trusted)

    def register_verifier(self, candidate_class: str, verifier: Callable) -> None:
        """Explicit legacy/diagnostic adapter use; never a new result admission gate."""
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
