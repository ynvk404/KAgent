"""F3/F4: offline native processes, bounded observations and storage faults."""
from __future__ import annotations

import asyncio
import base64
from dataclasses import asdict, replace
import errno
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
import zlib

import pytest

from src.engagement.state import EngagementState
from src.permission.runtime.execution import ExecutionPolicy
from src.permission.runtime.observations import ObservationStore, ObservationPersistenceError
from src.tools.common.runtime_metadata import RuntimeMetadata
from src.tools.execution.shell import MAX_OUTPUT_BYTES, run_with_capture
from src.redaction.redact import apply_evidence
from src.workflow.assessment import digest, source_row


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    policy = ExecutionPolicy(EngagementState(), tmp_path)
    policy.observations.attach_storage(tmp_path / "observations" / "capture.json")
    monkeypatch.setattr("src.permission.runtime.execution.current_policy", lambda: policy)
    return policy


async def emit(stdout: bytes, stderr: bytes = b"", code: int = 0):
    out = base64.b64encode(zlib.compress(stdout))
    err = base64.b64encode(zlib.compress(stderr))
    return await run_with_capture(sys.executable, ["-c",
        f"import os,base64,zlib; os.write(1,zlib.decompress(base64.b64decode({out!r}))); "
        f"os.write(2,zlib.decompress(base64.b64decode({err!r}))); raise SystemExit({code})"], 5, None)


def metadata(output) -> RuntimeMetadata:
    assert output.runtime_metadata is not None
    return output.runtime_metadata


def envelope(output):
    return str(output).rsplit("\n[runtime observation: ", 1)[0]


@pytest.mark.parametrize("stdout_size,stderr_size", [
    (40000, 40000), (MAX_OUTPUT_BYTES, 0), (MAX_OUTPUT_BYTES + 1, 0),
    (0, MAX_OUTPUT_BYTES + 1), (70000, 70000), (100, 50),
])
async def test_capture_and_retention_have_separate_completeness(runtime, stdout_size, stderr_size):
    output = await emit(b"a" * stdout_size, b"b" * stderr_size)
    meta = metadata(output)
    assert meta is not None and meta.stdout is not None and meta.stderr is not None
    assert meta.process == "exit" and meta.exit_code == 0
    for stream, size in ((meta.stdout, stdout_size), (meta.stderr, stderr_size)):
        assert stream.observed_bytes == size and stream.retained_bytes == min(size, MAX_OUTPUT_BYTES)
        assert stream.eof and stream.complete == (size <= MAX_OUTPUT_BYTES)
    rendered = envelope(output).encode()
    assert meta.capture_envelope_bytes == len(rendered)
    item = runtime.observations._items[meta.observation_id]
    assert meta.retained_bytes == len(item.body) <= 65536
    assert meta.retention_input_bytes == len(rendered)
    assert meta.retention == ("partial" if len(rendered) > 65536 else "complete")
    assert meta.delivery == "complete" and meta.delivered_bytes == len(output.encode())
    assert meta.persistence == "persisted"
    assert output.truncated == (stdout_size > MAX_OUTPUT_BYTES or stderr_size > MAX_OUTPUT_BYTES)
    assert item.complete == (not output.truncated and len(rendered) <= 65536)
    assert item.response_hash == hashlib.sha256(rendered).hexdigest()
    assert item.source_details["hash_basis"] == meta.response_hash_basis == "bounded-rendered-envelope-utf8"
    assert item.retained_hash == digest(source_row(item))
    restored = ObservationStore()
    restored.attach_storage(runtime.observations.storage)
    assert source_row(restored._items[item.id]) == source_row(item)
    assert restored._items[item.id].retained_hash == item.retained_hash


@pytest.mark.parametrize("data", [b"\xff" + b"a" * 65534, ("☃" * 21845).encode(), b"a" * 65535 + b"\xff"], ids=["invalid-head", "unicode-boundary", "invalid-tail"])
async def test_utf8_replacement_and_framing_are_counted_without_invalid_retained_text(runtime, data):
    output = await emit(data)
    meta = metadata(output)
    assert meta.stdout is not None
    assert meta.stdout.observed_bytes == len(data) and meta.stdout.complete
    assert meta.capture_envelope_bytes == len(envelope(output).encode())
    item = runtime.observations._items[meta.observation_id]
    item.body.decode("utf-8", errors="strict")
    assert len(item.body) <= 65536 and meta.retention == "partial" and not item.complete


async def test_redaction_precedes_observation_byte_cap(runtime):
    secret = "synthetic-secret-for-boundary-regression"
    output = await emit(b"a" * 65480 + ("\npassword=" + secret + "\n").encode(), b"tail")
    item = runtime.observations._items[metadata(output).observation_id]
    assert secret[:12].encode() not in item.body and b"[REDACTED" in item.body
    assert item.response_hash == hashlib.sha256(envelope(output).encode()).hexdigest()
    meta = metadata(output)
    assert meta.retention_input_bytes is not None and meta.capture_envelope_bytes is not None
    assert meta.retention_input_bytes == len(apply_evidence(envelope(output)).encode())


@pytest.mark.parametrize("replacement", ["", "☃" * 22000], ids=["shrink", "expand"])
async def test_redaction_length_change_is_reported(runtime, monkeypatch, replacement):
    monkeypatch.setattr("src.redaction.redact.apply_evidence", lambda value: value.replace("REPLACE", replacement))
    output = await emit(b"REPLACE")
    meta = metadata(output)
    item = runtime.observations._items[meta.observation_id]
    expected = envelope(output).replace("REPLACE", replacement).encode()
    assert meta.retention_input_bytes == len(expected)
    assert meta.retained_bytes == len(item.body)
    assert meta.retention == ("partial" if len(expected) > 65536 else "complete")
    assert item.complete == (len(expected) <= 65536)
    item.body.decode("utf-8", errors="strict")


def inject_fault(store, monkeypatch, stage, error=None):
    error = error or OSError("synthetic storage failure containing private text")
    def fail(*args, **kwargs):
        raise error
    if stage in {"write", "flush", "close", "short-write"}:
        original = os.fdopen
        class Stream:
            def __init__(self, wrapped): self.wrapped = wrapped
            def __enter__(self): return self
            def __exit__(self, *args): return self.wrapped.__exit__(*args)
            def fileno(self): return self.wrapped.fileno()
            def write(self, value):
                if stage == "short-write": return self.wrapped.write(value[:10])
                return fail() if stage == "write" else self.wrapped.write(value)
            def flush(self): return fail() if stage == "flush" else self.wrapped.flush()
            def close(self):
                self.wrapped.close()
                if stage == "close": fail()
        monkeypatch.setattr(os, "fdopen", lambda fd, mode: Stream(original(fd, mode)) if mode == "w" else original(fd, mode))
    elif stage in {"open", "fsync", "fchmod"}:
        monkeypatch.setattr(os, stage, fail)
    elif stage in {"mkdir", "chmod", "replace"}:
        monkeypatch.setattr(Path, stage, fail)
    else:
        raise AssertionError(stage)


@pytest.mark.parametrize("stage", ["mkdir", "open", "write", "short-write", "flush", "close", "fsync", "fchmod", "chmod", "replace"])
@pytest.mark.parametrize("code", [0, 3])
async def test_storage_fault_preserves_process_and_never_publishes(runtime, monkeypatch, stage, code):
    store = runtime.observations
    incumbent = store.capture_output("shell", "incumbent", owner=None)
    previous_items = store._items.copy()
    previous_file = store.storage.read_bytes()
    original_spawn = asyncio.create_subprocess_exec
    spawned = AsyncMock(wraps=original_spawn)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawned)
    inject_fault(store, monkeypatch, stage)
    output = await emit(b"process stdout", b"process stderr", code)
    assert str(output) == f"exit: {code}\nstdout:\nprocess stdout\nstderr:\nprocess stderr"
    assert output.status == ("success" if code == 0 else "error")
    assert metadata(output).process == "exit" and metadata(output).exit_code == code
    assert metadata(output).persistence == ("unknown" if stage == "replace" else "failed")
    assert metadata(output).retention == "unavailable" and metadata(output).observation_id is None
    assert "runtime observation:" not in output and "private text" not in output
    assert store._items == previous_items and incumbent in store._items
    assert store.storage.read_bytes() == previous_file
    spawned.assert_awaited_once()


async def test_store_full_failed_capture_does_not_evict_incumbents(runtime, monkeypatch):
    store = runtime.observations
    key = store.capture_output("shell", "incumbent", owner=None)
    prototype = store._items[key]
    store._items = {}
    for index in range(256):
        item = replace(prototype, id="obs_" + f"{index:032x}")
        store._items[item.id] = replace(item, retained_hash=digest(source_row(item)))
    store.persist()
    before = store._items.copy()
    original = store._persist_snapshot
    def inspect(staged):
        assert store._items == before and len(staged) == 256
        assert next(iter(before)) not in staged
        return original(staged)
    monkeypatch.setattr(store, "_persist_snapshot", inspect)
    inject_fault(store, monkeypatch, "fsync")
    result = await emit(b"new process result")
    assert metadata(result).persistence == "failed" and store._items == before


async def test_replace_then_raise_is_published_only_after_exact_bounded_readback(runtime, monkeypatch):
    original = Path.replace
    checked = []
    def replace_then_raise(path, target):
        original(path, target)
        raise OSError("synthetic failure after replace")
    original_check = runtime.observations._snapshot_committed
    def check(expected):
        assert not runtime.observations._items
        checked.append(len(expected))
        return original_check(expected)
    monkeypatch.setattr(Path, "replace", replace_then_raise)
    monkeypatch.setattr(runtime.observations, "_snapshot_committed", check)
    result = await emit(b"committed process result")
    assert metadata(result).persistence == "persisted" and metadata(result).observation_id in runtime.observations._items
    assert len(checked) == 1


async def test_unverified_replace_uncertainty_stays_unpublished(runtime, monkeypatch):
    original = Path.replace
    def replace_then_raise(path, target):
        original(path, target)
        raise OSError("synthetic failure after replace")
    monkeypatch.setattr(Path, "replace", replace_then_raise)
    monkeypatch.setattr(runtime.observations, "_snapshot_committed", lambda expected: False)
    result = await emit(b"bounded result")
    assert metadata(result).persistence == "unknown" and metadata(result).observation_id is None
    assert not runtime.observations._items and "runtime observation:" not in result


async def test_memory_only_is_intentional_and_never_claimed_durable(runtime):
    runtime.observations.storage = None
    result = await emit(b"memory result")
    assert metadata(result).persistence == "memory-only"
    assert metadata(result).observation_id in runtime.observations._items


@pytest.mark.parametrize("error", [asyncio.CancelledError(), RuntimeError("programming failure"), OSError(errno.ELOOP, "integrity gate")])
async def test_cancellation_programming_and_integrity_failures_propagate(runtime, monkeypatch, error):
    inject_fault(runtime.observations, monkeypatch, "write" if not isinstance(error, OSError) else "open", error)
    with pytest.raises(type(error)):
        await emit(b"process ran once")
    assert not runtime.observations._items
    assert not runtime.observations.storage.with_suffix(".tmp").exists()


async def test_two_storage_failures_do_not_mask_process_or_publish(runtime, monkeypatch):
    inject_fault(runtime.observations, monkeypatch, "write")
    monkeypatch.setattr(Path, "unlink", Mock(side_effect=OSError("cleanup unavailable")))
    result = await emit(b"stdout", b"stderr", 1)
    assert metadata(result).exit_code == 1 and metadata(result).persistence == "failed"
    assert not runtime.observations._items and "exit: 1" in result


async def test_partial_capture_is_not_promoted_by_metadata(runtime):
    result = await emit(b"a" * 40000, b"b" * 40000)
    key = metadata(result).observation_id
    verifier = Mock()
    runtime.observations.register_verifier("fixture", verifier)
    candidate = SimpleNamespace(candidate_class="fixture")
    assert runtime.observations.verify(candidate, (), [key], "") is None
    verifier.assert_not_called()


def test_legacy_hash_material_is_unchanged_when_new_capture_is_added(tmp_path):
    store = ObservationStore()
    action = SimpleNamespace(epoch="legacy", method="GET", url="https://fixture.test/path", transport_address="fixture", digest="request")
    key = store.capture(action, 200, b"legacy proof", complete=True)
    old = replace(store._items[key], source_details=None)
    old = replace(old, retained_hash=digest(source_row(old)))
    body = asdict(old)
    body["body"] = old.body.hex()
    path = tmp_path / "historical.json"
    path.write_text(json.dumps({"observations": [body], "results": {}}))
    loaded = ObservationStore()
    loaded.attach_storage(path)
    loaded.capture_output("shell", "new envelope", owner=None)
    restored = ObservationStore()
    restored.attach_storage(path)
    assert restored._items[key] == old
    assert restored._items[key].retained_hash == digest(source_row(old))


@pytest.mark.parametrize("data", [None, {"process": "forged"}, {"delivered_bytes": True},
    {"retained_bytes": 2**64}, {"observation_id": "obs_forged"}, {"secret": "discarded"},
    {"stdout": {"observed_bytes": 1, "retained_bytes": 2, "eof": True}}])
def test_archival_runtime_metadata_is_bounded_and_missing_means_unknown(data):
    assert RuntimeMetadata.from_dict(data) is None


async def test_timeout_and_capture_limits_survive_storage_failure(runtime, monkeypatch):
    inject_fault(runtime.observations, monkeypatch, "fsync")
    output = await run_with_capture(sys.executable, ["-c", "import time; print('before timeout', flush=True); time.sleep(30)"], 0.1, None)
    assert output.status == "error" and output.error_kind == "timeout"
    assert metadata(output).process == "timeout" and metadata(output).exit_code is None
    assert metadata(output).persistence == "failed" and "before timeout" in output
    assert not runtime.observations._items


async def test_capture_partial_and_persistence_failure_are_independent(runtime, monkeypatch):
    inject_fault(runtime.observations, monkeypatch, "fsync")
    output = await emit(b"x" * 70000, b"y" * 70000)
    meta = metadata(output)
    assert meta.stdout is not None and meta.stderr is not None
    assert not meta.stdout.complete and not meta.stderr.complete and output.truncated
    assert meta.delivery == "complete" and meta.retention == "unavailable" and meta.persistence == "failed"
    assert meta.exit_code == 0 and output.status == "success" and not runtime.observations._items


async def test_abort_keeps_cancellation_state_when_storage_also_fails(runtime, monkeypatch):
    inject_fault(runtime.observations, monkeypatch, "fsync")
    signal = SimpleNamespace(aborted=False)
    async def abort():
        await asyncio.sleep(0.1)
        signal.aborted = True
    abort_task = asyncio.create_task(abort())
    output = await run_with_capture(sys.executable, ["-c", "import time; print('before abort', flush=True); time.sleep(30)"], 5, signal)
    await abort_task
    assert output.status == "cancelled" and output.error_kind == "cancelled"
    assert metadata(output).process == "cancelled" and metadata(output).persistence == "failed"
    assert "before abort" in output and not runtime.observations._items


async def test_cancellation_is_not_replaced_by_close_failure(runtime, monkeypatch):
    original = os.fdopen
    class Stream:
        def __init__(self, wrapped): self.wrapped = wrapped
        def fileno(self): return self.wrapped.fileno()
        def write(self, value): raise asyncio.CancelledError()
        def close(self):
            self.wrapped.close()
            raise OSError("synthetic close failure during cancellation")
    monkeypatch.setattr(os, "fdopen", lambda fd, mode: Stream(original(fd, mode)))
    with pytest.raises(asyncio.CancelledError):
        await emit(b"bounded process output")
    assert not runtime.observations._items
    assert not runtime.observations.storage.with_suffix(".tmp").exists()


async def test_fdopen_failure_closes_the_acquired_descriptor(runtime, monkeypatch):
    original_open = os.open
    descriptors = []
    def acquire(path, flags, mode=0o777):
        fd = original_open(path, flags, mode)
        if Path(path) == runtime.observations.storage.with_suffix(".tmp"):
            descriptors.append(fd)
        return fd
    close = Mock(wraps=os.close)
    monkeypatch.setattr(os, "open", acquire)
    monkeypatch.setattr(os, "close", close)
    monkeypatch.setattr(os, "fdopen", Mock(side_effect=OSError("stream unavailable")))
    result = await emit(b"process stdout")
    assert metadata(result).persistence == "failed" and not runtime.observations._items
    assert len(descriptors) == 1
    assert any(call.args == (descriptors[0],) for call in close.call_args_list)
