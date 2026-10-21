"""Coordinated offline transactions; all stores live under pytest tmp_path."""
import asyncio
import json
import multiprocessing
import os
import stat
from dataclasses import replace
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import Any, cast

import pytest

from src.intelligence import store as module
from src.intelligence.store import (
    IntelligencePersistenceError, IntelligenceScenario, IntelligenceStore, LearningInput,
)
from src.target.origin import HTTPOrigin


@pytest.fixture
def store(tmp_path):
    return IntelligenceStore(cwd=tmp_path / "project", home=tmp_path / "home")


def row(identifier="new"):
    return IntelligenceScenario(id=identifier, title=identifier, lesson=f"Technical observation for {identifier}.")


def seed(store, data=None):
    store.project_path.parent.mkdir(parents=True, exist_ok=True)
    raw = data if data is not None else (json.dumps(row("old").to_wire()) + "\n").encode()
    store.project_path.write_bytes(raw)
    return raw


@pytest.mark.parametrize("suffix", [b"", b"\n", b"\n\n", b"\r\n"])
def test_append_valid_json_tail_with_or_without_newline(store, suffix):
    original = seed(store, json.dumps(row("old").to_wire()).encode() + suffix)
    assert len(store.append_batch([row()])) == 1
    assert store.project_path.read_bytes().startswith(original)
    assert [r.id for r in module.read_jsonl(store.project_path, "project")] == ["old", "new"]


@pytest.mark.parametrize("separator", ["\u2028", "\u2029", "\x85"])
def test_append_readback_uses_physical_jsonl_lines(store, separator):
    saved = store.append_batch([replace(row(), lesson=f"Observed condition{separator}retained response context.")])
    assert len(saved) == 1
    assert module.read_jsonl(store.project_path, "project")[0].lesson == saved[0].lesson


@pytest.mark.parametrize("tail", [b'{"id":', b'broken\n', b'[]\n', b'{"id":"unfinished', b'\xff'])
def test_malformed_tail_refuses_append_and_preserves_bytes(store, tail):
    original = seed(store, b'{"id":"old"}\n' + tail)
    with pytest.raises(IntelligencePersistenceError, match="tail.*preserved"):
        store.append_batch([row()])
    assert store.project_path.read_bytes() == original


def test_missing_filelock_fails_closed_for_every_writer(store, monkeypatch):
    original = seed(store)
    monkeypatch.setattr(module, "_HAS_FILELOCK", False)
    for action in [lambda: store.append_batch([row()]),
                   lambda: store.prune_if_too_long(store.project_path, "project"),
                   lambda: asyncio.run(store.clear("project"))]:
        with pytest.raises(IntelligencePersistenceError, match="require filelock"):
            action()
        assert store.project_path.read_bytes() == original


@pytest.mark.parametrize("operation", ["write", "short-write", "partial-write", "flush", "read"])
def test_io_faults_never_report_success_or_lose_existing_bytes(store, monkeypatch, operation):
    original = seed(store)
    store.read_scenarios(store.project_path, "project")
    real_fdopen = module.os.fdopen

    class FaultStream:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def write(self, data):
            if operation == "write":
                raise OSError("synthetic write failure")
            if operation == "partial-write":
                self.stream.write(data[:12])
                self.stream.flush()
                raise OSError("synthetic partial append")
            if operation == "short-write":
                return self.stream.write(data[:12])
            return self.stream.write(data)

        def flush(self):
            if operation == "flush":
                raise OSError("synthetic flush failure")
            return self.stream.flush()

        def read(self, count):
            return b"" if operation == "read" else self.stream.read(count)

    monkeypatch.setattr(module.os, "fdopen", lambda fd, mode, **kw: FaultStream(real_fdopen(fd, mode, **kw)))
    with pytest.raises((OSError, IntelligencePersistenceError)):
        store.append_batch([row()])
    assert store.project_path.read_bytes().startswith(original)
    assert str(store.project_path) not in store.file_cache
    if operation in {"partial-write", "short-write"}:
        with pytest.raises(IntelligencePersistenceError, match="tail"):
            store.append_batch([row("later")])
    else:
        assert [r.id for r in store.read_scenarios(store.project_path, "project")] == [
            r.id for r in module.read_jsonl(store.project_path, "project")]


def test_open_failure_preserves_data(store, monkeypatch):
    original = seed(store)
    real_open = module.os.open

    def fail_open(path, flags, *args, **kwargs):
        if Path(path) == store.project_path and flags & os.O_APPEND:
            raise OSError("synthetic open failure")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", fail_open)
    with pytest.raises(OSError, match="synthetic"):
        store.append_batch([row()])
    assert store.project_path.read_bytes() == original


def test_fsync_failure_has_uncertain_commit_and_refreshes_cache(store, monkeypatch):
    original = seed(store)
    store.read_scenarios(store.project_path, "project")

    def fail(_fd):
        raise OSError("synthetic fsync failure")

    monkeypatch.setattr(module.os, "fsync", fail)
    with pytest.raises(OSError, match="fsync"):
        store.append_batch([row()])
    assert store.project_path.read_bytes().startswith(original)
    assert str(store.project_path) not in store.file_cache
    assert {r.id for r in store.read_scenarios(store.project_path, "project")} == {"old", "new"}


def test_read_failure_before_dedup_is_not_treated_as_empty_store(store, monkeypatch):
    original = seed(store)
    real_read = Path.read_text

    def fail(path, *args, **kwargs):
        if path == store.project_path:
            raise OSError("synthetic read failure")
        return real_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail)
    with pytest.raises(OSError, match="read failure"):
        store.append_batch([row()])
    assert store.project_path.read_bytes() == original
    assert str(store.project_path) not in store.file_cache


def test_oversized_batch_cannot_report_records_removed_by_retention(store, monkeypatch):
    original = seed(store)
    monkeypatch.setattr(module, "MAX_SCENARIOS_PER_FILE", 1)
    with pytest.raises(IntelligencePersistenceError, match="retention"):
        store.append_batch([row("a"), row("b")])
    assert store.project_path.read_bytes() == original


def test_prune_does_not_discard_corrupt_interior_bytes(store, monkeypatch):
    original = seed(store, b'{"id":"old","title":"Old"}\nbroken\n' +
                    (json.dumps(row("second").to_wire()) + "\n").encode())
    monkeypatch.setattr(module, "MAX_SCENARIOS_PER_FILE", 1)
    store.prune_if_too_long(store.project_path, "project")
    assert store.project_path.read_bytes() == original


def test_prune_replace_failure_leaves_successfully_appended_records_readable(store, monkeypatch):
    original = seed(store)
    monkeypatch.setattr(module, "MAX_SCENARIOS_PER_FILE", 1)

    def fail(*_args):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(module.os, "replace", fail)
    assert store.append_batch([row()])[0].id == "new"
    assert store.project_path.read_bytes().startswith(original)
    assert {r.id for r in store.read_scenarios(store.project_path, "project")} == {"old", "new"}


@pytest.mark.parametrize("replacement", [False, True])
def test_cache_detects_equal_size_and_mtime_edit_or_replacement(store, replacement):
    original = seed(store)
    cached = store.read_scenarios(store.project_path, "project")
    before = store.project_path.stat()
    edited = original.replace(b'"old"', b'"new"')
    assert len(edited) == len(original)
    if replacement:
        other = store.project_path.with_suffix(".replacement")
        other.write_bytes(edited)
        os.utime(other, ns=(before.st_atime_ns, before.st_mtime_ns))
        os.replace(other, store.project_path)
    else:
        store.project_path.write_bytes(edited)
        os.utime(store.project_path, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = store.project_path.stat()
    assert before.st_mtime_ns == after.st_mtime_ns and before.st_size == after.st_size
    assert module.file_fingerprint(before) != module.file_fingerprint(after)
    fresh = store.read_scenarios(store.project_path, "project")
    assert fresh is not cached and fresh[0].id == "new"


def test_cache_observes_other_supported_writer(store):
    seed(store)
    store.read_scenarios(store.project_path, "project")
    other = IntelligenceStore(cwd=store.project_path.parents[2], home=store.personal_path.parents[2])
    other.append_batch([row()])
    assert {r.id for r in store.read_scenarios(store.project_path, "project")} == {"old", "new"}


def test_warm_retrieval_does_not_rehash_corpus_content(store, monkeypatch):
    store.append_batch([row()])
    store.search("technical observation", 5)  # Warm file and per-record identities.

    def unexpected_hash(*_args, **_kwargs):
        raise AssertionError("unchanged records must not be hashed on each turn")

    monkeypatch.setattr(module.hashlib, "sha256", unexpected_hash)
    assert store.search("technical observation", 5)


async def reached(event):
    assert await asyncio.wait_for(asyncio.to_thread(event.wait, 4), 5)


def pause_commit(monkeypatch):
    entered, release, finished = Event(), Event(), Event()
    real_write = module.write_records

    def held(path, records, separator):
        entered.set()
        assert release.wait(5), "test did not release the commit"
        try:
            return real_write(path, records, separator)
        finally:
            finished.set()

    monkeypatch.setattr(module, "write_records", held)
    return entered, release, finished


def agent_view(store, session, port):
    return SimpleNamespace(intelligence=store, store=SimpleNamespace(id=session),
                           target=SimpleNamespace(base_url=lambda: f"http://juice.lab:{port}"))


async def test_snapshot_captured_before_scheduling_and_transition_before_commit(store, tmp_path, monkeypatch):
    from src.agent.agent import Agent, build_turn_learning_inputs

    entered, release, _ = pause_commit(monkeypatch)
    fake = agent_view(store, "session-a", 3000)
    destination_a = store.project_path
    pending = Agent.learn_intelligence(cast(Any, fake), build_turn_learning_inputs(
        "Test this input once.", "Command failed because permission errors prevented the requested write."))
    other = IntelligenceStore(cwd=tmp_path / "project-b", home=tmp_path / "home-b")
    # Transition B before the coroutine even starts, then hold A before commit.
    fake.intelligence, fake.store, fake.target = other, SimpleNamespace(id="session-b"), agent_view(other, "b", 8081).target
    store.project_path = other.project_path  # Snapshot also owns its destination.
    task = asyncio.create_task(pending)
    try:
        await reached(entered)
        assert not destination_a.exists() and not other.project_path.exists()
    finally:
        release.set()
        await asyncio.wait_for(task, 5)
    rows = module.read_jsonl(destination_a, "project")
    assert rows and all(r.source_session_id == "session-a" and r.source_role == "assistant" for r in rows)
    assert all(r.target_origin == HTTPOrigin.from_url("http://juice.lab:3000").to_dict() for r in rows)
    assert not other.project_path.exists()


async def test_cancellation_joins_started_transaction_and_preserves_owner(store, monkeypatch):
    entered, release, finished = pause_commit(monkeypatch)
    pending = store.learn_from_text(
        "## Lessons learned\n- Probe failed because a permission error blocked the file read.",
        "session-a", target_origin=HTTPOrigin.from_url("http://juice.lab:3000"),
    )
    task = asyncio.create_task(pending)
    try:
        await reached(entered)
        task.cancel()
        # Deterministic loop checkpoints, no sleep-based race assertions.
        pulse = asyncio.Event()
        asyncio.get_running_loop().call_soon(pulse.set)
        await asyncio.wait_for(pulse.wait(), 1)
        assert not task.done() and not finished.is_set()
        task.cancel()  # Repeated cancellation must still join the writer.
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
    assert finished.is_set()
    rows = module.read_jsonl(store.project_path, "project")
    assert rows and all(r.source_session_id == "session-a" for r in rows)
    assert str(store.project_path) not in store.file_cache


async def test_commit_admitted_before_transition_keeps_snapshot_in_shared_project(store, monkeypatch):
    entered, release = Event(), Event()
    real_fsync = module.os.fsync

    def held(fd):
        real_fsync(fd)
        if stat.S_ISREG(os.fstat(fd).st_mode) and not entered.is_set():
            entered.set()  # A's bytes have actually been flushed and fsynced.
            assert release.wait(5)

    monkeypatch.setattr(module.os, "fsync", held)
    origin_a = HTTPOrigin.from_url("http://juice.lab:3000")
    task_a = asyncio.create_task(store.learn_from_text(
        "## Lessons learned\n- Probe failed because a permission error blocked the first endpoint.",
        "session-a", target_origin=origin_a))
    try:
        await reached(entered)
        task_b = asyncio.create_task(store.learn_from_text(
            "## Lessons learned\n- Probe failed because a syntax error blocked the second endpoint.",
            "session-b", target_origin=HTTPOrigin.from_url("http://juice.lab:8081")))
    finally:
        release.set()
        await asyncio.wait_for(task_a, 5)
    await asyncio.wait_for(task_b, 5)
    rows = module.read_jsonl(store.project_path, "project")
    assert {r.source_session_id for r in rows} == {"session-a", "session-b"}
    assert all(r.target_origin == origin_a.to_dict() for r in rows if r.source_session_id == "session-a")
    assert all(r.target_origin == HTTPOrigin.from_url("http://juice.lab:8081").to_dict()
               for r in rows if r.source_session_id == "session-b")


async def test_cancelled_faulting_worker_is_joined_and_does_not_start_recovery(store, monkeypatch):
    original = seed(store)
    entered, release, finished = Event(), Event(), Event()

    def held_failure(*_args):
        entered.set()
        assert release.wait(5)
        finished.set()
        raise OSError("synthetic failure before write")

    monkeypatch.setattr(module, "write_records", held_failure)
    task = asyncio.create_task(store.learn_from_text(
        "## Lessons learned\n- Probe failed because a permission error blocked the file read.", "owner-a"))
    try:
        await reached(entered)
        task.cancel()
        pulse = asyncio.Event()
        asyncio.get_running_loop().call_soon(pulse.set)
        await asyncio.wait_for(pulse.wait(), 1)
        assert not task.done()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
    assert finished.is_set() and store.project_path.read_bytes() == original
    assert str(store.project_path) not in store.file_cache


async def test_event_loop_progress_while_worker_waits_for_cross_process_lock(store, monkeypatch):
    store.project_path.parent.mkdir(parents=True)
    attempted = Event()
    real_lock = module._cross_process_lock

    def observed(path):
        attempted.set()
        return real_lock(path)

    monkeypatch.setattr(module, "_cross_process_lock", observed)
    blocker = module.filelock.FileLock(str(store.project_path) + ".lock")
    blocker.acquire()
    task = asyncio.create_task(store.learn_from_text(
        "## Lessons learned\n- Probe failed because DNS resolution returned a temporary error.", "lock-owner"))
    try:
        await reached(attempted)
        pulse = asyncio.Event()
        asyncio.get_running_loop().call_soon(pulse.set)
        await asyncio.wait_for(pulse.wait(), 1)
        assert not task.done()
    finally:
        blocker.release()
        await asyncio.wait_for(task, 5)


def process_writer(cwd, home, label, entered, release, attempted, done, results):
    """Spawn-safe writer with A held after reading and B attempting the same lock."""
    store = IntelligenceStore(cwd=cwd, home=home)
    if label == "a":
        original = store.read_scenarios

        def held(path, scope, **kwargs):
            rows = original(path, scope, **kwargs)
            entered.set()
            assert release.wait(8)
            return rows

        store.read_scenarios = held
    else:
        attempted.set()
    try:
        saved = store.append_batch([row("shared"), row(label)])
        results.put((label, [r.id for r in saved]))
    except Exception as error:
        results.put((label, type(error).__name__))
        raise
    finally:
        done.set()


def test_overlapping_process_writers_serialize_read_dedupe_commit(store):
    original = seed(store)
    context = multiprocessing.get_context("spawn")
    entered, release, attempted = context.Event(), context.Event(), context.Event()
    done_a, done_b, results = context.Event(), context.Event(), context.Queue()
    cwd, home = str(store.project_path.parents[2]), str(store.personal_path.parents[2])
    a = context.Process(target=process_writer, args=(cwd, home, "a", entered, release, attempted, done_a, results))
    b = context.Process(target=process_writer, args=(cwd, home, "b", entered, release, attempted, done_b, results))
    a.start()
    try:
        assert entered.wait(8)
        b.start()
        assert attempted.wait(8)
        assert not done_b.is_set()
    finally:
        release.set()
        a.join(10)
        if b.pid is not None:
            b.join(10)
    assert not a.is_alive() and not b.is_alive()
    assert a.exitcode == b.exitcode == 0
    saved = dict(results.get(timeout=2) for _ in range(2))
    assert saved == {"a": ["shared", "a"], "b": ["b"]}
    assert store.project_path.read_bytes().startswith(original)
    assert {r.id for r in module.read_jsonl(store.project_path, "project")} == {"old", "shared", "a", "b"}
    assert stat.S_IMODE(store.project_path.stat().st_mode) == 0o600
