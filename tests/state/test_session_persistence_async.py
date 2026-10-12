"""Offline ownership, failure and syscall coverage for session workers."""
import asyncio
import json
import os
from pathlib import Path
import threading

import pytest

from src.llm.core.types import Message
from src.session import store as module
from src.session.store import Store
from src.workflow.state import WorkflowState


@pytest.mark.parametrize("phase", ["serialize", "mkdir", "open", "replace", "chmod", "context_fsync", "clear"])
async def test_session_phases_yield_to_loop(tmp_path, monkeypatch, phase):
    store = Store(tmp_path / "session.json")
    await store.save([Message("user", "old")])
    entered, release = threading.Event(), threading.Event()
    loop_thread = threading.get_ident()
    threads = []
    def hold(fn):
        def wrapped(*args, **kwargs):
            threads.append(threading.get_ident())
            entered.set()
            assert release.wait(5)
            return fn(*args, **kwargs)
        return wrapped
    if phase == "serialize":
        monkeypatch.setattr(module, "_serialize_session", hold(module._serialize_session))
    elif phase == "mkdir":
        monkeypatch.setattr(Path, "mkdir", hold(Path.mkdir))
    elif phase == "open":
        monkeypatch.setattr(os, "open", hold(os.open))
    elif phase == "replace":
        monkeypatch.setattr(os, "replace", hold(os.replace))
    elif phase == "chmod":
        monkeypatch.setattr(os, "chmod", hold(os.chmod))
    elif phase == "context_fsync":
        monkeypatch.setattr(os, "fsync", hold(os.fsync))
    else:
        monkeypatch.setattr(Path, "unlink", hold(Path.unlink))
    operation = store.clear() if phase == "clear" else (
        store.save_context_snapshot("context") if phase == "context_fsync" else store.save([Message("user", "new")]))
    task = asyncio.create_task(operation)
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        # The injected syscall is still held while timers continue scheduling.
        for _ in range(3):
            await asyncio.sleep(0.02)
            assert not task.done()
        assert threads and all(t != loop_thread for t in threads)
    finally:
        release.set()
        await task
    if phase != "clear":
        assert store.load().messages[0].content == ("old" if phase == "context_fsync" else "new")
    assert not list(tmp_path.rglob("*.tmp.*"))


@pytest.mark.parametrize("worker_fails", [False, True])
@pytest.mark.parametrize("next_operation", ["save", "clear"])
async def test_cancelled_write_drains_before_other_store_retry_or_clear(tmp_path, monkeypatch, worker_fails, next_operation):
    store = Store(tmp_path / "session.json")
    await store.save([Message("user", "original")])
    entered, release = threading.Event(), threading.Event()
    original = os.replace
    calls = []
    def replace(src, dst):
        calls.append(str(dst))
        if len(calls) == 1:
            entered.set()
            assert release.wait(5)
            if worker_fails:
                raise OSError("injected replace failure")
        return original(src, dst)
    monkeypatch.setattr(os, "replace", replace)
    first = asyncio.create_task(store.save([Message("user", "cancelled snapshot")]))
    second = None
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        first.cancel()
        await asyncio.sleep(0.01)
        first.cancel()
        other = Store(store.path)
        second = asyncio.create_task(other.clear() if next_operation == "clear" else other.save([Message("user", "retry")]))
        await asyncio.sleep(0.04)
        assert not first.done() and not second.done()
        assert len(calls) == 1 and store._write_lock.locked()
        assert store.load().messages[0].content == "original"
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await first
        await second
        if next_operation == "save":
            assert store.load().messages[0].content == "retry"
        else:
            assert not store.path.exists()
        assert not store._write_lock.locked()
        assert not list(tmp_path.glob("*.tmp.*"))
    finally:
        release.set()
        await asyncio.gather(first, *([second] if second else []), return_exceptions=True)


async def test_overlapping_saves_own_queued_snapshot(tmp_path, monkeypatch):
    store = Store(tmp_path / "session.json")
    entered, release = threading.Event(), threading.Event()
    original = module._serialize_session
    def serialize(*args):
        if not entered.is_set():
            entered.set()
            assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(module, "_serialize_session", serialize)
    messages = [Message("user", "first")]
    state = WorkflowState(current_phase="validation")
    first = asyncio.create_task(store.save(messages, workflow=state))
    second = None
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        messages[0].content = "second"
        second = asyncio.create_task(store.save(messages, workflow=state))
        await asyncio.sleep(0.02)
        messages[0].content = "unsaved mutation"
        state.current_phase = "recon"
        release.set()
        await first
        await second
        loaded = store.load()
        assert loaded.messages[0].content == "second"
        assert loaded.workflow.current_phase == "validation"
    finally:
        release.set()
        await asyncio.gather(first, *([second] if second else []), return_exceptions=True)


async def test_failed_replace_preserves_previous_checkpoint_and_fsync_cadence(tmp_path, monkeypatch):
    store = Store(tmp_path / "session.json")
    fsyncs = []
    original_fsync = os.fsync
    def fsync(fd):
        fsyncs.append(fd)
        original_fsync(fd)
    monkeypatch.setattr(os, "fsync", fsync)
    await store.save([Message("user", "previous")])
    original = os.replace
    with monkeypatch.context() as patch:
        def fail(*args):
            raise OSError("injected replace failure")
        patch.setattr(os, "replace", fail)
        with pytest.raises(OSError):
            await store.save([Message("user", "failed")])
    assert store.load().messages[0].content == "previous"
    for _ in range(3):
        await store.save([Message("user", "retry")])
    assert len(fsyncs) == 2  # attempts 1 and 5, unchanged cadence
    assert os.replace is original
    assert json.loads(store.path.read_text())["messages"][0]["content"] == "retry"
    assert not list(tmp_path.glob("*.tmp.*"))


@pytest.mark.parametrize("worker_fails", [False, True])
async def test_cancelled_serialization_drains_without_starting_writer(tmp_path, monkeypatch, worker_fails):
    store = Store(tmp_path / "session.json")
    await store.save([Message("user", "original")])
    entered, release = threading.Event(), threading.Event()
    original = module._serialize_session
    def serialize(*args):
        entered.set()
        assert release.wait(5)
        if worker_fails:
            raise ValueError("injected serialization failure")
        return original(*args)
    monkeypatch.setattr(module, "_serialize_session", serialize)
    task = asyncio.create_task(store.save([Message("user", "cancelled")]))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        await asyncio.sleep(0.02)
        task.cancel()
        assert not task.done() and store._write_lock.locked()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert store.load().messages[0].content == "original"
        assert store.save_count == 1
        assert not list(tmp_path.glob("*.tmp.*"))
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)


async def test_context_cancellation_drains_before_next_context_writer(tmp_path, monkeypatch):
    store = Store.new_with_id(tmp_path / "sessions", "context")
    await store.save_context_snapshot("old")
    entered, release = threading.Event(), threading.Event()
    original = os.replace
    calls = []
    def replace(*args):
        calls.append(args)
        if len(calls) == 1:
            entered.set()
            assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(os, "replace", replace)
    first = asyncio.create_task(store.save_context_snapshot("cancelled"))
    second = None
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        first.cancel()
        await asyncio.sleep(0.01)
        first.cancel()
        other = Store.new_with_id(tmp_path / "sessions", "context")
        second = asyncio.create_task(other.save_context_snapshot("retry"))
        await asyncio.sleep(0.03)
        assert not first.done() and not second.done() and len(calls) == 1
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await first
        await second
        assert store.context_snapshot_path().read_text() == "retry\n"
        assert not list(tmp_path.rglob("*.tmp.*"))
    finally:
        release.set()
        await asyncio.gather(first, *([second] if second else []), return_exceptions=True)


async def test_cancelled_queued_save_never_enters_worker(tmp_path, monkeypatch):
    store = Store(tmp_path / "session.json")
    entered, release = threading.Event(), threading.Event()
    original = module._write_session
    calls = []
    def write(*args):
        calls.append(args)
        entered.set()
        assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(module, "_write_session", write)
    first = asyncio.create_task(store.save([Message("user", "owner")]))
    second = None
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        second = asyncio.create_task(Store(store.path).save([Message("user", "queued")]))
        await asyncio.sleep(0.02)
        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second
        release.set()
        await first
        assert len(calls) == 1
        assert store.load().messages[0].content == "owner"
    finally:
        release.set()
        await asyncio.gather(first, *([second] if second else []), return_exceptions=True)


async def test_checkpoint_deadline_drains_real_write_before_timeout_and_retry(tmp_path, monkeypatch):
    store = Store(tmp_path / "session.json")
    entered, release = threading.Event(), threading.Event()
    original = os.replace
    def replace(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(os, "replace", replace)
    async def checkpoint():
        async with asyncio.timeout(0.02):
            await store.save([Message("user", "deadline snapshot")])
    task = asyncio.create_task(checkpoint())
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        await asyncio.sleep(0.06)
        assert not task.done() and store._write_lock.locked()
        release.set()
        with pytest.raises(TimeoutError):
            await task
        assert store.load().messages[0].content == "deadline snapshot"
        assert not store._write_lock.locked()
        await store.save([Message("user", "retry")])
        assert store.load().messages[0].content == "retry"
        assert not list(tmp_path.glob("*.tmp.*"))
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("phase", ["serialize", "open", "fdopen", "write", "flush", "fsync"])
async def test_failed_session_phase_keeps_checkpoint_and_owned_temp_cleanup(tmp_path, monkeypatch, phase):
    store = Store(tmp_path / "session.json")
    await store.save([Message("user", "previous")])
    store.save_count = 4  # next attempt exercises the existing fifth-save fsync
    original_fdopen = os.fdopen
    descriptors = []
    def fail(*args, **kwargs):
        raise OSError("injected persistence failure")
    with monkeypatch.context() as patch:
        if phase == "serialize":
            patch.setattr(module, "_serialize_session", fail)
        elif phase in {"open", "fsync"}:
            patch.setattr(os, phase, fail)
        elif phase == "fdopen":
            def fail_fdopen(fd, *args, **kwargs):
                descriptors.append(fd)
                fail()
            patch.setattr(os, "fdopen", fail_fdopen)
        else:
            class Handle:
                def __init__(self, *args, **kwargs):
                    self.handle = original_fdopen(*args, **kwargs)
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    self.handle.close()
                def write(self, content):
                    return fail() if phase == "write" else self.handle.write(content)
                def flush(self):
                    return fail() if phase == "flush" else self.handle.flush()
            patch.setattr(os, "fdopen", Handle)
        with pytest.raises(OSError, match="injected"):
            await store.save([Message("user", "failed")])
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert store.load().messages[0].content == "previous"
    assert not list(tmp_path.glob("*.tmp.*"))
    assert not store._write_lock.locked()
    await store.save([Message("user", "retry")])
    assert store.load().messages[0].content == "retry"
