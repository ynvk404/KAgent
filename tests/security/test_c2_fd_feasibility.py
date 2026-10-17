"""C2-only design probes. Prototype is NOT a production FileWrite replacement.

Green observation tests include rejected designs and residual counterexamples.
No namespace, platform, permission lease or full semantics proof is implied.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading

import pytest

from src.engagement.state import EngagementState
from src.permission.permission import AlwaysAllow, AlwaysDeny, YoloPrompter, UserControlledRefusal
from src.permission.runtime.execution import ExecutionBlocked, ExecutionPolicy, file_resource_identity
from src.tools.common.registry import Registry
from src.tools.execution.file import FileWriteTool, gate_sensitive_path


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    violations = []
    def deny(*args, **kwargs):
        violations.append(True)
        raise AssertionError("C2 probe forbids network")
    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    yield
    assert not violations


@pytest.fixture
def scratch():
    with tempfile.TemporaryDirectory(prefix="kagent-c2-fd-", dir="/tmp") as directory:
        yield Path(directory)


@contextmanager
def active(root, args, signal=None):
    policy = ExecutionPolicy(EngagementState(), root)
    prompter = YoloPrompter(AlwaysAllow(), True)
    prompter.bind_execution_policy(policy)
    tool = FileWriteTool()
    token = policy.start(policy.prepare(tool, args, signal=signal), tool, args, signal)
    try:
        yield policy, tool, prompter
    finally:
        policy.stop(token)


def supported():
    return (os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW")
            and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NONBLOCK"))


class Bound:
    """Test-local POSIX candidate; root is trusted, parents must already exist.

    No mkdir, creation, truncation or byte reads during binding. Component
    no-follow traversal and fstat compare actual opened leaf to reviewed value.
    This does NOT make the namespace immovable: see reparent counterexample.
    """
    def __init__(self, root, path, *, capability=True, before_open=lambda: None):
        self.parent = -1
        self.leaf = -1
        if not capability or not supported():
            raise NotImplementedError("no safe supported handle adapter")
        relative = path.relative_to(root)
        if not relative.parts or any(p in {"..", "."} for p in relative.parts):
            raise ValueError("unsupported resource spelling")
        self.name = relative.name
        expected = file_resource_identity(path)
        before_open()
        try:
            self.parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            for part in relative.parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=self.parent)
                os.close(self.parent)
                self.parent = child
            try:
                self.leaf = os.open(self.name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                    dir_fd=self.parent)
            except FileNotFoundError:
                if expected[1:] != ("absent",):
                    raise ValueError("reviewed file disappeared")
            else:
                info = os.fstat(self.leaf)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or expected[1:] != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)):
                    raise ValueError("opened object differs from reviewed object")
        except BaseException:
            self.close()
            raise

    def begin(self):
        # Controller calls only AFTER proposed admission, with no intervening
        # await. Creation/truncation are effects, not a resource-ready check.
        if self.leaf < 0:
            self.leaf = os.open(self.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o644, dir_fd=self.parent)
        os.ftruncate(self.leaf, 0)
        fd, self.leaf = self.leaf, -1
        return fd

    def close(self):
        for name in ("leaf", "parent"):
            fd = getattr(self, name)
            if fd >= 0:
                setattr(self, name, -1)
                os.close(fd)


def write_close(fd, data):
    """Worker receives owned descriptor + immutable bytes, never a pathname."""
    try:
        remaining = memoryview(data)
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise OSError("zero-byte write")
            remaining = remaining[written:]
    finally:
        os.close(fd)


async def join_worker(pending):
    try:
        return await asyncio.shield(pending)
    except asyncio.CancelledError:
        while not pending.done():
            try:
                await asyncio.shield(pending)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        # Explicit PROTOTYPE precedence: retrieve error, cancellation wins.
        if not pending.cancelled():
            pending.exception()
        raise


async def proposed(policy, tool, prompter, args, lock, *, signal=None,
                   ready=None, before_open=lambda: None, after_admit=lambda: None,
                   worker=write_close, capability=True):
    """Bounded candidate, NOT proof of unchanged policy or FileWrite semantics.

    Controller explicitly grants one admitted continuation. Such a grant does
    not exist in production ExecutionPolicy; tests expose this semantic gap.
    Worker is submitted only after first controller mutation, avoiding a new
    pre-mutation scheduling await. Missing-parent support/chmod omitted here.
    """
    path = Path(args["path"]).absolute()
    payload = args["content"].encode("utf-8")
    await gate_sensitive_path(prompter, str(path), "write to", signal)
    async with lock:
        bound = Bound(policy.root, path, capability=capability, before_open=before_open)
        try:
            if ready is not None:
                await ready(bound)
            task = asyncio.current_task()
            if task is not None and task.cancelling():
                raise asyncio.CancelledError
            policy.revalidate_active(tool, args, signal)
            # Proposed admission point. No production policy mutation.
            after_admit()
            fd = bound.begin()
            pending = asyncio.create_task(asyncio.to_thread(worker, fd, payload))
            await join_worker(pending)
        finally:
            bound.close()


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("invalid", ["revoke", "signal", "task"])
async def test_before_admission_has_zero_mutation(scratch, existing, invalid):
    path = scratch / "out"
    if existing:
        path.write_bytes(b"original")
    args = {"path": str(path), "content": "new"}
    signal = asyncio.Event()
    with active(scratch, args, signal) as (policy, tool, prompter):
        async def ready(bound):
            assert path.read_bytes() == b"original" if existing else not path.exists()
            if invalid == "revoke":
                policy.revoke(tool.name())
            elif invalid == "signal":
                signal.set()
            else:
                current = asyncio.current_task()
                assert current is not None
                current.cancel()
                await asyncio.sleep(0)
        task = asyncio.create_task(proposed(policy, tool, prompter, args, asyncio.Lock(),
                                            signal=signal, ready=ready))
        with pytest.raises(ExecutionBlocked if invalid == "revoke" else asyncio.CancelledError):
            await task
    assert path.read_bytes() == b"original" if existing else not path.exists()


async def test_production_registry_deny_does_not_create_new_parent(scratch):
    policy = ExecutionPolicy(EngagementState(), scratch)
    prompter = YoloPrompter(AlwaysDeny())
    prompter.bind_execution_policy(policy)
    registry = Registry()
    registry.register(FileWriteTool())
    path = scratch / "missing" / "out"
    with pytest.raises(UserControlledRefusal):
        await registry.execute("file_write", {"path": str(path), "content": "new"}, None, prompter)
    assert not path.parent.exists() and policy.active == 0


@pytest.mark.parametrize("swap", ["leaf-symlink", "ancestor-symlink", "leaf-replace"])
async def test_bind_rejects_changed_actual_object_before_open(scratch, swap):
    lab = scratch / "lab"
    parent = lab / "parent"
    parent.mkdir(parents=True)
    destination = parent / "out"
    destination.write_bytes(b"original")
    outside = scratch / "outside"
    outside.mkdir()
    canary = outside / "out"
    canary.write_bytes(b"outside")
    args = {"path": str(destination), "content": "new"}
    def before_open():
        if swap == "ancestor-symlink":
            parent.rename(lab / "retired")
            parent.symlink_to(outside, target_is_directory=True)
        else:
            destination.rename(parent / "retired")
            if swap == "leaf-symlink":
                destination.symlink_to(canary)
            else:
                destination.write_bytes(b"replacement")
    with active(lab, args) as (policy, tool, prompter):
        with pytest.raises((OSError, ValueError)):
            await proposed(policy, tool, prompter, args, asyncio.Lock(), before_open=before_open)
    assert canary.read_bytes() == b"outside"
    assert (lab / "retired/out" if swap == "ancestor-symlink" else parent / "retired").read_bytes() == b"original"


async def test_swap_after_binding_before_admission_is_rejected(scratch):
    destination = scratch / "out"
    destination.write_bytes(b"original")
    outside = scratch / "outside"
    outside.write_bytes(b"outside")
    args = {"path": str(destination), "content": "new"}
    with active(scratch, args) as (policy, tool, prompter):
        async def ready(bound):
            destination.rename(scratch / "retired")
            destination.symlink_to(outside)
        with pytest.raises(ExecutionBlocked):
            await proposed(policy, tool, prompter, args, asyncio.Lock(), ready=ready)
    assert outside.read_bytes() == b"outside" and (scratch / "retired").read_bytes() == b"original"


async def test_symlink_after_admission_never_redirects_fd_write(scratch):
    destination = scratch / "out"
    destination.write_bytes(b"original")
    outside = scratch / "outside"
    outside.write_bytes(b"outside")
    args = {"path": str(destination), "content": "new"}
    def after_admit():
        destination.rename(scratch / "retired")
        destination.symlink_to(outside)
    with active(scratch, args) as (policy, tool, prompter):
        await proposed(policy, tool, prompter, args, asyncio.Lock(), after_admit=after_admit)
    assert outside.read_bytes() == b"outside" and (scratch / "retired").read_bytes() == b"new"


@pytest.mark.parametrize("existing", [False, True])
async def test_pinned_parent_can_be_reparented_outside_scope_counterexample(scratch, existing):
    lab, outside = scratch / "lab", scratch / "outside"
    parent = lab / "parent"
    parent.mkdir(parents=True)
    outside.mkdir()
    destination = parent / "out"
    if existing:
        destination.write_bytes(b"original")
    args = {"path": str(destination), "content": "new"}
    def after_admit():
        parent.rename(outside / "moved")
    with active(lab, args) as (policy, tool, prompter):
        await proposed(policy, tool, prompter, args, asyncio.Lock(), after_admit=after_admit)
    assert (outside / "moved/out").read_bytes() == b"new"
    print("C2_FD COUNTEREXAMPLE: pinned object writes outside current root namespace")


async def test_post_admission_revoke_is_explicit_proposed_lease_not_policy_proof(scratch):
    path = scratch / "out"
    path.write_bytes(b"original")
    args = {"path": str(path), "content": "new"}
    entered, release = threading.Event(), threading.Event()
    calls = []
    def held(fd, data):
        calls.append((type(fd), type(data), threading.get_ident()))
        entered.set()
        try:
            assert release.wait(5)
        except BaseException:
            os.close(fd)
            raise
        write_close(fd, data)
    with active(scratch, args) as (policy, tool, prompter):
        main_thread = threading.get_ident()
        task = asyncio.create_task(proposed(policy, tool, prompter, args, asyncio.Lock(), worker=held))
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            assert path.read_bytes() == b""  # first mutation on controller, not at bind
            policy.revoke(tool.name())
            assert not policy.nested_allowed()
            with pytest.raises(ExecutionBlocked):
                policy.prepare(tool, args)
            release.set()
            await task
            assert path.read_bytes() == b"new" and len(calls) == 1
            assert calls[0][0:2] == (int, bytes) and calls[0][2] != main_thread
            print("C2_FD DESIGN_ONLY: invalid active receipt, admitted continuation still writes")
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)


async def test_repeated_cancellation_drains_and_serializes_second_writer(scratch):
    path = scratch / "out"
    path.write_bytes(b"original")
    lock = asyncio.Lock()
    entered, release = threading.Event(), threading.Event()
    queued, second_entered = asyncio.Event(), threading.Event()
    def held(fd, data):
        entered.set()
        try:
            assert release.wait(5)
        except BaseException:
            os.close(fd)
            raise
        write_close(fd, data)
    async def call(content, worker):
        args = {"path": str(path), "content": content}
        with active(scratch, args) as (policy, tool, prompter):
            if content == "second":
                queued.set()
            await proposed(policy, tool, prompter, args, lock, worker=worker)
    def second_writer(fd, data):
        second_entered.set()
        write_close(fd, data)
    first = asyncio.create_task(call("first", held))
    second = None
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        first.cancel()
        await asyncio.sleep(0)  # cancellation enters drain
        first.cancel()
        second = asyncio.create_task(call("second", second_writer))
        await asyncio.wait_for(queued.wait(), 2)  # second has reached ownership wait
        assert lock.locked() and not first.done() and not second.done()
        assert not second_entered.is_set()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await first
        # The waiting receipt was prepared against the truncated first file.
        # Preserve production freshness rejection rather than bypassing it.
        with pytest.raises(ExecutionBlocked, match="arguments-changed"):
            await second
        assert not second_entered.is_set() and path.read_bytes() == b"first"
        await call("second", second_writer)  # fresh review/current resource
        assert path.read_bytes() == b"second" and not lock.locked()
    finally:
        release.set()
        await asyncio.gather(first, *([second] if second else []), return_exceptions=True)


async def test_partial_write_failure_propagates_without_atomicity_claim(scratch):
    path = scratch / "out"
    path.write_bytes(b"original")
    args = {"path": str(path), "content": "complete"}
    def broken(fd, data):
        try:
            os.write(fd, data[:3])
            raise OSError("synthetic partial write")
        finally:
            os.close(fd)
    with active(scratch, args) as (policy, tool, prompter):
        with pytest.raises(OSError, match="partial write"):
            await proposed(policy, tool, prompter, args, asyncio.Lock(), worker=broken)
    assert path.read_bytes() == b"com"


async def test_unsupported_adapter_fails_before_any_open(scratch, monkeypatch):
    args = {"path": str(scratch / "out"), "content": "new"}
    with active(scratch, args) as (policy, tool, prompter):
        def forbidden(*args, **kwargs):
            pytest.fail("unsupported adapter must not fallback to open")
        with monkeypatch.context() as patch:
            patch.setattr(os, "open", forbidden)
            with pytest.raises(NotImplementedError):
                await proposed(policy, tool, prompter, args, asyncio.Lock(), capability=False)
    assert not (scratch / "out").exists()


async def test_missing_parent_is_unimplemented_not_pre_admission_mkdir(scratch):
    args = {"path": str(scratch / "missing/out"), "content": "new"}
    with active(scratch, args) as (policy, tool, prompter):
        with pytest.raises(FileNotFoundError):
            await proposed(policy, tool, prompter, args, asyncio.Lock())
    assert not (scratch / "missing").exists()


async def test_revoke_between_proposed_admission_and_first_mutation_counterexample(scratch):
    path = scratch / "out"
    path.write_bytes(b"original")
    args = {"path": str(path), "content": "new"}
    with active(scratch, args) as (policy, tool, prompter):
        def after_admit():
            assert path.read_bytes() == b"original"
            policy.revoke(tool.name())
            with pytest.raises(ExecutionBlocked):
                policy.revalidate_active(tool, args, None)
        await proposed(policy, tool, prompter, args, asyncio.Lock(), after_admit=after_admit)
    assert path.read_bytes() == b"new"
    print("C2_FD DESIGN_ONLY: explicit proposed lease required before first mutation")


async def test_submission_failure_exposes_fd_transfer_gap_and_partial_effect(scratch, monkeypatch):
    path = scratch / "out"
    path.write_bytes(b"original")
    args = {"path": str(path), "content": "new"}
    captured = []
    original_to_thread = asyncio.to_thread
    async def unavailable(worker, *worker_args, **worker_kwargs):
        # Fault only the prototype's descriptor handoff. Permission gates may
        # perform their own unrelated, joined filesystem reads in workers.
        if worker is not write_close:
            return await original_to_thread(worker, *worker_args, **worker_kwargs)
        fd, payload = worker_args
        captured.append(fd)
        raise RuntimeError("synthetic executor submission unavailable")
    with active(scratch, args) as (policy, tool, prompter):
        with monkeypatch.context() as patch:
            patch.setattr(asyncio, "to_thread", unavailable)
            try:
                with pytest.raises(RuntimeError, match="submission"):
                    await proposed(policy, tool, prompter, args, asyncio.Lock())
                assert len(captured) == 1 and stat.S_ISREG(os.fstat(captured[0]).st_mode)
                assert path.read_bytes() == b""  # no atomic success/rollback
                print("C2_FD COUNTEREXAMPLE: minimal handoff leaks FD if submission fails")
            finally:
                for fd in captured:
                    os.close(fd)  # probe cleanup only; production untouched


async def test_worker_short_writes_are_completed_without_reopening_path(scratch, monkeypatch):
    args = {"path": str(scratch / "out"), "content": "unicode: ế\n"}
    original = os.write
    writes = []
    def short(fd, payload):
        writes.append(threading.get_ident())
        return original(fd, payload[:2])
    with active(scratch, args) as (policy, tool, prompter):
        with monkeypatch.context() as patch:
            patch.setattr(os, "write", short)
            await proposed(policy, tool, prompter, args, asyncio.Lock())
    assert (scratch / "out").read_bytes() == args["content"].encode("utf-8")
    assert len(writes) > 1 and all(t != threading.get_ident() for t in writes)


async def test_filesystem_rejecting_safe_open_never_falls_back(scratch, monkeypatch):
    args = {"path": str(scratch / "out"), "content": "new"}
    attempts = []
    def unsupported(*args, **kwargs):
        attempts.append(args)
        raise OSError(errno.EOPNOTSUPP, "synthetic unsupported safe open")
    with active(scratch, args) as (policy, tool, prompter):
        with monkeypatch.context() as patch:
            patch.setattr(f"{__name__}.supported", lambda: True)
            patch.setattr(os, "open", unsupported)
            with pytest.raises(OSError, match="unsupported safe open"):
                await proposed(policy, tool, prompter, args, asyncio.Lock())
    assert len(attempts) == 1 and not (scratch / "out").exists()


async def test_cancelled_queued_admitted_write_still_runs_only_under_proposed_lease(scratch, monkeypatch):
    path = scratch / "out"
    path.write_bytes(b"original")
    args = {"path": str(path), "content": "new"}
    busy, release = threading.Event(), threading.Event()
    submitted = asyncio.Event()
    loop = asyncio.get_running_loop()
    lock = asyncio.Lock()
    def occupy():
        busy.set()
        assert release.wait(5)
    with ThreadPoolExecutor(max_workers=1) as executor:
        holder = executor.submit(occupy)
        assert busy.wait(2)  # bounded setup only; no operation under test yet
        original_to_thread = asyncio.to_thread
        async def queued(worker, *worker_args, **worker_kwargs):
            if worker is not write_close:
                return await original_to_thread(worker, *worker_args, **worker_kwargs)
            fd, payload = worker_args
            pending = loop.run_in_executor(executor, worker, fd, payload)
            submitted.set()
            return await pending
        with active(scratch, args) as (policy, tool, prompter):
            with monkeypatch.context() as patch:
                patch.setattr(asyncio, "to_thread", queued)
                task = asyncio.create_task(proposed(policy, tool, prompter, args, lock))
                try:
                    await asyncio.wait_for(submitted.wait(), 2)
                    assert path.read_bytes() == b""
                    policy.revoke(tool.name())
                    task.cancel()
                    await asyncio.sleep(0)
                    task.cancel()
                    await asyncio.sleep(0)
                    assert lock.locked() and not task.done()
                    release.set()
                    with pytest.raises(asyncio.CancelledError):
                        await task
                    assert path.read_bytes() == b"new" and not lock.locked()
                    print("C2_FD DESIGN_ONLY: queued admitted continuation survives revoke/cancel")
                finally:
                    release.set()
                    await asyncio.gather(task, return_exceptions=True)
                    holder.result(timeout=2)


async def test_close_error_is_not_reported_as_success(scratch, monkeypatch):
    args = {"path": str(scratch / "out"), "content": "complete"}
    controller = threading.get_ident()
    original = os.close
    def fail_after_close(fd):
        original(fd)
        if threading.get_ident() != controller:
            raise OSError("synthetic close error after bytes written")
    with active(scratch, args) as (policy, tool, prompter):
        with monkeypatch.context() as patch:
            patch.setattr(os, "close", fail_after_close)
            with pytest.raises(OSError, match="close error"):
                await proposed(policy, tool, prompter, args, asyncio.Lock())
    assert (scratch / "out").read_bytes() == b"complete"


@pytest.mark.parametrize("kind", ["symlink", "regular"])
async def test_new_leaf_claimed_after_admission_is_not_overwritten(scratch, kind):
    path = scratch / "out"
    canary = scratch / "canary"
    canary.write_bytes(b"outside synthetic value")
    args = {"path": str(path), "content": "new"}
    def after_admit():
        assert not path.exists()
        if kind == "symlink":
            path.symlink_to(canary)
        else:
            path.write_bytes(b"competing creator")
    with active(scratch, args) as (policy, tool, prompter):
        with pytest.raises(FileExistsError):
            await proposed(policy, tool, prompter, args, asyncio.Lock(), after_admit=after_admit)
    assert canary.read_bytes() == b"outside synthetic value"
    assert path.is_symlink() if kind == "symlink" else path.read_bytes() == b"competing creator"
