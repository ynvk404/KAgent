"""A process leader exiting must not bypass capture timeout or cancellation."""
import asyncio
import os
from pathlib import Path
import shlex
import signal
import sys
from types import SimpleNamespace

import pytest

from src.tools.execution.shell import BashTool, ShellTool, run_with_capture
from tests.helpers.burp_selection import make_runtime


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX process groups")


async def _assert_descendant_exited(pid: int, *, timeout: float = 2.0) -> None:
    # EOF and reaping of the direct child do not synchronize the orphan's final
    # /proc state. Require it to exit within a bound; a live process never passes.
    status = Path(f'/proc/{pid}/stat')
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        try:
            state = status.read_text().rsplit(')', 1)[1].split()[0]
        except FileNotFoundError:
            return
        if state == 'Z':
            return  # Terminated; reaping an orphan belongs to its new parent.
        assert asyncio.get_running_loop().time() < deadline, f'descendant {pid} still live: state={state}'
        await asyncio.sleep(.01)


@pytest.mark.parametrize("ending", ["timeout", "cancel", "cancel-again", "abort"])
async def test_exited_leader_with_term_resistant_child_closes_pipes(tmp_path, ending, monkeypatch):
    marker = tmp_path / "child.pid"
    # The child shares the command's process group and pipes. It installs its
    # TERM handler before the parent exits, so the test exercises descendants.
    script = f"""
import os, signal, time
child = os.fork()
if child:
    while not os.path.exists({str(marker)!r}):
        time.sleep(.01)
    os._exit(0)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
with open({str(marker)!r}, 'w') as stream:
    stream.write(str(os.getpid()))
while True:
    time.sleep(.1)
"""
    processes = []
    original = asyncio.create_subprocess_exec

    async def spawn(*args, **kwargs):
        process = await original(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    from src.tools.execution import shell
    term_sent = asyncio.Event()
    original_kill = shell.kill_process_group

    def kill(pid, sig=signal.SIGTERM):
        original_kill(pid, sig)
        if sig == signal.SIGTERM:
            term_sent.set()

    monkeypatch.setattr(shell, 'kill_process_group', kill)
    abort = SimpleNamespace(aborted=False)
    task = asyncio.create_task(run_with_capture(sys.executable, ["-c", script],
        .5 if ending == "timeout" else 30, abort))
    try:
        async with asyncio.timeout(5):
            while not marker.exists() or not processes or processes[0].returncode is None:
                await asyncio.sleep(.01)
        if ending in {"cancel", "cancel-again"}:
            task.cancel()
            if ending == "cancel-again":
                await asyncio.wait_for(term_sent.wait(), 2)
                task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(asyncio.shield(task), 3)
        else:
            if ending == "abort":
                abort.aborted = True
            result = await asyncio.wait_for(asyncio.shield(task), 3)
            assert result.error_kind == ("timeout" if ending == "timeout" else "cancelled")
            assert result.runtime_metadata is not None
            assert result.runtime_metadata.stdout is not None and result.runtime_metadata.stdout.eof
            assert result.runtime_metadata.stderr is not None and result.runtime_metadata.stderr.eof
        # An orphan may briefly remain a zombie until its init reaps it, but
        # must no longer execute or hold the output descriptors.
        child = int(marker.read_text())
        await _assert_descendant_exited(child)
        assert processes[0].returncode == 0 and task.done()
        assert processes[0].stdout is not None and processes[0].stdout.at_eof()
        assert processes[0].stderr is not None and processes[0].stderr.at_eof()
    finally:
        for process in processes:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("tool_type", [ShellTool, BashTool])
@pytest.mark.parametrize("cancel_again", [False, True])
@pytest.mark.parametrize("descriptor_load", [0, 32768])
async def test_cancellation_during_spawn_keeps_receipt_until_group_cleanup(
    tmp_path, monkeypatch, tool_type, cancel_again, descriptor_load,
):
    if descriptor_load:
        if not sys.platform.startswith('linux'):
            pytest.skip('Linux /proc exit-state regression')
        import resource
        descriptor_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        if descriptor_limit != resource.RLIM_INFINITY and descriptor_limit < descriptor_load + 64:
            pytest.skip('Descriptor exit-window fixture exceeds the process descriptor limit')
    rt = make_runtime(tmp_path)
    tool = tool_type()
    rt.registry.register(tool)
    marker = tmp_path / "spawn-child.pid"
    script = f"""
import os, signal, time
child = os.fork()
if not child:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if {descriptor_load}:
        # Keep output open through high-numbered duplicates. Kernel teardown
        # can close these pipes before finishing release of the other files.
        held_fds = [os.open(os.devnull, os.O_RDONLY) for _ in range({descriptor_load})]
        output_fds = [os.dup(1), os.dup(2)]
        os.close(1)
        os.close(2)
    with open({str(marker)!r}, 'w') as stream:
        stream.write(str(os.getpid()))
while True:
    time.sleep(.1)
"""
    real_spawn = asyncio.create_subprocess_exec
    spawned, release = asyncio.Event(), asyncio.Event()
    processes = []

    async def delayed_spawn(*args, **kwargs):
        process = await real_spawn(*args, **kwargs)
        processes.append(process)
        spawned.set()
        # Model the real spawn window: the child can already run before the
        # create_subprocess_exec await hands its handle to run_with_capture.
        await release.wait()
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", delayed_spawn)
    task = asyncio.create_task(rt.registry.execute(tool.name(), {
        "command": shlex.quote(sys.executable) + " -c " + shlex.quote(script),
    }, None, rt.prompter))
    try:
        await asyncio.wait_for(spawned.wait(), 5)
        async with asyncio.timeout(5):
            while not marker.exists():
                await asyncio.sleep(.01)
        task.cancel()
        done, _ = await asyncio.wait({task}, timeout=.05)
        assert not done, "cancellation must wait for the owned process handle"
        assert rt.policy.active == 1 and rt.policy._active_receipts
        if cancel_again:
            task.cancel()
            done, _ = await asyncio.wait({task}, timeout=.05)
            assert not done and rt.policy.active == 1
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(task), 5)
        assert processes[0].returncode is not None
        assert processes[0].stdout is not None and processes[0].stderr is not None
        assert processes[0].stdout.at_eof() and processes[0].stderr.at_eof()
        await _assert_descendant_exited(int(marker.read_text()))
        assert rt.policy.active == 0 and not rt.policy._active_receipts
    finally:
        release.set()
        for process in processes:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.gather(*(process.wait() for process in processes))


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux /proc state check')
@pytest.mark.parametrize('terminate', [False, True])
async def test_descendant_exit_check_waits_and_rejects_a_live_process(terminate):
    proc = await asyncio.create_subprocess_exec(sys.executable, '-c',
        'import sys; print("ready", flush=True); sys.stdin.buffer.read(1)',
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
    checker = None
    try:
        assert proc.stdout is not None and proc.stdin is not None
        assert await asyncio.wait_for(proc.stdout.readline(), 2) == b'ready\n'
        checker = asyncio.create_task(_assert_descendant_exited(proc.pid, timeout=2 if terminate else .1))
        if terminate:
            done, _ = await asyncio.wait({checker}, timeout=.02)
            assert not done and proc.returncode is None
            proc.stdin.write(b'exit')
            await proc.stdin.drain()
            proc.stdin.close()
            await asyncio.wait_for(checker, 2)
            assert await proc.wait() == 0
        else:
            with pytest.raises(AssertionError, match='still live'):
                await checker
            assert proc.returncode is None
    finally:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
        if checker is not None:
            checker.cancel()
            await asyncio.gather(checker, return_exceptions=True)
