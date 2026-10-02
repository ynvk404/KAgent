from __future__ import annotations

import asyncio
from pathlib import Path
import shutil
import sys

import pytest

from src.config.config import PluginConfig
from src.engagement.state import EngagementState
from src.permission.execution import ExecutionPolicy
from src.permission.execution import ExecutionBlocked
from src.permission.permission import Decision, YoloPrompter
from src.permission.worker import OfflineWorker
from src.tools.registry import Registry
from src.tools.shell import ShellTool
from src.tools.plugin import CommandPluginTool


class Operator:
    def __init__(self):
        self.calls = 0

    async def ask(self, request, signal=None):
        self.calls += 1
        return Decision.DENY


@pytest.fixture
async def worker_runtime(tmp_path):
    if sys.platform != "linux" or shutil.which("bwrap") is None or shutil.which("prlimit") is None:
        pytest.skip("real Linux offline worker requires already installed bwrap/prlimit; not full-mode acceptance")
    root = tmp_path / "lab"
    root.mkdir()
    (root / "wordlist.txt").write_text("admin\nnew-endpoint\n")
    control = root / "control"
    control.mkdir()
    (control / "fake-key").write_text("FAKE_CONTROL_KEY")
    outside = tmp_path / "fake-home-key"
    outside.write_text("FAKE_HOST_KEY")
    (root / "outside-link").symlink_to(outside)
    worker = await OfflineWorker.available(root, (control,))
    assert worker is not None, "installed worker must enforce real isolation; no silent skip/fallback"
    policy = ExecutionPolicy(EngagementState(), root, protected=(control,))
    policy.worker = worker
    operator = Operator()
    p = YoloPrompter(operator, True)
    p.bind_execution_policy(policy)
    registry = Registry()
    registry.register(ShellTool())
    return registry, p, policy, operator, root, outside


@pytest.mark.asyncio
async def test_real_worker_preserves_source_wordlist_payload_artifacts_without_dialog(worker_runtime):
    registry, p, _, operator, root, _ = worker_runtime
    result = await registry.execute("shell", {"command": "cat wordlist.txt; printf '<script>fixture</script>' > artifacts/worker/proof.txt"}, None, p)
    assert "new-endpoint" in result
    assert (root / "artifacts/worker/proof.txt").read_text() == "<script>fixture</script>"
    assert operator.calls == 0


@pytest.mark.asyncio
async def test_real_worker_blocks_host_protected_symlink_and_writes(worker_runtime):
    registry, p, _, operator, root, outside = worker_runtime
    command = f"cat '{outside}' control/fake-key outside-link; printf hacked > wordlist.txt"
    result = await registry.execute("shell", {"command": command}, None, p)
    assert "FAKE_HOST_KEY" not in result and "FAKE_CONTROL_KEY" not in result
    assert outside.read_text() == "FAKE_HOST_KEY" and (root / "wordlist.txt").read_text() == "admin\nnew-endpoint\n"
    assert operator.calls == 0


@pytest.mark.asyncio
async def test_real_worker_direct_socket_cannot_reach_host_loopback(worker_runtime):
    registry, p, _, operator, _, _ = worker_runtime
    accepted = []

    async def accept(reader, writer):
        accepted.append(True)
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(accept, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        command = f"python3 -c \"import socket; socket.create_connection(('127.0.0.1', {port}), timeout=1)\""
        result = await registry.execute("shell", {"command": command}, None, p)
        assert "Error" in result or "refused" in result
        assert not accepted and operator.calls == 0
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_real_plugin_stdin_output_in_worker_without_dialog(worker_runtime):
    registry, p, _, operator, root, _ = worker_runtime
    cfg = PluginConfig(name="fixture_plugin", command="/usr/bin/python3", args=["-c",
                       "import sys,json; print(json.load(sys.stdin)['payload']); print(open('wordlist.txt').read())"])
    registry.register(CommandPluginTool(cfg))
    result = await registry.execute("fixture_plugin", {"payload": "' OR 1=1-- <script>fixture</script>"}, None, p)
    assert "' OR 1=1--" in result and "new-endpoint" in result
    assert operator.calls == 0


@pytest.mark.asyncio
async def test_real_worker_background_children_do_not_survive(worker_runtime):
    registry, p, policy, operator, root, _ = worker_runtime
    await registry.execute("shell", {"command": "(sleep 1; printf escaped > artifacts/worker/child.txt) & printf done"}, None, p)
    await asyncio.sleep(1.2)
    assert not (root / "artifacts/worker/child.txt").exists()
    assert policy.active == 0 and operator.calls == 0


@pytest.mark.asyncio
async def test_worker_rejects_hardlink_and_host_ipc_before_launch(worker_runtime):
    import os
    registry, p, _, operator, root, outside = worker_runtime
    link = root / "host-hardlink"
    os.link(outside, link)
    with pytest.raises(ExecutionBlocked, match="ambiguous-hardlink"):
        await registry.execute("shell", {"command": "cat host-hardlink"}, None, p)
    link.unlink()
    fifo = root / "host-fifo"
    os.mkfifo(fifo)
    with pytest.raises(ExecutionBlocked, match="host-ipc"):
        await registry.execute("shell", {"command": "cat host-fifo"}, None, p)
    assert operator.calls == 0 and outside.read_text() == "FAKE_HOST_KEY"
