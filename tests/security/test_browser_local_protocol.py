"""Real patched Node protocol under OfflineWorker isolation, mock extension only."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import shutil
import sys

import pytest

from src.permission.worker.worker import OfflineWorker
from src.tools.mcp.browser_deployment import verify_browser_local_deployment, BROWSER_LOCAL_ROOT
from src.tools.mcp.session_servers import BROWSER_MCP_SERVER


@pytest.mark.asyncio
async def test_patched_protocol_with_mock_extension_in_private_namespace(tmp_path):
    if not BROWSER_LOCAL_ROOT.exists() or not shutil.which('bwrap'):
        pytest.skip('explicitly prepared patched closure and Linux worker required')
    verify_browser_local_deployment()
    worker = await OfflineWorker.available(tmp_path, ())
    assert worker is not None
    script = Path(__file__).with_name('browser_local_protocol.mjs').read_text()
    command, args = await worker.prepare(BROWSER_MCP_SERVER.command, BROWSER_MCP_SERVER.args, browser_mcp=True)
    # Test fixture substitution AFTER designated worker preflight. Production
    # launch/argv enforcement cannot accept an arbitrary Node payload this way.
    args[-2:] = ['/usr/bin/node', '--input-type=module', '-e', script]
    child = await asyncio.create_subprocess_exec(command, *args, stdout=asyncio.subprocess.PIPE,
                                                  stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(child.communicate(), 30)
        assert child.returncode == 0, stderr.decode()
        report = json.loads(stdout)
        assert report.pop('tools') == 12
        assert report and all(report.values())
    finally:
        if child.returncode is None:
            child.kill()
            await child.wait()


@pytest.mark.asyncio
async def test_real_persistent_owner_permission_and_cleanup_in_private_namespace():
    if not BROWSER_LOCAL_ROOT.exists() or not shutil.which('bwrap'):
        pytest.skip('explicitly prepared patched closure and Linux namespace required')
    verify_browser_local_deployment()
    script = Path(__file__).with_name('browser_local_owner.py')
    child = await asyncio.create_subprocess_exec('/usr/bin/bwrap', '--unshare-net', '--ro-bind', '/', '/',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--', sys.executable, str(script),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(child.communicate(), 30)
        assert child.returncode == 0, stderr.decode()
        report = json.loads(stdout)
        assert report['realOwner'] and report['persistentPid'] and report['queuedRevocation'] and report['cleanup']
        assert not report['anyioContextErrors'] and not report['realChrome']
    finally:
        if child.returncode is None:
            child.kill()
            await child.wait()
