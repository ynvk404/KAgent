"""Real Python MCP owner + Node + mock socket, inside private network namespace."""
from __future__ import annotations

import asyncio
from pathlib import Path
import json
import os
import tempfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.engagement.state import EngagementState
from src.permission.permission import Decision, UserControlledRefusal, YoloPrompter
from src.permission.runtime.execution import ExecutionBlocked, ExecutionPolicy
from src.tools.common.registry import Registry
from src.tools.mcp.browser_local import BrowserLocalBinding, linux_listeners
from src.tools.mcp.integration import discover_mcp_tools
from src.tools.mcp.session_servers import BROWSER_LOCAL_SERVER
from src.tools.mcp import browser_local as local
from src.tools.mcp import browser_deployment as deployment

ORIGIN = 'http://juice.lab:8081'
MOCK = """
import { WebSocket } from '/usr/local/lib/kagent-browser-mcp/0.1.3-kagent-local-v3/node_modules/ws/wrapper.mjs';
import { existsSync, readFileSync } from 'node:fs';
const ws = new WebSocket('ws://127.0.0.1:9009');
ws.on('message', bytes => {
  const req = JSON.parse(bytes.toString());
  console.log(req.type);
  if (req.type === 'browser_click' && req.payload.element === 'hold') return;
  const origin = existsSync('/tmp/browser-mock-origin') ? readFileSync('/tmp/browser-mock-origin', 'utf8') : 'http://juice.lab:8081';
  const result = req.type === 'getUrl' ? origin
    : req.type === 'getTitle' ? 'MOCK-OWNER-MARKER'
    : req.type === 'browser_snapshot' ? '- textbox [ref=s1e1]' : null;
  ws.send(JSON.stringify({ id: req.id, type: 'messageResponse', payload: { requestId: req.id, result } }));
});
ws.on('close', () => process.exit(0));
setTimeout(() => process.exit(2), 20000).unref();
"""


async def main():
    # Parent verified the host root-owned closure before entering bwrap. Its
    # unprivileged user namespace maps the host administrator UID to overflow
    # 65534. Adapt only this fixture's ownership predicate; digest/type/link/
    # inventory and executable checks remain the production checks.
    assert Path('/usr/local/lib/kagent-browser-mcp').stat().st_uid == 65534
    deployment._has_immutable_owner = lambda info: info.st_uid == 65534 and not info.st_mode & 0o022
    # These checks concern the private test namespace, never host Windows ports.
    async def isolated_ports():
        assert not linux_listeners()
    local.check_ports_free = isolated_ports
    os.environ['OPENAI_API_KEY'] = 'fixture-must-not-export'
    os.environ['NODE_OPTIONS'] = '--require=/tmp/must-not-load.js'
    errors = []
    asyncio.get_running_loop().set_exception_handler(lambda loop, context: errors.append(context))
    with tempfile.TemporaryDirectory() as scratch:
        engagement = EngagementState()
        engagement.add_origin(ORIGIN)
        policy = ExecutionPolicy(engagement, Path(scratch))
        binding = BrowserLocalBinding(policy, BROWSER_LOCAL_SERVER, lab_origin=ORIGIN)
        policy.browser_local = binding

        class Operator:
            execution_policy = policy
            decision = Decision.ALLOW_ONCE
            asks = 0

            async def ask(self, request, signal=None):
                self.asks += 1
                return self.decision

        operator = Operator()
        registry = Registry()
        discovered = await discover_mcp_tools(BROWSER_LOCAL_SERVER, execution_policy=policy, browser_local=binding)
        for tool in discovered['tools']:
            registry.register(tool)
        child: asyncio.subprocess.Process | None = None
        pairing: asyncio.Task | None = None
        messages = []
        collector: asyncio.Task | None = None

        async def mock_pair():
            nonlocal child, collector
            while not linux_listeners():
                await asyncio.sleep(0.02)
            child = await asyncio.create_subprocess_exec('/usr/bin/node', '--input-type=module', '-e', MOCK,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env={'PATH': '/usr/bin:/bin', 'HOME': '/tmp'})
            async def collect():
                assert child is not None and child.stdout is not None
                async for line in child.stdout:
                    messages.append(line.decode().strip())
            collector = asyncio.create_task(collect())

        async def call(name, args):
            return await registry.execute('mcp_browser_browser_' + name, args, None, operator)

        try:
            pairing = asyncio.create_task(mock_pair())
            result = await call('navigate', {'url': ORIGIN})
            assert 'MOCK-OWNER-MARKER' in result
            await pairing
            owner = binding.owner
            assert owner is not None
            pid = (await owner.request('browser_status'))['pid']
            environment = Path(f'/proc/{pid}/environ').read_bytes()
            assert b'OPENAI_API_KEY' not in environment and b'NODE_OPTIONS' not in environment
            assert b'HOME=/tmp\0' in environment
            limits = Path(f'/proc/{pid}/limits').read_text()
            assert '1610612736' in limits and '120' in next(row for row in limits.splitlines() if row.startswith('Max cpu time'))
            await call('snapshot', {})
            await call('click', {'ref': 's1e1', 'element': 'search'})
            await call('type', {'ref': 's1e1', 'element': 'search', 'text': 'fixture', 'submit': False})
            assert binding.owner is owner and (await owner.request('browser_status'))['pid'] == pid
            yolo = YoloPrompter(operator, True)
            yolo.bind_execution_policy(policy)
            grant = binding.activate_grant('read')
            before_asks = operator.asks
            await registry.execute('mcp_browser_browser_snapshot', {}, None, yolo)
            assert operator.asks == before_asks and grant.remaining == 19
            # The actual pinned server checks CURRENT extension metadata even
            # with auto-approval. No snapshot action may run on a foreign tab.
            origin_control = Path('/tmp/browser-mock-origin')
            origin_control.write_text('http://outside.lab:8081')
            before_snapshots = messages.count('browser_snapshot')
            try:
                await registry.execute('mcp_browser_browser_snapshot', {}, None, yolo)
                raise AssertionError('Browser grant bypassed current-tab guard')
            except RuntimeError as exc:
                assert 'outside controller origin' in str(exc)
            assert messages.count('browser_snapshot') == before_snapshots
            origin_control.write_text('unverifiable-url')
            try:
                await registry.execute('mcp_browser_browser_snapshot', {}, None, yolo)
                raise AssertionError('Browser grant accepted unverifiable tab origin')
            except RuntimeError as exc:
                assert 'Invalid URL' in str(exc)
            assert messages.count('browser_snapshot') == before_snapshots
            origin_control.unlink()
            assert binding.owner is owner and (await owner.request('browser_status'))['pid'] == pid
            yolo.set_yolo(False)
            operator.decision = Decision.DENY
            before = len(messages)
            try:
                await call('snapshot', {})
                raise AssertionError('DENY dispatched')
            except UserControlledRefusal:
                pass
            await asyncio.sleep(0.02)
            assert len(messages) == before
            operator.decision = Decision.ALLOW_ONCE
            held = asyncio.create_task(call('click', {'ref': 's1e1', 'element': 'hold'}))
            while messages.count('browser_click') < 2:
                await asyncio.sleep(0.02)
            queued = asyncio.create_task(call('type', {'ref': 's1e1', 'element': 'queued', 'text': 'fixture', 'submit': False}))
            await asyncio.sleep(0.03)
            policy.revoke('mcp_browser_browser_type')
            results = await asyncio.wait_for(asyncio.gather(held, queued, return_exceptions=True), 6)
            assert isinstance(results[0], RuntimeError) and 'outcome unknown' in str(results[0])
            assert isinstance(results[1], ExecutionBlocked)
            assert messages.count('browser_type') == 1
            await binding.close()
            assert not linux_listeners() and not Path(f'/proc/{pid}').exists()
            assert policy.active == 0 and not errors, errors
            print(json.dumps({'realOwner': True, 'persistentPid': True, 'permission': True,
                              'queuedRevocation': True, 'unknownOutcome': True, 'cleanup': True,
                              'boundedYoloGrant': True, 'grantCurrentTabGuard': True,
                              'anyioContextErrors': False, 'realChrome': False}))
        finally:
            if pairing is not None and not pairing.done():
                pairing.cancel()
                await asyncio.gather(pairing, return_exceptions=True)
            await binding.close()
            if child is not None:
                if child.returncode is None:
                    child.kill()
                await child.wait()
            if collector is not None:
                await collector


if __name__ == '__main__':
    asyncio.run(asyncio.wait_for(main(), 25))
