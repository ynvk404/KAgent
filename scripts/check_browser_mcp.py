"""Offline initialize/list_tools resource measurement; never controls Chrome."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.engagement.state import EngagementState
from src.permission.runtime.execution import ExecutionPolicy
from src.permission.worker.worker import OfflineWorker
from src.tools.mcp.browser_deployment import BROWSER_MCP_ADDRESS_SPACE, BROWSER_MCP_VERSION
from src.tools.mcp.integration import discover_mcp_tools
from src.tools.mcp.session_servers import BROWSER_MCP_SERVER


async def measure(rounds: int) -> dict:
    samples = []
    with tempfile.TemporaryDirectory(prefix='kagent-browser-check-') as scratch:
        root = Path(scratch)
        worker = await OfflineWorker.available(root, ())
        if worker is None:
            raise RuntimeError('isolated worker unavailable')
        policy = ExecutionPolicy(EngagementState(), root)
        policy.worker = worker
        for attempt in range(rounds):
            peaks: dict[str, int] = {}

            async def monitor():
                while True:
                    pending = [os.getpid()]
                    visited = set()
                    while pending:
                        pid = pending.pop()
                        if pid in visited:
                            continue
                        visited.add(pid)
                        try:
                            children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
                            pending.extend(int(child) for child in children)
                            command = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
                            if command[:1] != [b'/usr/bin/node']:
                                continue
                            for row in Path(f'/proc/{pid}/status').read_text().splitlines():
                                label, _, value = row.partition(':')
                                if label in {'VmPeak', 'VmHWM', 'VmSize', 'VmRSS'}:
                                    peaks[label] = max(peaks.get(label, 0), int(value.split()[0]) * 1024)
                        except (OSError, ValueError):
                            continue
                    await asyncio.sleep(0.02)

            watcher = asyncio.create_task(monitor())
            started = time.monotonic()
            session = None
            try:
                discovered = await discover_mcp_tools(BROWSER_MCP_SERVER, execution_policy=policy)
                session = discovered['session']
                elapsed = time.monotonic() - started
                await asyncio.sleep(0.25)
                samples.append({'round': attempt + 1, 'initialize_list_seconds': round(elapsed, 3),
                                'tools': [tool.name() for tool in discovered['tools']],
                                'node_proc_bytes': dict(peaks)})
            finally:
                if session is not None:
                    await session.close()
                watcher.cancel()
                await asyncio.gather(watcher, return_exceptions=True)
    return {'package': '@browsermcp/mcp', 'version': BROWSER_MCP_VERSION,
            'address_space_bytes': BROWSER_MCP_ADDRESS_SPACE, 'rounds': samples,
            'mean_initialize_list_seconds': statistics.mean(x['initialize_list_seconds'] for x in samples),
            'browser_tested': False}


def check_cli() -> dict:
    with tempfile.TemporaryDirectory(prefix='kagent-browser-cli-') as task_home:
        result = subprocess.run([
            str(Path(sys.executable).with_name('kagent')), '--browser', '--list-tools',
            '--backend', 'openai-compat', '--model', 'local-placeholder',
            '--base-url', 'http://127.0.0.1:1', '--api-key', 'placeholder',
        ], env={'HOME': task_home, 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=150)
    return {'exit_code': result.returncode, 'stderr': result.stderr,
            'browser_tool_lines': [row for row in result.stdout.splitlines() if row.startswith('- mcp_browser_')]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rounds', type=int, default=10)
    parser.add_argument('--cli', action='store_true', help='also run real kagent --browser --list-tools with isolated HOME')
    args = parser.parse_args()
    if not 1 <= args.rounds <= 50:
        parser.error('rounds must be between 1 and 50')
    report = asyncio.run(measure(args.rounds))
    if args.cli:
        report['cli'] = check_cli()
    print(json.dumps(report, indent=2))
