"""Fresh-process CWE discovery/RPC checks, sequential and under actual tooling load.

No provider/config writes, target HTTP, package installation or OS cache dropping.
Each discovery, search and get uses the existing isolated launch path/deadlines.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import signal
import sys
import time

from mcp import ClientSession
from components.cwe_mcp.contract import SearchResponse, LookupResponse

from scripts.check_cwe_mcp import connect
from src.findings.cwe_enrichment import TrustedSource, parse_response
from src.tools.mcp.integration import HANDSHAKE_TIMEOUT_S


INSPECT = """import hashlib, zipfile, time
from pathlib import Path
root = Path(__import__('sys').argv[1])
while True:
    with zipfile.ZipFile(root / 'runtime.zip') as archive:
        for name in archive.namelist():
            if name.endswith('.py'):
                compile(archive.read(name), name, 'exec', dont_inherit=True)
    for path in (root / 'runtime').rglob('*'):
        if path.is_file():
            with path.open('rb') as stream:
                hashlib.file_digest(stream, 'sha256')
    time.sleep(1)
"""


async def stop_process(process):
    # Only this harness's explicitly created session/process group is stopped.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(process.wait(), 5)
    except TimeoutError:
        os.killpg(process.pid, signal.SIGKILL)
        await process.wait()


@asynccontextmanager
async def tooling_load(deployment: Path):
    processes = set()
    async def pyright():
        while True:
            process = await asyncio.create_subprocess_exec(
                str(Path(sys.executable).parent / 'pyright'),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                start_new_session=True)
            processes.add(process)
            try:
                if await process.wait() != 0:
                    raise RuntimeError('moderate-load pyright failed')
            finally:
                await stop_process(process)
                processes.discard(process)
    inspector = await asyncio.create_subprocess_exec(
        '/usr/bin/python3', '-I', '-B', '-c', INSPECT, str(deployment),
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        start_new_session=True)
    processes.add(inspector)
    task = asyncio.create_task(pyright())
    try:
        yield task, inspector
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        for process in tuple(processes):
            await stop_process(process)


async def rounds(deployment: Path, count: int, mode: str, samples: list, load=None):
    root = Path(__file__).resolve().parents[1]
    for index in range(count):
        before = len(samples)
        started = time.monotonic()
        registry, prompter, policy, _, session, metrics = await connect(root, deployment)
        try:
            source = TrustedSource(registry, policy)
            search = parse_response(await registry.execute('mcp_cwe_catalog_search_cwe',
                {'query': 'missing authorization', 'max_results': 5}, None, prompter), 'search')
            exact = parse_response(await registry.execute('mcp_cwe_catalog_get_cwe',
                {'id': 639}, None, prompter), 'get')
            assert isinstance(search, SearchResponse) and isinstance(exact, LookupResponse)
            assert search.candidates and exact.found and exact.candidate is not None
            assert exact.candidate.cwe_id == 'CWE-639'
            source.unchanged()
            assert policy.active == 0 and not policy.engagement.http_permissions.grants
            if load is not None:
                task, inspector = load
                assert not task.done() and inspector.returncode is None
        finally:
            await session.close()
        current = samples[before:]
        assert len(current) == 3 and all(s['completed'] and s['seconds'] < HANDSHAKE_TIMEOUT_S for s in current)
        print(json.dumps({'mode': mode, 'round': index + 1, 'fresh_processes': current,
                          'discovery': metrics, 'round_seconds': time.monotonic() - started}), flush=True)


async def main(deployment: Path, count: int):
    samples = []
    original = ClientSession.initialize
    async def measured(self, *args, **kwargs):
        start = time.monotonic()
        completed = False
        try:
            result = await original(self, *args, **kwargs)
            completed = True
            return result
        finally:
            samples.append({'seconds': time.monotonic() - start, 'completed': completed})
    ClientSession.initialize = measured
    try:
        await rounds(deployment, count, 'sequential', samples)
        async with tooling_load(deployment) as load:
            await rounds(deployment, count, 'pyright-and-dependency-inspection', samples, load)
    finally:
        ClientSession.initialize = original
    print(json.dumps({'successful_fresh_processes': len(samples), 'handshake_budget_seconds': HANDSHAKE_TIMEOUT_S,
                      'max_initialization_seconds': max(s['seconds'] for s in samples)}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--deployment', required=True, type=Path)
    parser.add_argument('--rounds', type=int, default=5)
    options = parser.parse_args()
    if not 1 <= options.rounds <= 20:
        parser.error('--rounds must be between 1 and 20')
    asyncio.run(main(options.deployment, options.rounds))
