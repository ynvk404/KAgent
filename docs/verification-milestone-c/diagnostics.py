"""Read-only timing observer for the reported stall case; no traffic/prose."""
import asyncio
import gc
import json
from pathlib import Path
import resource
import threading
import time

import pytest


@pytest.fixture(autouse=True)
def observe_stall(request, monkeypatch):
    if not request.node.nodeid.endswith("test_owned_stop_without_declaration_records_unknown_not_false[stall]"):
        yield
        return
    module = request.module
    from tests.benchmarks.test_scenario1_closure import StopClient
    from src.session.store import Store

    start = time.monotonic()
    rows = []
    def record(kind, **fields):
        rows.append(dict(event=kind, elapsed=time.monotonic() - start,
                         cpu=time.process_time(), **fields))
    def resources():
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return dict(rss_kib=usage.ru_maxrss, threads=len(threading.enumerate()),
                    loadavg=Path('/proc/loadavg').read_text().split()[:3],
                    gc=gc.get_stats(), io=Path('/proc/self/io').read_text())
    record('before', resources=resources())
    original_execute = module.execute_case
    original_chat = StopClient.chat
    original_save = Store.save

    async def chat(self, *args, **kwargs):
        record('chat_start', step=self.step)
        try:
            return await original_chat(self, *args, **kwargs)
        finally:
            record('chat_end', step=self.step)

    async def save(self, *args, **kwargs):
        record('save_start')
        try:
            return await original_save(self, *args, **kwargs)
        finally:
            record('save_end')

    async def execute(*args, **kwargs):
        record('execute_start', tasks=len(asyncio.all_tasks()))
        result = await original_execute(*args, **kwargs)
        record('execute_end', status=result.status, metrics=result.metrics,
               tasks=len(asyncio.all_tasks()))
        return result

    monkeypatch.setattr(StopClient, 'chat', chat)
    monkeypatch.setattr(Store, 'save', save)
    monkeypatch.setattr(module, 'execute_case', execute)
    yield
    record('after', resources=resources())
    output = Path(__file__).resolve().parents[2] / '.kagent/verification/a-observations.jsonl'
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('a') as stream:
        stream.write(json.dumps(dict(node=request.node.nodeid, rows=rows)) + '\n')
