"""Publication saturation preserves saved evidence and removes only owned output."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
from threading import Barrier
from typing import Any, cast

import pytest

from src.tools.execution import scanner_runner
from src.tools.execution.scanners import ScannerPlan
from tests.security.test_scanner_end_to_end import runtime, wire


def publish_fixture(rt, index, session='session'):
    envelope = {'artifacts': {}}
    digest = scanner_runner.publish(rt.binding, cast(ScannerPlan, None), 'scan_' + f'{index:032x}',
        envelope, b'{"id":"fixture"}\n', session)
    assert digest is not None
    return envelope


def test_session_publication_limit_preserves_existing_artifacts_and_cleans_rejected_job(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_runner, 'MAX_RETAINED_JOBS', 2)
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:8080')
    kept = [publish_fixture(rt, index) for index in range(2)]
    before = {p: p.read_bytes() for p in (rt.root / '.kagent/scanners').rglob('*') if p.is_file()}
    with pytest.raises(OSError, match='retention limit'):
        publish_fixture(rt, 2)
    assert {p: p.read_bytes() for p in before} == before
    parent = (rt.root / kept[0]['artifacts']['manifest']).parent.parent
    assert len(list(parent.iterdir())) == 2
    # Quota belongs to the session; another saved session keeps its own budget.
    assert publish_fixture(rt, 3, 'other-session')['artifacts']['manifest']


def test_overlapping_publishers_cannot_exceed_session_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_runner, 'MAX_RETAINED_JOBS', 1)
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:8080')
    # Pre-create shared ancestors so this test measures publication serialization.
    parent = rt.root / '.kagent/scanners' / hashlib.sha256(b'session').hexdigest()
    parent.mkdir(parents=True, mode=0o700)
    for path in (parent.parent, parent.parent.parent):
        path.chmod(0o700)
    barrier = Barrier(2)
    def attempt(index):
        barrier.wait(timeout=5)
        try:
            return publish_fixture(rt, index)
        except OSError:
            return None
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, range(2)))
    assert sum(result is not None for result in results) == 1
    assert len(list(parent.iterdir())) == 1


def test_publication_failure_cleans_owned_directory_and_releases_slot(tmp_path, monkeypatch):
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:8080')
    original = scanner_runner.PrivateJob.write
    def fail_manifest(self, name, data):
        if name == 'manifest.json':
            raise OSError('fixture interrupted manifest commit')
        return original(self, name, data)
    with monkeypatch.context() as patch:
        patch.setattr(scanner_runner.PrivateJob, 'write', fail_manifest)
        envelope = {'artifacts': {'manifest': None, 'normalized': None, 'result_refs': []}}
        before = deepcopy(envelope)
        with pytest.raises(OSError, match='interrupted manifest'):
            scanner_runner.publish(rt.binding, cast(ScannerPlan, None), 'scan_' + '0' * 32,
                                   envelope, b'fixture', 'session')
        assert envelope == before
    parent = rt.root / '.kagent/scanners' / hashlib.sha256(b'session').hexdigest()
    assert not list(parent.iterdir())
    assert publish_fixture(rt, 1)['artifacts']['manifest']


@pytest.mark.parametrize('oversized', ['dataset', 'manifest'])
def test_oversized_publication_leaves_no_artifact_or_success_path(tmp_path, monkeypatch, oversized):
    rt = runtime(tmp_path / 'project', 'http://127.0.0.1:8080')
    envelope: dict[str, Any] = {'artifacts': {}}
    data = b'fixture'
    if oversized == 'dataset':
        monkeypatch.setattr(scanner_runner, 'MAX_DATASET', 4)
    else:
        monkeypatch.setattr(scanner_runner, 'MAX_MANIFEST_BYTES', 512)
        envelope['oversized'] = 'x' * 1024
    before = deepcopy(envelope)
    with pytest.raises(OSError, match='retention limit'):
        scanner_runner.publish(rt.binding, cast(ScannerPlan, None), 'scan_' + '0' * 32,
                               envelope, data, 'session')
    assert envelope == before
    assert not list(rt.root.rglob('normalized.jsonl'))
    assert not list(rt.root.rglob('manifest.json'))


async def test_saturation_is_visible_in_agent_result_without_unreadable_refs(tmp_path, wire, monkeypatch):
    from tests.integration.test_scanner_agent_handoff import agent_runtime
    from tests.helpers.agent_fakes import FakeClient, FakeSignal
    from tests.security.test_scanner_end_to_end import require_binaries
    from src.llm.core.types import FunctionCall, ToolCall
    require_binaries()
    monkeypatch.setattr(scanner_runner, 'MAX_RETAINED_JOBS', 1)
    origin, _ = wire
    rt = agent_runtime(tmp_path, origin, FakeClient([]))
    results = []
    for index in range(2):
        tc = ToolCall(str(index), FunctionCall('shell', json.dumps({'scanner': 'nmap',
            'target': '127.0.0.1', 'ports': str(rt.target.origin().port)})))
        parsed = rt.agent.parse_tool_call(tc)
        rt.agent._tool_call_event(tc, parsed)
        result = await rt.agent.run_parsed_tool_call(tc, parsed, FakeSignal())
        assert result.status == 'observation', result
        results.append(json.loads(result.result))
    assert results[0]['artifacts']['result_refs']
    limited = results[1]['artifacts']
    assert limited['retrieval'] == 'retrieval_limited' and not limited['result_refs']
    assert limited['publication_error'] == 'scanner artifact retention limit reached'
    assert limited['manifest'] is None and limited['normalized'] is None
    row = rt.agent.workflow.scanner_jobs[results[1]['job_id']]
    assert row.projection()['publication_error'] == limited['publication_error']
    from src.workflow.scanner import ScannerJob
    restored = ScannerJob.from_dict(row.to_dict())
    assert restored is not None and restored.projection()['publication_error'] == limited['publication_error']
