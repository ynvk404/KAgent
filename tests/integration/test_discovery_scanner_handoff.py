import json

import pytest

from tests.integration.test_scanner_agent_handoff import agent_runtime, wire, require_binaries
from tests.helpers.discovery_calls import execute
from tests.helpers.agent_fakes import FakeClient


@pytest.mark.parametrize('scanner', ['ffuf', 'nmap'])
async def test_finalized_scanner_inventory_preserves_exact_job_rows_and_no_auto_inputs(tmp_path, wire, scanner):
    require_binaries()
    origin, counters = wire
    runtime = agent_runtime(tmp_path, origin, FakeClient([]), enumeration=scanner == 'ffuf')
    args = ({'scanner': 'ffuf', 'url': origin + '/FUZZ', 'wordlist_id': 'fixture', 'threads': 1}
            if scanner == 'ffuf' else {'scanner': 'nmap', 'target': '127.0.0.1',
                                     'ports': str(runtime.target.origin().port)})
    output = await execute(runtime, 'shell', args)
    envelope = json.loads(output.result)
    assert envelope['execution']['status'] == 'completed'
    state = runtime.agent.workflow
    source = next(row for row in state.discovery_sources.values() if row.kind == scanner)
    job = state.scanner_jobs[source.scanner_job_id]
    assert source.scanner_job_id == envelope['job_id'] and source.retained_hash == job.artifacts['dataset_sha256']
    assert not job.dispositions and not state.attack_surface_inputs and not state.candidates
    if scanner == 'ffuf':
        links = [row for row in state.discovery_provenance.values() if row.source_id == source.id]
        assert {row.locator for row in links} == {row['id'] for row in envelope['records']}
        assert {ep.url for ep in state.endpoints.values()} == {row['url'] for row in envelope['records']}
    else:
        assert not state.endpoints
    requests = counters['requests']
    listed = await execute(runtime, 'workflow', {'action': 'list', 'view': 'endpoints', 'discovery_source_id': source.id})
    assert json.loads(listed.result)['total'] == len(state.endpoints)
    assert counters['requests'] == requests
    assert not state.evidence and not state.validation_results and not state.attempts
