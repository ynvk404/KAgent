"""Real offline publication adapters -> bounded WorkflowState metadata."""
import json

import pytest

from tests.agent.test_tool_result_offloading import make
from tests.agent.test_native_discovery_retention import native, execute, dataset


@pytest.mark.asyncio
async def test_native_source_ref_and_baseline_rejection(native):
    agent, _ = native()
    await execute(agent, ['hit1', 'hit2', 'reject1'])
    ref, full, _ = dataset(agent)
    state = agent.workflow
    assert len(state.discovery_sources) == 1
    source = next(iter(state.discovery_sources.values()))
    assert source.retained_ref == ref.result_ref and source.retained_hash == ref.sha256
    assert source.disposition == 'processed' and not source.selected
    assert {ep.url for ep in state.endpoints.values()} == {'https://target.test/hit1', 'https://target.test/hit2'}
    assert all(ep.method == 'GET' for ep in state.endpoints.values())
    assert len(state.discovery_provenance) == 2
    assert not state.attack_surface_inputs and not state.candidates and not state.attempts and not state.evidence
    assert len(full['wildcard_baseline']) == 2 and len(full['rejected']) == 1
    assert 'wildcard_baseline' not in json.dumps(source.to_dict())


@pytest.mark.asyncio
async def test_native_inline_missing_retention_is_explicit(native):
    agent, _ = native()
    agent.result_retention.store = None
    await execute(agent, ['hit1'])
    source = next(iter(agent.workflow.discovery_sources.values()))
    assert source.retained_ref is None and source.disposition == 'partial' and source.limitations


@pytest.mark.asyncio
async def test_native_handoff_is_bounded_and_raw_remains_full(native):
    agent, _ = native()
    await execute(agent, [f'hit{i}' for i in range(300)])
    _, full, _ = dataset(agent)
    assert len(full['discovered']) == 300
    assert len(agent.workflow.endpoints) == 256
    source = next(iter(agent.workflow.discovery_sources.values()))
    assert source.disposition == 'partial' and any('256' in note for note in source.limitations)


@pytest.mark.asyncio
async def test_native_old_owner_cannot_publish_to_replacement_state(native):
    from src.workflow.discovery.inventory import native_handoff
    from src.workflow.state import WorkflowState
    agent, _ = native()
    _, _, result = await execute(agent, ['hit1'])
    produced = result.result.native_discovery
    replacement = WorkflowState.from_dict(agent.workflow.to_dict())
    before = replacement.to_dict()
    with pytest.raises(ValueError, match='owner'):
        native_handoff(replacement, produced, 'other')
    assert replacement.to_dict() == before
