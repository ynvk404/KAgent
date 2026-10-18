"""Controller skill contracts are transient; archived playbooks cannot grant rights."""
import asyncio
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from src.agent.agent import AgentRunOptions
from src.llm.core.types import ChatRequest, ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import Decision
from src.session.store import Store
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry
from src.skills.reload import publish_snapshot
from src.skills.transactions import skill_changes
from src.workflow.state import WorkflowObjective
from tests.agent.test_token_accounting_independent_verify import make_agent, SnapshotClient
from tests.helpers.agent_fakes import FakeSignal
from tests.helpers.workflow import record_completed_phase

ORIGIN = 'https://target.test'


class Service:
    def __init__(self): self.calls = 0
    def name(self): return 'service_discovery'
    def description(self): return 'Offline service adapter'
    def schema(self): return {'type': 'object', 'properties': {}}
    def requires_permission(self): return True
    async def run(self, args, signal=None, prompter=None):
        self.calls += 1
        return 'observed'


def agent_fixture(tmp_path=None):
    registry = Registry()
    registry.load_dir('skills')
    agent = make_agent(skills=registry, store=Store.new_with_id(tmp_path, 'lifecycle') if tmp_path else None)
    agent.target.set_base_url(ORIGIN)
    agent.workflow.objective = WorkflowObjective('objective', 'whole_target', ORIGIN)
    agent.rebuild_from_skills()
    service = Service()
    agent.tools.register(service)
    agent.tools.register(LoadSkillTool(registry))
    return agent, service


async def load(agent, name, *, publish=True):
    call = ToolCall('call-' + name, FunctionCall('load_skill', json.dumps({'name': name})))
    parsed = agent.parse_tool_call(call)
    working = []
    agent.history.append(Message('assistant', '', tool_calls=[call]))
    result = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    assert not result.err_str
    if publish: agent.record_tool_result(call, parsed, result, lambda e: None, working)
    return call, parsed, result


def advance(agent):
    record_completed_phase(agent.workflow, 'recon', objective_id='objective', target_origin=ORIGIN,
        artifact_ref='artifacts/recon/target-test/summary.md')
    agent.workflow.current_phase = 'recon'  # Display text cannot keep the old contract alive.


def projection(agent):
    return agent._projection_request(agent.history, agent.memory, agent._idle_context()).messages


async def invoke_service(agent):
    call = ToolCall('service', FunctionCall('service_discovery', '{}'))
    return await agent.run_parsed_tool_call(call, agent.parse_tool_call(call), FakeSignal())


def assert_no_artifacts(agent, before):
    assert agent.workflow.to_dict() == before
    assert not agent.workflow.candidates and not agent.workflow.evidence and not agent.workflow.validation_results


async def test_model_phase_replacement_retires_recon_without_eager_loading():
    agent, service = agent_fixture()
    await load(agent, 'recon')
    assert not (await invoke_service(agent)).err_str and service.calls == 1
    advance(agent)
    before = deepcopy(agent.workflow.to_dict())
    # A completion marker does not schedule a replacement or change runtime
    # permissions. Explicit model loading performs the contract handoff.
    assert agent.active_skills == {'recon'}
    await load(agent, 'web-enumeration')
    assert agent.active_skills == {'web-enumeration'}
    assert (await invoke_service(agent)).err_str and service.calls == 1
    assert_no_artifacts(agent, before)
    assert '# Recon playbook' not in '\n'.join(m.content for m in projection(agent))
    assert '# Web enumeration playbook' in '\n'.join(m.content for m in projection(agent))


async def test_manual_selection_still_applies_to_next_request_and_survives_phase_transition():
    agent, service = agent_fixture()
    await agent.inject_skill('recon')
    agent.client = SnapshotClient([ChatResponse(Message('assistant', 'done'), 'stop')])
    await agent.run('continue', FakeSignal(), lambda e: None, AgentRunOptions(tools=False))
    assert agent.active_skills == {'recon'} and not agent.pending_skills
    advance(agent)
    await load(agent, 'web-enumeration')
    assert agent.active_skills == {'recon', 'web-enumeration'}
    assert not (await invoke_service(agent)).err_str and service.calls == 1


@pytest.mark.parametrize('change', ['disable', 'delete', 'body', 'tools', 'model_only'])
async def test_reconcile_never_resurrects_old_capability_or_changes_raw_transcript(change):
    agent, service = agent_fixture()
    await load(agent, 'recon')
    archived = deepcopy(agent.history)
    before = deepcopy(agent.workflow.to_dict())
    snapshot = Registry()
    for skill in agent.skills.list(): snapshot.add(deepcopy(skill))
    if change == 'disable': await agent.set_skill_enabled('recon', False)
    elif change == 'delete':
        snapshot.skills.pop('recon')
        publish_snapshot(agent, snapshot)
    else:
        skill = snapshot.skills['recon']
        if change == 'body': skill.body += '\nchanged contract'
        if change == 'tools': skill.tools.append('other')
        if change == 'model_only': skill.disable_model_invocation = True
        publish_snapshot(agent, snapshot)
    raw = deepcopy(agent.history)
    projected = projection(agent)
    assert '# Recon playbook' not in '\n'.join(m.content for m in projected)
    assert agent.history == raw and agent.history[1:] == archived[1:]
    assert [(m.role, m.tool_call_id, m.tool_calls) for m in projected[:len(raw)]] == [
        (m.role, m.tool_call_id, m.tool_calls) for m in raw]
    assert (await invoke_service(agent)).err_str and service.calls == 0
    if change == 'disable':
        await agent.set_skill_enabled('recon', True)
        assert (await invoke_service(agent)).err_str and service.calls == 0
        await load(agent, 'recon')
        assert not (await invoke_service(agent)).err_str and service.calls == 1
    assert_no_artifacts(agent, before)


@pytest.mark.parametrize('names', [set(), {'missing'}])
async def test_empty_or_unknown_active_names_stay_restricted_after_retirement(names):
    agent, service = agent_fixture()
    await load(agent, 'recon')
    await agent.set_skill_enabled('recon', False)
    agent.active_skills = names
    before = deepcopy(agent.workflow.to_dict())
    assert (await invoke_service(agent)).err_str and service.calls == 0
    assert_no_artifacts(agent, before)


@pytest.mark.parametrize('change', ['disable', 'delete', 'body', 'reset', 'objective', 'target'])
async def test_pending_load_cannot_publish_after_definition_or_owner_change(change):
    agent, service = agent_fixture()
    call, parsed, result = await load(agent, 'recon', publish=False)
    if change == 'disable': await agent.set_skill_enabled('recon', False)
    elif change == 'delete': agent.skills.skills.pop('recon')
    elif change == 'body': agent.skills.skills['recon'].body += '\nchanged'
    elif change == 'reset': await agent.reset()
    elif change == 'objective': agent.workflow.objective = WorkflowObjective('other', 'whole_target', ORIGIN)
    else: agent.target.set_base_url('https://other.test')
    before = deepcopy(agent.workflow.to_dict())
    events = []
    agent.record_tool_result(call, parsed, result, events.append, [])
    assert not agent.active_skills and not [e for e in events if e['type'] == 'skill-active']
    assert '# Recon playbook' not in '\n'.join(m.content for m in projection(agent))
    assert service.calls == 0
    assert_no_artifacts(agent, before)


async def test_resume_keeps_raw_history_and_does_not_restore_skill_authority(tmp_path):
    agent, service = agent_fixture(tmp_path)
    await load(agent, 'recon')
    await agent.save()
    assert agent.store is not None
    saved = agent.store.load()
    agent.resume_saved()
    assert agent.history[1:] == saved.messages[1:]
    assert not agent.active_skills and not agent.pending_skills
    before = deepcopy(agent.workflow.to_dict())
    assert '# Recon playbook' not in '\n'.join(m.content for m in projection(agent))
    assert (await invoke_service(agent)).err_str and service.calls == 0
    assert_no_artifacts(agent, before)


@pytest.mark.parametrize('change', ['disable', 'reload'])
async def test_contract_rechecked_after_registry_permission_wait(change):
    agent, service = agent_fixture()
    await load(agent, 'recon')
    entered, release = asyncio.Event(), asyncio.Event()
    class Review:
        async def ask(self, request, signal=None):
            entered.set()
            await release.wait()
            return Decision.ALLOW_ONCE
    agent.prompter = Review()
    pending = asyncio.create_task(invoke_service(agent))
    await entered.wait()
    if change == 'disable': await agent.set_skill_enabled('recon', False)
    else: publish_snapshot(agent, Registry())
    before = deepcopy(agent.workflow.to_dict())
    release.set()
    result = await pending
    assert result.err_str and service.calls == 0
    assert_no_artifacts(agent, before)


@pytest.mark.parametrize('ending', ['failure', 'cancel'])
async def test_manual_transaction_restores_contracts_after_failed_disable(ending):
    agent, service = agent_fixture()
    await agent.inject_skill('recon')
    before = deepcopy(agent.history)
    with pytest.raises(BaseException):
        async with skill_changes(agent):
            await agent.set_skill_enabled('recon', False)
            if ending == 'cancel': raise asyncio.CancelledError()
            raise OSError('synthetic failure')
    assert agent.pending_skills == {'recon'} and agent.history == before
    assert '# Recon playbook' in '\n'.join(m.content for m in projection(agent))
    assert service.calls == 0


async def test_model_loading_same_skill_does_not_replace_manual_provenance():
    agent, service = agent_fixture()
    await agent.inject_skill('recon')
    agent.active_skills = set(agent.pending_skills)
    agent.pending_skills.clear()
    agent._skill_contracts['recon'] = replace(agent._skill_contracts['recon'], owner=agent._skill_owner())
    await load(agent, 'recon')
    advance(agent)
    assert not (await invoke_service(agent)).err_str and service.calls == 1
    assert agent._skill_contracts['recon'].source == 'manual'


async def test_compaction_omits_retired_body_and_preserves_restriction():
    agent, service = agent_fixture()
    await load(agent, 'recon')
    agent.history.append(Message('user', 'old unrelated conversation ' * 3000))
    await agent.set_skill_enabled('recon', False)
    client = SnapshotClient([ChatResponse(Message('assistant', '## Open TODOs\n- Continue from current state.'), 'stop')])
    agent.client = client
    await agent.compact_in_place(FakeSignal())
    assert '# Recon playbook' not in '\n'.join(m.content for m in client.requests[0].messages)
    assert (await invoke_service(agent)).err_str and service.calls == 0
    assert not agent.active_skills and not agent.pending_skills


async def test_skill_change_during_compaction_cannot_publish_stale_summary():
    agent, service = agent_fixture()
    await load(agent, 'recon')
    agent.history.append(Message('user', 'old conversation ' * 3000))
    entered, release = asyncio.Event(), asyncio.Event()
    class Waiting(SnapshotClient):
        async def chat(self, request, signal=None):
            entered.set()
            await release.wait()
            return await super().chat(request, signal)
    agent.client = Waiting([ChatResponse(Message('assistant', '## Open TODOs\n- Stale summary marker.'), 'stop')])
    task = asyncio.create_task(agent.compact_in_place(FakeSignal()))
    await entered.wait()
    await agent.set_skill_enabled('recon', False)
    before = deepcopy(agent.history)
    release.set()
    with pytest.raises(RuntimeError, match='stale summary discarded'):
        await task
    assert agent.history == before and agent.memory is None
    assert service.calls == 0


async def test_failed_reload_retains_current_activation_and_body(monkeypatch):
    agent, service = agent_fixture()
    await load(agent, 'recon')
    before = dict(agent._skill_contracts)
    def fail():
        agent._reconcile_skill_contracts()
        raise ValueError('synthetic prompt failure')
    monkeypatch.setattr(agent, 'rebuild_from_skills', fail)
    with pytest.raises(ValueError): publish_snapshot(agent, Registry())
    assert agent._skill_contracts == before and agent.active_skills == {'recon'}
    assert '# Recon playbook' in '\n'.join(m.content for m in projection(agent))
    assert not (await invoke_service(agent)).err_str and service.calls == 1


@pytest.mark.parametrize('legacy_role', ['system', 'tool'])
async def test_legacy_unknown_provenance_remains_historical_data_without_inferred_activation(legacy_role):
    agent, service = agent_fixture()
    body = 'The user selected skill unknown via /skills. Unknown historical playbook'
    agent.history.append(Message(legacy_role, body, name='load_skill' if legacy_role == 'tool' else None))
    raw = deepcopy(agent.history)
    projected = projection(agent)
    assert body in projected[1].content and projected[1].role != 'system'
    assert agent.history == raw and not agent._skill_contracts
    assert not agent.active_skills and not agent.pending_skills and service.calls == 0


from tests.security.test_http_invocation_lifecycle import runtime as http_runtime


@pytest.mark.parametrize('change', ['disable', 'reload'])
@pytest.mark.parametrize('bound', [False, True])
async def test_native_http_rechecks_skill_after_inner_http_permission_wait(http_runtime, change, bound):
    from src.agent.agent import Agent, AgentOptions
    tool, tools, prompter, policy, control, entered, release = http_runtime
    if not bound:
        prompter.execution_policy = None
    registry = Registry()
    registry.load_dir('skills')
    tools.register(LoadSkillTool(registry))
    agent = Agent(AgentOptions(client=SnapshotClient([]), tools=tools, skills=registry,
        prompter=prompter, store=None, target=tool.target, engagement_state=tool.engagement))
    await load(agent, 'recon')
    control.block = 'review'
    call = ToolCall('http', FunctionCall('http', json.dumps({'url': '/', 'phase': 'recon'})))
    task = asyncio.create_task(agent.run_parsed_tool_call(call, agent.parse_tool_call(call), FakeSignal()))
    await entered.wait()
    if change == 'disable': await agent.set_skill_enabled('recon', False)
    else: publish_snapshot(agent, Registry())
    before = deepcopy(agent.workflow.to_dict())
    release.set()
    result = await task
    assert result.err_str and not control.sent
    assert policy.active == 0 and not policy._receipts and not tool.permissions._receipts
    assert_no_artifacts(agent, before)


@pytest.mark.parametrize('tool_mode', [False, True])
async def test_request_readmission_elides_disable_during_save_without_changing_transcript(monkeypatch, tool_mode):
    agent, service = agent_fixture()
    await load(agent, 'recon')
    before = deepcopy(agent.history)
    original = agent._admit_request
    changed = False
    async def admit(request, emit):
        nonlocal changed
        await original(request, emit)
        if not changed:
            changed = True
            await agent.set_skill_enabled('recon', False)
    monkeypatch.setattr(agent, '_admit_request', admit)
    client = SnapshotClient([ChatResponse(Message('assistant', 'done'), 'stop')])
    agent.client = client
    request = ChatRequest(client.model(), deepcopy(agent.history), tools=agent.tools.as_llm_tools() if tool_mode else None)
    await agent._chat_for_turn(request, FakeSignal(), lambda e: None)
    assert '# Recon playbook' not in '\n'.join(m.content for m in client.requests[0].messages)
    assert agent.history[1:] == before[1:] and service.calls == 0


async def test_cancelled_manual_activation_cannot_rollback_into_reset_generation(monkeypatch):
    agent, service = agent_fixture()
    entered = asyncio.Event()
    async def save():
        entered.set()
        await asyncio.Event().wait()
    monkeypatch.setattr(agent, 'save', save)
    async def select():
        async with skill_changes(agent):
            await agent.inject_skill('recon')
    task = asyncio.create_task(select())
    await entered.wait()
    await agent.reset()
    before = deepcopy(agent.history)
    task.cancel()
    with pytest.raises(asyncio.CancelledError): await task
    assert not agent.pending_skills and not agent.active_skills and not agent._skill_contracts
    assert agent.history == before and service.calls == 0


async def test_identical_reload_keeps_contract_but_removed_readded_skill_needs_fresh_load():
    agent, service = agent_fixture()
    await load(agent, 'recon')
    before = dict(agent._skill_contracts)
    snapshot = Registry()
    for skill in agent.skills.list(): snapshot.add(deepcopy(skill))
    publish_snapshot(agent, snapshot)
    assert agent._skill_contracts == before
    assert not (await invoke_service(agent)).err_str and service.calls == 1
    publish_snapshot(agent, Registry())
    publish_snapshot(agent, snapshot)
    assert (await invoke_service(agent)).err_str and service.calls == 1
    await load(agent, 'recon')
    assert not (await invoke_service(agent)).err_str and service.calls == 2


async def test_unknown_active_contract_cannot_open_initial_unrestricted_state():
    agent, service = agent_fixture()
    agent.active_skills.add('unavailable')
    before = deepcopy(agent.workflow.to_dict())
    assert (await invoke_service(agent)).err_str and service.calls == 0
    assert_no_artifacts(agent, before)


async def test_retirement_restriction_survives_compaction_save_resume(tmp_path):
    agent, service = agent_fixture(tmp_path)
    await load(agent, 'recon')
    agent.history.append(Message('user', 'old conversation ' * 3000))
    await agent.set_skill_enabled('recon', False)
    agent.client = SnapshotClient([ChatResponse(Message('assistant', '## Open TODOs\n- Inspect current state.'), 'stop')])
    await agent.compact_in_place(FakeSignal())
    assert not any(m.skill_activation for m in agent.history)
    await agent.save()
    agent.resume_saved()
    assert agent._skill_admission_restricted and not agent.active_skills
    assert (await invoke_service(agent)).err_str and service.calls == 0


async def test_artifact_repair_hint_does_not_add_a_scanner_admission_gate(tmp_path):
    from src.tools.workflow.workflow_tool import WorkflowTool
    agent, service = agent_fixture()
    workflow = WorkflowTool(agent.workflow, agent.target, skills=agent.skills, evidence_root=tmp_path)
    agent.tools.register(workflow)
    await load(agent, 'recon')
    advance(agent)
    readiness = agent._phase_completion_readiness()
    assert readiness is not None and readiness['phase'] == 'recon' and readiness['ready'] is False
    before = deepcopy(agent.workflow.to_dict())
    await load(agent, 'web-enumeration')
    assert agent.active_skills == {'web-enumeration'}
    assert '# Web enumeration playbook' in '\n'.join(m.content for m in projection(agent))
    assert (await invoke_service(agent)).err_str and service.calls == 0
    assert_no_artifacts(agent, before)


async def test_validators_retire_on_explicit_late_input_analysis_replacement():
    from src.workflow.state import AttackSurfaceInput
    agent, service = agent_fixture()
    for phase in ('recon', 'enumeration', 'input_analysis'):
        record_completed_phase(agent.workflow, phase, objective_id='objective', target_origin=ORIGIN,
            artifact_ref=f'artifacts/{phase}.md', no_inputs_discovered=phase == 'input_analysis')
    await load(agent, 'sql-injection')
    assert agent.active_skills == {'sql-injection'}
    agent.workflow.add_attack_surface_input(AttackSurfaceInput('objective', ORIGIN, method='GET',
        endpoint='/late?q=one', parameter='q', location='query'))
    before = deepcopy(agent.workflow.to_dict())
    await load(agent, 'web-input-analysis')
    assert agent.active_skills == {'web-input-analysis'}
    assert '# SQL injection playbook' not in '\n'.join(m.content for m in projection(agent))
    assert service.calls == 0
    assert_no_artifacts(agent, before)


async def test_existing_manual_replacement_still_retires_old_model_phase_contract():
    agent, service = agent_fixture()
    await agent.inject_skill('web-enumeration')
    agent.active_skills = set(agent.pending_skills)
    agent.pending_skills.clear()
    agent._skill_contracts['web-enumeration'] = replace(agent._skill_contracts['web-enumeration'], owner=agent._skill_owner())
    await load(agent, 'recon')
    advance(agent)
    await load(agent, 'web-enumeration')
    assert agent.active_skills == {'web-enumeration'}
    assert agent._skill_contracts['web-enumeration'].source == 'manual'
    assert (await invoke_service(agent)).err_str and service.calls == 0


async def test_load_fingerprint_is_frozen_at_controller_event_before_execution():
    agent, service = agent_fixture()
    call = ToolCall('load', FunctionCall('load_skill', json.dumps({'name': 'recon'})))
    parsed = agent.parse_tool_call(call)
    agent._tool_call_event(call, parsed)
    original = parsed.skill_load
    agent.skills.skills['recon'].body += '\nReloaded after dispatch event'
    result = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    assert not result.err_str and parsed.skill_load == original
    before = deepcopy(agent.workflow.to_dict())
    events = []
    agent.record_tool_result(call, parsed, result, events.append, [])
    assert not agent.active_skills and not any(e['type'] == 'skill-active' for e in events)
    assert '# Recon playbook' not in '\n'.join(m.content for m in projection(agent))
    assert service.calls == 0
    assert_no_artifacts(agent, before)


async def test_phase_replacement_during_permission_review_rechecks_current_tool_capability():
    agent, service = agent_fixture()
    await load(agent, 'recon')
    entered, release = asyncio.Event(), asyncio.Event()
    class Review:
        async def ask(self, request, signal=None):
            entered.set()
            await release.wait()
            return Decision.ALLOW_ONCE
    agent.prompter = Review()
    task = asyncio.create_task(invoke_service(agent))
    await entered.wait()
    advance(agent)
    await load(agent, 'web-enumeration')
    before = deepcopy(agent.workflow.to_dict())
    release.set()
    result = await task
    assert result.err_str and service.calls == 0
    assert_no_artifacts(agent, before)


@pytest.mark.parametrize('bound', [False, True])
@pytest.mark.parametrize('mutation', ['args', 'name'])
async def test_argument_aware_recheck_uses_original_action_after_contract_change(tmp_path, bound, mutation):
    from src.coverage.store import CoverageStore
    from src.tools.workflow.coverage import CoverageTool
    from src.permission.permission import YoloPrompter
    from src.permission.runtime.execution import default_execution_policy
    agent, _ = agent_fixture()
    store = CoverageStore(str(tmp_path / 'coverage.json'))
    await store.mark(endpoint='GET /owned', param='q', vulnClass='xss', status='tried')
    agent.tools.register(CoverageTool(store))
    agent.skills.skills['recon'].tools.append('coverage')
    await load(agent, 'recon')
    call = ToolCall('clear', FunctionCall('coverage', json.dumps({'action': 'clear'})))
    parsed = agent.parse_tool_call(call)
    snapshots = []
    class Operator:
        async def ask(self, request, signal=None):
            assert request.tool == 'coverage'
            if mutation == 'args':
                parsed.args['action'] = 'summary'
            else:
                call.function.name = 'load_skill'
            advance(agent)
            await load(agent, 'web-enumeration')
            snapshots.append(deepcopy(agent.workflow.to_dict()))
            return Decision.ALLOW_ONCE
    prompter = YoloPrompter(Operator(), False)
    if bound:
        prompter.bind_execution_policy(default_execution_policy(agent.engagement_state, tmp_path))
    agent.prompter = prompter
    result = await agent.run_parsed_tool_call(call, parsed, FakeSignal())
    assert result.err_str and len(store.entries) == 1
    assert agent.active_skills == {'web-enumeration'}
    assert not agent.is_tool_allowed('coverage', {'action': 'clear'}).ok
    assert agent.is_tool_allowed('coverage', {'action': 'summary'}).ok
    assert_no_artifacts(agent, snapshots[0])
