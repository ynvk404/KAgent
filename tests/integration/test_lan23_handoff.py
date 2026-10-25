"""Loaded guidance and independently ready inputs do not impose global barriers."""
import json

from src.skills.artifacts import completion_artifact_path
from tests.helpers.burp_selection import ORIGIN
from tests.helpers.discovery_calls import execute
from tests.integration.test_lan06_handoff import analysis, proposal  # noqa: F401


async def test_loading_sql_guidance_and_partial_analysis_keep_independent_validation(analysis):
    rt, item, _, sent = analysis
    await execute(rt, 'load_skill', {'name': 'sql-injection'})
    assert 'input_analysis' not in rt.workflow.completed_phases()
    assert not rt.workflow.attempts and rt.agent._planner_context().structured_phase == 'input_analysis'
    other = json.loads((await execute(rt, 'workflow', {'action': 'record_input', 'method': 'POST',
        'endpoint': '/unresolved', 'parameter': 'body', 'location': 'json'})).result)['input']
    await execute(rt, 'workflow', {'action': 'set_input_disposition', 'input_id': other['id'],
        'disposition': 'blocked', 'disposition_reason': 'The required request schema is unavailable; no auth assumption.'})
    candidate = json.loads((await execute(rt, 'workflow', proposal(item))).result)['candidate']
    await execute(rt, 'workflow', {'action': 'set_input_disposition', 'input_id': item['id'],
        'disposition': 'analyzed', 'analysis_complete': True})
    skill = rt.skills.get('web-input-analysis')
    assert skill is not None and skill.completion_artifact
    path = rt.policy.root / completion_artifact_path(skill.completion_artifact, ORIGIN)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('Partial offline handoff: one analyzed candidate; one input remains blocked.')
    assert not rt.workflow_tool.phase_completion_readiness('web-input-analysis')['ready']
    started = json.loads((await execute(rt, 'workflow', {'action': 'start_validation',
        'candidate_id': candidate['id']})).result)
    assert started['ok'] and len(sent) == 1
    assert rt.workflow.attack_surface_inputs[other['id']].disposition == 'blocked'
    assert 'input_analysis' not in rt.workflow.completed_phases()
