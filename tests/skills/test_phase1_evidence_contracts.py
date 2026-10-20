"""Loaded playbook/schema examples plus production request/observation provenance."""
import ast
import json
from pathlib import Path
import re

import pytest

from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry
from tests.security.test_agent_assessment import setup
from tests.security.test_execution_policy import runtime  # noqa: F401


async def loaded(name):
    skills = Registry()
    skills.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    return await LoadSkillTool(skills).run({'name': name})


async def test_xss_submission_examples_use_real_runtime_references(runtime, tmp_path):
    state, candidate, _, args, oid = await setup(runtime, tmp_path)
    registry, p, *_ = runtime
    text = await loaded('cross-site-scripting')
    match = re.search(r'```python\n(.*?)\n```', text, re.S)
    assert match is not None
    block = match[1]
    expressions = ast.parse(block).body
    assert all(isinstance(e, ast.Expr) for e in expressions)
    values = {'candidate_id': candidate.id, 'proof_path': 'proof.md', 'sources': [oid],
              'evidence_id': args['evidence_refs'][0], 'attempt_id': args['attempt_id']}
    submissions = [eval(compile(ast.Expression(e.value), '<skill-example>', 'eval'), {'__builtins__': {}}, values)
                   for e in expressions if isinstance(e, ast.Expr)]
    assert submissions[0].keys() == {'action', 'candidate_id', 'evidence_path', 'observation_ids'}
    assert json.loads(await registry.execute('workflow', submissions[0], None, p))['ok']
    assert json.loads(await registry.execute('workflow', submissions[1], None, p))['ok']
    result = state.latest_result(candidate.id)
    assert result is not None and result.outcome == 'not-confirmed'
    assert 'observation_ids' not in submissions[2] and 'evidence_refs' not in submissions[2]


async def test_xss_unresolved_example_without_primary_and_wrong_ownership(runtime, tmp_path):
    state, candidate, _, args, oid = await setup(runtime, tmp_path)
    registry, p, *_ = runtime
    # Current unresolved contract permits absence, never supplied wrong refs.
    unresolved = {'action': 'record_result', 'candidate_id': candidate.id,
        'skill_name': 'cross-site-scripting', 'outcome': 'insufficient-evidence',
        'deferred_reason': 'Capture unavailable'}
    rejected = await registry.execute('workflow', {**unresolved, 'observation_ids': ['obs_wrong']}, None, p)
    assert 'PRIMARY_REFERENCE_UNAVAILABLE' in rejected and not state.validation_results
    assert json.loads(await registry.execute('workflow', unresolved, None, p))['ok']
    assert not state.eligible_for_finding(candidate.id)


async def test_sql_ledger_retains_controls_errors_and_incomplete_captures(runtime, tmp_path):
    state, candidate, _, args, full = await setup(runtime, tmp_path, candidate_class='sqli', payload='positive')
    registry, p, policy, _, sent, *_ = runtime
    ledger = [(full, 'positive')]
    for value, cap, label in [('control', 32, 'control'), ('error', 32, 'error'), ('positive', 1, 'incomplete')]:
        await registry.execute('http', {'url': '/fixture?q=' + value, 'phase': 'validation', 'max_response_bytes': cap}, None, p)
        ledger.append((next(reversed(policy.observations._items)), label))
    for oid, label in ledger:
        item = policy.observations._items[oid]
        preview = bytes.fromhex(item.source_details['request_preview_hex']).decode()
        expected = 'positive' if label == 'incomplete' else label
        assert '?q=' + expected in preview
        assert item.complete is (label != 'incomplete')
    assert sum(label == 'positive' for _, label in ledger) == 1
    text = ' '.join((await loaded('sql-injection')).split())
    for rule in ('two complete benign controls', 'one truncated UNION positive',
                 'do not copy a label from an earlier LLM summary', 'HTTP 200 alone',
                 'no fixed observation count'):
        assert rule in text
    # This is provenance coverage, not a SQL semantic verifier or request classifier.
    assert len(sent) == 4 and not state.validation_results


async def test_sql_terminal_example_uses_production_assessment_contract(runtime, tmp_path):
    state, candidate, _, args, oid = await setup(runtime, tmp_path, candidate_class='sqli')
    registry, p, *_ = runtime
    registered = json.loads(await registry.execute('workflow', {
        'action': 'record_evidence', 'candidate_id': candidate.id,
        'evidence_path': 'proof.md', 'observation_ids': [oid]}, None, p))
    text = await loaded('sql-injection')
    match = re.search(r'```python\n(.*?)\n```', text, re.S)
    assert match is not None
    expressions = ast.parse(match[1]).body
    assert len(expressions) == 1 and isinstance(expressions[0], ast.Expr)
    values = {'candidate_id': candidate.id, 'attempt_id': args['attempt_id'],
              'sources': [oid], 'evidence_id': registered['evidence']['id'],
              'hypothesis': 'A bounded fixture input could affect a SQL query',
              'criteria': 'Compare complete fixture control and probe responses',
              'limitations': 'Synthetic contract check; no SQLi semantics established',
              'observed_impact': 'The bounded fixture test did not establish SQL injection'}
    submission = eval(compile(ast.Expression(expressions[0].value), '<skill-example>', 'eval'),
                      {'__builtins__': {}}, values)
    # Required assessment fields and completed_attempt are enforced by production.
    for key in ('hypothesis', 'criteria', 'limitations', 'observed_impact', 'severity', 'completed_attempt'):
        incomplete = {**submission, 'assessment': {
            k: v for k, v in submission['assessment'].items() if k != key}}
        assert (await registry.execute('workflow', incomplete, None, p)).startswith('error:')
        assert not state.validation_results and not state.eligible_for_finding(candidate.id)
    result = json.loads(await registry.execute('workflow', submission, None, p))
    assert result['ok'] and result['result']['outcome'] == 'not-confirmed'
    assert not state.eligible_for_finding(candidate.id)
