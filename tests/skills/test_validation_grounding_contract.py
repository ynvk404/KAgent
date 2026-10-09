"""Loaded playbook instruction contracts; these do not verify LLM behavior."""
from pathlib import Path

import pytest

from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry


@pytest.fixture
def skills():
    registry = Registry()
    registry.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    return registry


@pytest.mark.asyncio
@pytest.mark.parametrize('name', ['sql-injection', 'cross-site-scripting'])
async def test_loaded_validation_guidance_binds_claims_to_captures_and_new_repair_snapshots(skills, name):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': name})).split())
    for contract in ('observation ID', 'request_preview_complete: false',
                     'execution status' if name == 'sql-injection' else 'completed execution',
                     'Metadata-only capture', 'record_evidence', 'correct `observation_ids`',
                     'new immutable snapshot', '`evidence_refs` before resubmitting',
                     'registered snapshots in place', 'at most one repair submission',
                     '`insufficient-evidence` and stop'):
        assert contract.lower() in loaded.lower()
    metadata = skills.get(name)
    assert metadata is not None
    assert 'workflow' in metadata.tools
    assert not any('browser' in tool for tool in metadata.tools)


@pytest.mark.asyncio
async def test_sql_diagnostics_revise_quote_hypothesis_within_existing_allowance(skills):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': 'sql-injection'})).split())
    for contract in ('inside a SQL string literal', 'unless later observations contradict it',
                     'ordinary application text do not establish SQL context',
                     'retain an ambiguous context', 'After consecutive probes',
                     'same expression-type error', 'before another request',
                     'type error is distinct from a syntax error',
                     'do not restart the allowance or require every technique',
                     'any terminal assessment', 'distinct executed observations',
                     'reusing an observation ID does not establish repeatability'):
        assert contract in loaded


@pytest.mark.asyncio
async def test_xss_context_and_transformation_remain_bounded_without_execution_inference(skills):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': 'cross-site-scripting'})).split())
    for contract in ('neither `<html>` nor `<body>` wrappers are required',
                     'at most one bounded same-context close variant',
                     'This consumes the close variant allowance', 'every delimiter',
                     'Compare distinct captured requests', 'Content-Type, surrounding syntax',
                     'encoding, inert context and CSP',
                     'Neither raw reflection nor HTML fragment parsing alone establishes execution',
                     'not observed browser execution', 'retain `browser-required`'):
        assert contract in loaded
