"""Loaded instruction contracts, not an automated SQLi semantic verifier."""
from pathlib import Path

import pytest

from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry


@pytest.fixture
def skills():
    registry = Registry()
    registry.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    return registry


@pytest.mark.parametrize('name, obligations', [
    ('web-input-analysis', ['ordinary search differences', 'sibling endpoint', 'same empty result',
        'exact baseline', 'deferred_reason', 'queued', 'autonomously', 'read_discovery_source',
        'read_tool_result', 'Do not drop input_id']),
    ('web-enumeration', ['read_tool_result', 'each retained discovery row', '401/403', '500',
        'summary totals', 'field assignments', 'Shell HTTP is not a truncation fallback']),
])
async def test_loaded_playbooks_address_observed_grounding_failures(skills, name, obligations):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': name})).split())
    for obligation in obligations:
        assert obligation.lower() in loaded.lower()
    metadata = skills.get(name)
    assert metadata is not None and 'http' in metadata.tools and 'workflow' in metadata.tools
    assert 'Juice Shop' not in loaded and '/rest/products/search' not in loaded


async def test_response_shape_alone_does_not_recommend_sql_validator(skills):
    loaded = ' '.join((await LoadSkillTool(skills).run({'name': 'web-input-analysis'})).split())
    assert 'A different response shape tells you a parameter is worth handing to `sql-injection`' not in loaded
    assert 'class-specific' in loaded and 'SQL shape hypothetical' in loaded
