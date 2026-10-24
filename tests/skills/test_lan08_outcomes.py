"""Loaded instructions, not an executable SQLi classifier or model reliability test."""
import re

from src.skills.registry import Registry
from src.skills.load_skill import LoadSkillTool


async def test_negative_outcome_definition_requires_an_established_oracle():
    skills = Registry()
    skills.load_dir('skills')
    body = await LoadSkillTool(skills).run({'name': 'sql-injection'})
    definition = re.sub(r'\s+', ' ', body.split('- `not-confirmed` —', 1)[1].split('\n- `blocked`', 1)[0])
    assert 'context-compatible' in definition and 'established oracle' in definition
    assert 'insufficient-evidence' in definition and 'syntax' in definition
