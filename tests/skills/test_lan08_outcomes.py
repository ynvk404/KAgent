"""Loaded instructions, not an executable SQLi classifier or model reliability test."""
import re

from src.skills.registry import Registry
from src.skills.load_skill import LoadSkillTool


async def test_negative_outcome_requires_an_established_observation_mechanism():
    skills = Registry()
    skills.load_dir('skills')
    body = await LoadSkillTool(skills).run({'name': 'sql-injection'})
    definition = re.sub(r'\s+', ' ', body.split('- `not-confirmed` —', 1)[1].split('\n- `blocked`', 1)[0])
    assert 'adequate, relevant testing' in definition and 'bounded scope' in definition
    assert 'negative-assessment criteria' in definition
    assert 'without exact SQL syntax or proven predicate execution' in definition
    criteria = re.sub(r'\s+', ' ', body.split('**Negative-assessment criteria.**', 1)[1]
                      .split('For a boolean-based confirmed result', 1)[0])
    # Preserve the declaration contract while separating observation sensitivity
    # from successful injection; missing exact syntax alone is not a veto.
    assert 'assessment.oracle_status: established' in criteria
    assert 'assessment.oracle_basis' in criteria and 'observation mechanism' in criteria
    assert 'does not require a positive SQLi oracle' in criteria
    unresolved = re.sub(r'\s+', ' ', body.split('- `insufficient-evidence` —', 1)[1]
                        .split('`confirmed` and `not-confirmed` require', 1)[0])
    assert 'weakly controlled, unobservable or incomplete testing' in unresolved
    assert 'required sources or reproducible proof are unavailable' in unresolved
