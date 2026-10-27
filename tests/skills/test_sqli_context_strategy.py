"""Loaded guidance and local SQL examples; these do not measure LLM decisions."""
import asyncio
import sqlite3
from pathlib import Path

import pytest

from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry


@pytest.fixture(scope='module')
def loaded_sql():
    registry = Registry()
    registry.load_dir(Path(__file__).resolve().parents[2] / 'skills')
    return asyncio.run(LoadSkillTool(registry).run({'name': 'sql-injection'}))


def compact(text):
    return ' '.join(text.lower().split())


@pytest.mark.parametrize('context,requirements', [
    ('SELECT row predicate', ('known benign match', 'full repeated pair', 'TRUE loses')),
    ('SELECT scalar/projection', ('known projection', 'computed result', 'echo/control')),
    ('INSERT / VALUES, UPDATE / SET', ('typed scalar', 'UPDATE / WHERE', 'isolation and cleanup')),
    ('CALL argument or call suffix', ('argument expression', 'argument types', 'completed call', 'other routines')),
    ('Identifier, sort key, or unknown expression', ('expected type', 'observable effect', 'hypothetical')),
])
def test_loaded_context_table_connects_technique_to_oracle_and_limit(loaded_sql, context, requirements):
    row = next(line for line in loaded_sql.splitlines() if line.startswith('| ' + context + ' |'))
    for requirement in requirements:
        assert compact(requirement) in compact(row)


def test_component_guidance_preserves_whole_target_and_replay_contracts(loaded_sql):
    text = compact(loaded_sql.split('### Input component checkpoint', 1)[1]
                   .split('## Phase 1:', 1)[0])
    for requirement in (
        'input_component: name', 'replace the selected query/form key',
        'preserve its baseline value', 'input_component: value',
        'keep its key', 'json pointer', 'path', 'header or cookie',
        'not a new workflow field or tool argument',
        'do not require it from whole-target handoffs',
        'effective request preview', 'pre-dispatch', 'not a target sql response',
        'selectors replace supported values, not parameter names',
        'do not drop `candidate_id`', 'no new adapter, origin or action authority',
    ):
        assert requirement in text


def test_failed_oracles_require_a_new_prediction_and_early_finalization(loaded_sql):
    decision = compact(loaded_sql.split('## Decision checkpoint', 1)[1]
                       .split('## Runtime completion contract', 1)[0])
    for requirement in (
        'diagnostic categories', 'echoed payloads', 'without showing evaluation',
        'equal retained body hashes', 'marker must actually occur in its cited response',
        'revised hypothesis', 'different observable prediction',
        'finalize as unresolved', 'effect bookkeeping', 'minimal proof writing',
        'registration', 'result submission', 'finding persistence',
        'perform those local steps immediately', 'no quota or budget extension',
    ):
        assert requirement in decision
    selection = compact(loaded_sql.split('## Phase 2: Validation', 1)[1].split('### 2a.', 1)[0])
    assert 'different parser token alone is not a controlled error-based oracle' in selection
    assert 'insufficient-evidence' in selection and 'completed `not-confirmed`' in selection


def test_local_update_set_and_where_require_different_observations():
    # These local writes are rolled back in an in-memory fixture. They never
    # authorize target readback or relax the playbook's isolation/cleanup guard.
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE scratch(v INTEGER)')
        db.execute('INSERT INTO scratch VALUES (9)')
        for predicate, scalar, affected in [('1=1', 1, 1), ('1=2', 0, 0)]:
            set_result = db.execute('UPDATE scratch SET v=(' + predicate + ')')
            assert set_result.rowcount == 1  # both acknowledge a write
            assert db.execute('SELECT v FROM scratch').fetchone() == (scalar,)
            filter_result = db.execute('UPDATE scratch SET v=9 WHERE ' + predicate)
            assert filter_result.rowcount == affected
        db.rollback()


def test_local_escaped_literal_acceptance_is_not_controlled_evaluation():
    with sqlite3.connect(':memory:') as db:
        for value in ("moss' AND 1=1", "moss' AND 1=2"):
            escaped = value.replace("'", "''")
            assert db.execute("SELECT '" + escaped + "'").fetchone() == (value,)
        # Error-free echo is distinct from evaluating the input as SQL.
        assert db.execute('SELECT 7 * 7').fetchone() == (49,)
