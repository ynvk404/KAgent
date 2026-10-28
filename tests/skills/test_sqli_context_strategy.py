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


def negative_criteria(loaded_sql):
    return compact(loaded_sql.split('**Negative-assessment criteria.**', 1)[1]
                   .split('For a boolean-based confirmed result', 1)[0])


def test_loaded_negative_criteria_require_relevant_observations_not_positive_execution(loaded_sql):
    criteria = negative_criteria(loaded_sql)
    for requirement in (
        'assessment.oracle_status: established', 'assessment.oracle_basis',
        'observation mechanism', 'correct input targeting',
        'benign controls showing that the application processes that input',
        'usable response/status/timing evidence', 'capable of revealing the tested behavior',
        'does not require a positive sqli oracle or proof that an injected sql predicate executed',
        'not proof of absolute safety', 'exact server-side sql or syntax context is not required',
        'justify test relevance', 'supported hypotheses', 'coverage and limitations',
        'an inapplicable technique is a limitation', 'no universal payload count',
    ):
        assert requirement in criteria


@pytest.mark.parametrize('start,end', [
    ('## Decision checkpoint', '## Runtime completion contract'),
    ('## Phase 2: Validation', '### 2a.'),
    ('### 2a.', '### 2b.'),
    ('If the negative-assessment criteria are met', '## Phase 3:'),
    ('## Recording the result', '### Closing an inconclusive attempt'),
])
def test_loaded_negative_entrypoints_use_the_same_assessment_criteria(loaded_sql, start, end):
    section = compact(loaded_sql.split(start, 1)[1].split(end, 1)[0])
    # The conclusion paragraph's opening contains the reference itself.
    assert 'negative-assessment criteria' in compact(start) + ' ' + section
    assert 'insufficient-evidence' in section or 'inconclusive' in section


@pytest.mark.parametrize('limitation', [
    'malformed', 'irrelevant', 'weak controls', 'unobservable effects',
    'incomplete testing', 'unresolved parser sensitivity',
])
def test_loaded_negative_criteria_preserve_inadequate_testing_as_unresolved(loaded_sql, limitation):
    criteria = negative_criteria(loaded_sql)
    assert limitation in criteria
    assert 'require `insufficient-evidence` when they prevent this assessment' in criteria
    assert 'a baseline alone or a few generic payloads with unchanged responses is insufficient' in criteria


def test_loaded_outcomes_do_not_require_exact_context_or_treat_parser_errors_as_confirmation(loaded_sql):
    outcomes = compact(loaded_sql.split('## Recording the result', 1)[1]
                       .split('### Closing an inconclusive attempt', 1)[0])
    assert 'unchanged responses can support this outcome with justified test relevance and controls' in outcomes
    assert 'without exact sql syntax or proven predicate execution' in outcomes
    assert 'unresolved parser sensitivity remains' in outcomes
    assert 'unresolved predicate compatibility or syntax context requires' not in compact(loaded_sql)
    checkpoint = compact(loaded_sql.split('### Evidence-to-decision checkpoint', 1)[1]
                         .split('### Standard result entry template', 1)[0])
    assert 'parser messages alone do not establish sqli-2' in checkpoint
    assert 'demonstrating controlled sql evaluation rather than merely altered parsing' in checkpoint
    assert 'not sqli-2 confirmation by themselves' in checkpoint


@pytest.mark.parametrize('parameterized', [True, False])
def test_local_controls_distinguish_bounded_negative_from_repeatable_positive(loaded_sql, parameterized):
    # Both implementations receive the same controls/probes. This illustrates
    # the documented distinction locally; it does not test an LLM's judgment.
    assert 'matching and nonmatching benign inputs' in negative_criteria(loaded_sql)
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE items(label TEXT)')
        db.execute('INSERT INTO items VALUES (?)', ('moss',))

        def rows(value):
            if parameterized:
                return db.execute('SELECT label FROM items WHERE label=?', (value,)).fetchall()
            return db.execute("SELECT label FROM items WHERE label='" + value + "'").fetchall()

        assert rows('moss') == [('moss',)]
        assert rows('birch') == []
        if parameterized:
            # Literal handling produces no SQL errors or positive predicate
            # oracle; calibrated controls still expose the tested row behavior.
            assert all(rows(value) == [] for value in (
                "moss'", "moss' AND '1'='1", "moss' AND '1'='2"))
        else:
            with pytest.raises(sqlite3.OperationalError):
                rows("moss'")  # parser sensitivity alone, not confirmation
            for _ in range(2):
                assert rows("moss' AND '1'='1") == [('moss',)]
                assert rows("moss' AND '1'='2") == []
            # A nonmatching seed hides a real injection from an AND comparison.
            assert rows("birch' AND '1'='1") == rows("birch' AND '1'='2") == []
