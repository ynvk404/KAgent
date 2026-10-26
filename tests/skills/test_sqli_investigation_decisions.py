"""Guidance coverage plus a synthetic SQL trace; no live target or model."""
import asyncio
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import parse_qs, urlencode

import httpx
import pytest

from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry


PLAYBOOK = Path(__file__).resolve().parents[2] / 'skills/sql-injection/SKILL.md'


def section(start, end):
    return ' '.join(PLAYBOOK.read_text().split(start, 1)[1].split(end, 1)[0].lower().split())


def test_probe_decisions_connect_diagnostics_to_a_discriminating_prediction():
    text = section('## Decision checkpoint', '## Runtime completion contract')
    assert 'observe → hypothesize → discriminate → predict → execute → interpret → reassess → decide' in text
    for boundary in ('quotes', 'expression', 'parentheses/grouping', 'trailing syntax'):
        assert boundary in text
    assert 'did not test the computed-output hypothesis' in text
    assert 'syntactically incorrect probe does not invalidate a technique' in text
    assert 'same prediction' in text and 'equivalent failed probes' in text
    assert 'no new request or external event' in text


def test_union_decision_prioritizes_constants_without_relaxing_proof_or_scope():
    text = section('### Bounded UNION-based', '### 2c.')
    for concept in ('constants of compatible types', 'computed expression', 'owned benign control',
                    'already known projection', 'reproduce the evaluated result', 'not that oracle',
                    'never enumerate', 'version/banner reads still require phase 3'):
        assert concept in text
    assert 'do not substitute real application columns' in text


def test_closure_distinguishes_untested_hypotheses_and_reasoned_decline():
    text = section('### Closing an inconclusive attempt', '### Evidence-to-decision checkpoint')
    for concept in ('untested alternative', 'falsified hypothesis', 'remaining uncertainty',
                    'low-cost', 'meaningfully different', 'unsafe', 'exceed resources',
                    'retry_decision', 'decline', 'neither retry nor decline', 'can be reconsidered',
                    'no minimum payload count', 'not a mandatory technique'):
        assert concept in text


@pytest.mark.parametrize('grouping_depth', [1, 2, 3])
def test_synthetic_trace_separates_syntax_rejection_from_constant_evaluation(grouping_depth):
    # Representative historical failure mode: a parser error before UNION is
    # not a test of its projection. Depth varies in this invented local query;
    # no historical payload or target identity is copied into the playbook.
    with sqlite3.connect(':memory:') as db:
        def query(value):
            return db.execute("SELECT 'ordinary' WHERE " + '(' * grouping_depth
                              + f"'needle' LIKE '%{value}%'" + ')' * grouping_depth).fetchall()

        assert query('needle') == [('ordinary',)]
        with pytest.raises(sqlite3.OperationalError):
            query("x' UNION SELECT (7 * 7) --")
        revised = "x'" + ')' * grouping_depth + ' UNION SELECT (7 * 7) --'
        assert query(revised) == [(49,)]
        assert query(revised) == [(49,)]
        # Scripted trace establishes this local SQL distinction only. It does
        # not measure whether an LLM will identify or apply the revised strategy.


@pytest.fixture(scope='module')
def loaded_sql():
    registry = Registry()
    registry.load_dir(PLAYBOOK.parents[1])
    return asyncio.run(LoadSkillTool(registry).run({'name': 'sql-injection'}))


@pytest.fixture(scope='module')
def grouping_templates(loaded_sql):
    # Test the SQL delivered by the real loader, not a second reasoning policy.
    block = next(block for block in re.findall(r'```sql\s*\n(.*?)```', loaded_sql, re.S)
                 if '-- H1:' in block)
    return dict(re.findall(r'-- (H[123]):[^\n]*\n([^\n]+)', block))


@pytest.mark.parametrize('hypothesis', ['H1', 'H2', 'H3'])
def test_documented_grouping_predictions_and_failed_probe_limits(grouping_templates, hypothesis):
    template = grouping_templates[hypothesis]
    with sqlite3.connect(':memory:') as db:
        assert db.execute(template.replace('{input}', 'moss')).fetchall() == [('marker',)]
        assert db.execute(template.replace('{input}', 'birch')).fetchall() == []
        # A bare quote/group probe leaves an incompatible suffix in all three.
        with pytest.raises(sqlite3.OperationalError):
            db.execute(template.replace('{input}', "')"))
        syntax_test = template.replace('{input}', "moss'))--")
        if hypothesis == 'H2':
            assert db.execute(syntax_test).fetchall() == [('marker',)]
        else:
            with pytest.raises(sqlite3.OperationalError):
                db.execute(syntax_test)


def test_documented_boundary_acceptance_precedes_a_distinct_evaluation_test(loaded_sql, grouping_templates):
    assembled = next(block.strip() for block in re.findall(r'```sql\s*\n(.*?)```', loaded_sql, re.S)
                     if not block.startswith('--') and "LIKE '%moss'))--" in block)
    template = grouping_templates['H2']
    assert assembled == template.replace('{input}', "moss'))--")
    with sqlite3.connect(':memory:') as db:
        # Acceptance preserves an ordinary marker, whereas a controlled predicate
        # changes evaluation in this synthetic query. Neither is live HTTP proof.
        assert db.execute(assembled).fetchall() == [('marker',)]
        rows = [db.execute(template.replace('{input}', "moss')) AND " + predicate + '--')).fetchall()
                for predicate in ('1=1', '1=2')]
        assert rows == [[('marker',)], []]


def test_documented_like_composition_changes_the_intended_true_value(loaded_sql):
    block = next(block for block in re.findall(r'```sql\s*\n(.*?)```', loaded_sql, re.S)
                 if "'1'='1%'" in block)
    with sqlite3.connect(':memory:') as db:
        assert [db.execute(sql).fetchall() for sql in block.splitlines() if sql.strip()] == [
            [], [('marker',)], [],
        ]
        # Both equalities can be empty even when the application concatenates SQL.
        assert db.execute(block.splitlines()[0].replace("='1%'", "='2%'")).fetchall() == []
        for predicate in ('1=1', '1=2'):
            with pytest.raises(sqlite3.OperationalError):
                db.execute("SELECT 'marker' WHERE (('moss' LIKE '%moss' AND (" + predicate + "%'));")


def test_synthetic_quotes_identifiers_numeric_and_expression_positions():
    with sqlite3.connect(':memory:') as db:
        # SQL quote doubling preserves data; a backslash alone does not in SQLite.
        assert db.execute("SELECT 'moss'''").fetchone() == ("moss'",)
        with pytest.raises(sqlite3.OperationalError):
            db.execute("SELECT 'moss\\''")
        assert db.execute('SELECT 1 AND 1=2').fetchone() == (0,)
        assert db.execute("SELECT '1 AND 1=2'").fetchone() == ('1 AND 1=2',)
        assert db.execute('SELECT "label" FROM (SELECT \'moss\' AS label)').fetchone() == ('moss',)
        assert db.execute("SELECT 'label' FROM (SELECT 'moss' AS label)").fetchone() == ('label',)
        assert db.execute("SELECT lower('MOSS') = 'moss'").fetchone() == (1,)
        assert db.execute("SELECT 'marker' WHERE 1=2").fetchall() == []
        assert db.execute('SELECT 1=2').fetchall() == [(0,)]
        assert db.execute("SELECT 'marker' ORDER BY 1=2").fetchall() == [('marker',)]
        # In-memory scratch only: VALUES stores a scalar; it is not an AND row filter.
        db.execute('CREATE TABLE scratch(v)')
        db.execute('INSERT INTO scratch(v) VALUES (1 AND 1=2)')
        assert db.execute('SELECT v FROM scratch').fetchall() == [(0,)]


def test_synthetic_comment_literal_suffix_and_newline():
    with sqlite3.connect(':memory:') as db:
        assert db.execute("SELECT '--tail'").fetchone() == ('--tail',)
        assert db.execute('SELECT 1 --+ 1').fetchone() == (1,)
        assert db.execute('SELECT 1 --\n+ 1').fetchone() == (2,)
        with pytest.raises(sqlite3.OperationalError):
            db.execute('SELECT (1 --)')


def test_synthetic_computed_result_is_distinct_from_echo_but_can_collide_with_baseline():
    with sqlite3.connect(':memory:') as db:
        echo = db.execute("SELECT '7 * 7'").fetchone()[0]
        computed = db.execute('SELECT 7 * 7').fetchone()[0]
        ordinary = db.execute('SELECT 49').fetchone()[0]
        assert echo == '7 * 7' and computed == 49
        assert str(computed) not in echo
        assert computed == ordinary  # Presence of 49 alone cannot discriminate this control.


@pytest.mark.parametrize(('logical', 'wire'), [("'", 'q=%27'), ('%27', 'q=%2527'), ('%2527', 'q=%252527')])
def test_logical_input_wire_and_single_decoding_remain_distinct(grouping_templates, logical, wire):
    assert urlencode({'q': logical}) == wire
    request = httpx.Request('GET', 'https://example.invalid/search?' + wire)
    assert request.url.raw_path == ('/search?' + wire).encode('ascii')
    once = parse_qs(request.url.query.decode('ascii'))['q'][0]
    assert once == logical
    assert json.loads(json.dumps({'q': logical}))['q'] == logical  # JSON adds no percent decode.
    with sqlite3.connect(':memory:') as db:
        sql = grouping_templates['H2'].replace('{input}', once)
        if logical == "'":
            with pytest.raises(sqlite3.OperationalError):
                db.execute(sql)
        else:
            assert db.execute(sql).fetchall() == []
