"""Guidance coverage plus a synthetic SQL trace; no live target or model."""
from pathlib import Path
import sqlite3

import pytest


PLAYBOOK = Path(__file__).resolve().parents[2] / 'skills/sql-injection/SKILL.md'


def section(start, end):
    return ' '.join(PLAYBOOK.read_text().split(start, 1)[1].split(end, 1)[0].lower().split())


def test_probe_decisions_connect_diagnostics_to_a_discriminating_prediction():
    text = section('## Decision checkpoint', '## Runtime completion contract')
    assert 'observe → hypothesize → discriminate → reassess' in text
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
