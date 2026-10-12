"""Bounded impact and source summaries, without changing assessment semantics."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from src.ui.core.outcomes import _evidence_summary, concise_text


def source(identifier, kind='native-http', **fields):
    return {'source': {'id': identifier, 'source_kind': kind, 'role': 'baseline',
                       'complete': True, 'truncated': False,
                       'execution_status': 'completed', **fields}}


@pytest.mark.parametrize('kind,singular,plural', [
    ('native-http', 'HTTP observation', 'HTTP observations'),
    ('imported-capture', 'imported capture', 'imported captures'),
    ('tool-output', 'tool output', 'tool outputs'),
])
def test_evidence_counts_distinct_sources_instead_of_roles(kind, singular, plural):
    row = source('one', kind)
    assert _evidence_summary(SimpleNamespace(evidence_manifest=[row, row])) == f'1 {singular}'
    assert _evidence_summary(SimpleNamespace(evidence_manifest=[row, source('two', kind)])) == f'2 {plural}'


def test_evidence_mixed_sources_excludes_unusable_and_unknown_without_mutation():
    rows = [source('http'), source('http'), source('capture', 'imported-capture'),
            source('output', 'tool-output'), source('incomplete', complete=False),
            source('truncated', truncated=True), source('failed', execution_status='failed'),
            source('unknown', 'unknown'), {'source': {}}, {}]
    original = deepcopy(rows)
    assert _evidence_summary(SimpleNamespace(evidence_manifest=rows)) == (
        '1 HTTP observation · 1 imported capture · 1 tool output')
    assert rows == original
    assert _evidence_summary(SimpleNamespace(evidence_manifest=[])) == ''


@pytest.mark.parametrize('length', [239, 240, 241, 1000])
def test_impact_marker_boundary_and_repeat_formatting(length):
    text = 'x' * length
    displayed = concise_text(text, shortened_marker='… [shortened]')
    assert len(displayed) <= 240
    assert displayed.endswith('… [shortened]') is (length > 240)
    assert concise_text(displayed, shortened_marker='… [shortened]') == displayed
    if length <= 240:
        assert displayed == text
