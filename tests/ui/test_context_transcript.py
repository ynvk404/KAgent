"""Presentation checks; the runtime continues to own all context behavior."""
from copy import deepcopy
from src.agent.events import CompactEvent, DecisionEvent, ErrorEvent
from src.agent.agent import IneffectiveCompactionError
from src.llm.runtime.context_budget import ContextCapacityError, InputBudget
from tests.ui.test_progress_milestones import dispatch
from tests.ui.test_app import make_app
from src.ui.widgets.status_bar import idle_line
from tests.ui.test_status_bar import props
from src.llm.core.types import ChatRequest, Message
from src.agent.agent import _to_agent_event
from tests.agent.test_token_accounting_independent_verify import make_agent


def test_changing_pressure_diagnostics_stay_out_of_transcript():
    app = make_app()
    for count in range(15):
        dispatch(app, DecisionEvent(summary=f'context pressure: estimated total ~{41735+count} tokens; '
            'fixed/non-compactable floor; unresolved pressure: soft threshold exceeded',
            context_diagnostics={'estimated_total': 41735+count, 'estimate_only': True}))
    assert not app.state.transcript
    assert not app.state.issues


def test_real_compaction_receipt_is_concise_and_displayed_once():
    app = make_app()
    event = CompactEvent(summary='auto-compacted history', tokens_before=44600, tokens_after=20100)
    dispatch(app, event)
    dispatch(app, event)
    assert [row.text for row in app.state.transcript] == ['Context compacted · 44.6k → 20.1k tokens']


def test_trigger_and_skip_are_not_success_and_failure_is_visible():
    app = make_app()
    for summary in ['auto-compact triggered (soft pressure)', 'auto-compact skipped: nothing to compact',
                    'nothing to compact']:
        dispatch(app, CompactEvent(summary=summary, tokens_before=44600))
    assert not app.state.transcript
    dispatch(app, ErrorEvent(err=RuntimeError('auto-compact failed (1/3): provider unavailable')))
    assert len(app.state.transcript) == 1
    assert app.state.transcript[0].kind == 'error'


def test_ineffective_reduction_stays_quiet_and_hard_failure_is_visible():
    app = make_app()
    for i in range(15):
        message = 'compact result rejected: projected request would not shrink meaningfully'
        dispatch(app, ErrorEvent(err=IneffectiveCompactionError(message)))
        dispatch(app, ErrorEvent(err=RuntimeError(f'auto-compact failed ({i}/3): {message}')))
    assert not app.state.transcript and not app.state.issues
    dispatch(app, ErrorEvent(err=ContextCapacityError(44000, InputBudget(input_limit=32000), 35000)))
    assert app.state.transcript[-1].kind == 'error'
    assert '44000' in app.state.transcript[-1].text


def test_explicit_success_without_measurements_does_not_invent_numbers():
    app = make_app()
    dispatch(app, CompactEvent(summary='auto-compacted history: measurements unavailable'))
    assert app.state.transcript[0].text == 'Context compacted'


async def test_real_pressure_keeps_runtime_diagnostics_and_status_telemetry(monkeypatch):
    agent = make_agent()
    app = make_app()
    agent.set_auto_compact_threshold(100)
    setattr(agent.client, 'input_token_limit', 1000)
    diagnostic_trace = []
    monkeypatch.setattr(agent, '_trace', lambda kind, **data: diagnostic_trace.append((kind, data)))
    request = ChatRequest(model=agent.client.model(), messages=[Message('system', 's' * 800)])
    before = deepcopy(request)
    events = []
    await agent._admit_request(request, events.append)
    for event in events:
        dispatch(app, _to_agent_event(event))
    assert not app.state.transcript
    assert events[0]['context_diagnostics'] == agent.last_context_diagnostics
    assert any(kind == 'context_admission' and data['estimate_only'] for kind, data in diagnostic_trace)
    assert request == before
    assert 'history ~36.7k · request ~44.6k/32k soft 139%' in idle_line(
        props(ctx_tokens=36700, request_tokens=44600, compact_threshold=32000)).plain


def test_normal_usage_and_unavailable_reduction_are_quiet():
    app = make_app()
    dispatch(app, DecisionEvent(summary='context guard: below reduction threshold'))
    dispatch(app, CompactEvent(summary='nothing to compact'))
    assert not app.state.transcript
