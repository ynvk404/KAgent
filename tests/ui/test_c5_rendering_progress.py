import pytest
from textual.app import App, ComposeResult

from src.agent.events import ToolCallEvent, ToolResultEvent, DoneEvent
from src.ui.core.app import _RichLogWriter
from src.ui.core.state import TranscriptEntry
from src.ui.widgets.transcript import entry_view, RenderedLine
from src.ui.widgets.transcript_view import TranscriptView
from tests.ui.test_progress_milestones import dispatch
from tests.ui.test_app import make_app


class TranscriptApp(App):
    def compose(self) -> ComposeResult:
        yield TranscriptView(id='transcript')


async def test_real_richlog_line_writer_styles_only_generated_ansi(monkeypatch):
    monkeypatch.delenv('NO_COLOR', raising=False)
    app = TranscriptApp()
    async with app.run_test(size=(80, 20)) as pilot:
        log = app.query_one(TranscriptView)
        writer = _RichLogWriter(log)
        for line in entry_view(TranscriptEntry('assistant', '**bold** and *italic*\n\x1b[31mUNTRUSTED\x1b[0m')):
            writer.write_line(line)
        writer.write_line(RenderedLine('\x1b]52;c;UNTRUSTED\x07', 'white'))
        await pilot.pause()
        segments = [segment for strip in log.lines for segment in strip]
        text = ''.join(segment.text for segment in segments)
        assert '\x1b' not in text and '\\x1b[31mUNTRUSTED' in text
        assert any('bold' in segment.text and segment.style is not None and segment.style.bold for segment in segments)
        assert any('italic' in segment.text and segment.style is not None and segment.style.italic for segment in segments)
        assert '\\x1b]52;c;' in text


def test_old_operation_errors_do_not_become_current_blocker_count_or_final_cause():
    app = make_app()
    for identity in ('one', 'two'):
        dispatch(app, ToolCallEvent(id=identity, name='workflow', args={'action': 'record_result', 'candidate_id': identity}))
        dispatch(app, ToolResultEvent(id=identity, name='workflow', result='error: OLD-ERROR-' + identity,
                                     status='error', error_kind='workflow_state'))
    dispatch(app, DoneEvent(stop_reason='workflow_blocked'))
    summary = app.state.transcript[-1].text
    assert 'unresolved operation' not in summary
    assert 'unresolved blocker' not in summary and 'OLD-ERROR' not in summary
