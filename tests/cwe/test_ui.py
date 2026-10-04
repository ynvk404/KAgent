from unittest.mock import Mock
from rich.text import Text

import pytest

from src.ui.core.app import KAgent, _modal_text
from src.ui.widgets.text_input_modal import TextInputModal, TextInputRequest
from tests.ui.test_app import make_app


@pytest.mark.asyncio
async def test_cwe_review_metadata_is_plain_scrollable_and_does_not_choose(monkeypatch):
    monkeypatch.setattr(KAgent, 'on_mount', lambda self: None)
    app = make_app()
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    resolve = Mock()
    request = TextInputRequest(header='CWE classification review',
        question='\n'.join(f'{i}: [bold]literal source[/bold]' for i in range(100)),
        placeholder='0–5', resolve=resolve, reject=Mock(), scrollable=True)
    async with app.run_test(size=(80, 40)) as pilot:
        app.text_input = request
        app._sync_overlay()
        await pilot.pause()
        rendered = _modal_text(app._text_input_modal)
        assert isinstance(rendered, Text)
        assert '[bold]literal source[/bold]' in rendered.plain
        await pilot.press('pagedown')
        await pilot.pause()
        assert app.overlay_content_static.scroll_y > 0
        resolve.assert_not_called()


@pytest.mark.asyncio
async def test_cancelled_operator_input_clears_only_its_own_overlay():
    import asyncio
    app = make_app()
    request = TextInputRequest(header='CWE review', question='Choose or abstain',
        placeholder='0–1', resolve=Mock(), reject=Mock(), scrollable=True)
    first = asyncio.create_task(app.prompt_text(request))
    await asyncio.sleep(0)
    assert app.text_input is not None and app.text_input_future is not None
    future = app.text_input_future
    with pytest.raises(ValueError, match='already pending'):
        await app.prompt_text(request)
    assert app.text_input_future is future and not first.done()
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    assert app.text_input is None and app.text_input_future is None
    second = asyncio.create_task(app.prompt_text(request))
    await asyncio.sleep(0)
    app.resolve_text_input('0')
    assert await second == '0'
    assert app.text_input is None and app.text_input_future is None
