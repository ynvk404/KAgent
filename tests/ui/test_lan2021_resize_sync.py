"""Geometry checks must await Textual's deferred resize callback."""
import pytest
from textual.geometry import Size

from tests.ui import test_overview as overview

offline_startup = overview.offline_startup


@pytest.mark.parametrize("reading", [False, True])
async def test_resize_assertions_wait_for_delayed_layout(tmp_path, monkeypatch, reading):
    set_timer = overview.KAgent.set_timer
    delayed = []

    def timer(self, delay, callback=None, *args, **kwargs):
        if getattr(callback, "__name__", "") == "_check_resize":
            delay = 0.2
            delayed.append(self.size)
        return set_timer(self, delay, callback, *args, **kwargs)

    monkeypatch.setattr(overview.KAgent, "set_timer", timer)
    # Reuse every existing geometry, selection, anchor and tail assertion.
    await overview.test_progress_height_resize_keeps_transcript_anchor_tail_and_copy(tmp_path, reading)
    assert {Size(45, 24), Size(80, 14), Size(120, 32)} <= set(delayed)
