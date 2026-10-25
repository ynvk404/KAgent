"""Startup delays are separate from responsiveness of the measured operation."""
import asyncio
import time

import pytest

from tests.ui import test_persistence_responsiveness as oracle

offline = oracle.offline


@pytest.mark.parametrize("blocked_operation", [False, True])
async def test_measurement_excludes_startup_but_keeps_operation_blocking(tmp_path, monkeypatch, blocked_operation):
    factory = oracle._make_app
    startup_delays = []

    def make_app():
        app = factory()
        set_interval = app.set_interval

        def interval(seconds, callback, *args, **kwargs):
            timer = set_interval(seconds, callback, *args, **kwargs)
            if seconds == oracle.HEARTBEAT:
                # First heartbeat, then a deliberately slow startup callback,
                # all before measure starts the actual filesystem operation.
                def startup():
                    startup_delays.append(True)
                    time.sleep(0.18)
                asyncio.get_running_loop().call_later(0.04, startup)
            return timer

        monkeypatch.setattr(app, "set_interval", interval)
        return app

    monkeypatch.setattr(oracle, "_make_app", make_app)
    if blocked_operation:
        run = oracle.FileWriteTool.run

        async def blocking(self, args, signal, prompter):
            time.sleep(0.18)  # noqa: ASYNC251 - deliberate blocking positive control.
            return await run(self, args, signal, prompter)

        monkeypatch.setattr(oracle.FileWriteTool, "run", blocking)
    result = await oracle.measure("file_write", False, tmp_path, monkeypatch)
    assert startup_delays == [True]
    assert oracle.RESPONSIVE_LIMIT_MS == 120.0
    if blocked_operation:
        assert result.heartbeat_gap_ms >= 180
        with pytest.raises(oracle.ResponsivenessFailure):
            oracle.assert_responsive(result)
    else:
        oracle.assert_responsive(result)
