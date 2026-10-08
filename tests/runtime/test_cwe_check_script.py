"""The merged CWE check keeps acceptance and startup modes independently runnable."""
from contextlib import asynccontextmanager
import json
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import check_cwe_mcp as script


def test_cli_routes_acceptance_and_startup_modes(monkeypatch, tmp_path):
    calls = []

    async def acceptance(deployment):
        calls.append(("acceptance", deployment))

    async def startup(deployment, count):
        calls.append(("startup", deployment, count))

    monkeypatch.setattr(script, "main", acceptance)
    monkeypatch.setattr(script, "check_startup", startup)
    base = ["--deployment", str(tmp_path)]
    script.cli(base)
    script.cli([*base, "--startup"])
    script.cli([*base, "--startup", "--rounds", "2"])
    assert calls == [("acceptance", tmp_path), ("startup", tmp_path, 5), ("startup", tmp_path, 2)]


@pytest.mark.parametrize("flags", [
    ["--rounds", "2"], ["--startup", "--rounds", "0"], ["--startup", "--rounds", "21"],
])
def test_cli_rejects_invalid_startup_options_before_execution(tmp_path, flags):
    with pytest.raises(SystemExit) as error:
        script.cli(["--deployment", str(tmp_path), *flags])
    assert error.value.code == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_under_load", [False, True])
async def test_startup_measures_both_modes_and_restores_initialize(monkeypatch, tmp_path, capsys, fail_under_load):
    modes = []
    load_events = []

    async def initialize(self, *args, **kwargs):
        return "initialized"

    async def rounds(deployment, count, mode, samples, load=None):
        modes.append((mode, count, load))
        if load is not None and fail_under_load:
            raise RuntimeError("load failure")
        for _ in range(count * 3):
            await script.ClientSession.initialize(cast(script.ClientSession, object()))

    @asynccontextmanager
    async def load(deployment):
        load_events.append("start")
        try:
            yield "tooling"
        finally:
            load_events.append("stop")

    monkeypatch.setattr(script.ClientSession, "initialize", initialize)
    monkeypatch.setattr(script, "startup_rounds", rounds)
    monkeypatch.setattr(script, "tooling_load", load)
    if fail_under_load:
        with pytest.raises(RuntimeError, match="load failure"):
            await script.check_startup(tmp_path, 2)
    else:
        await script.check_startup(tmp_path, 2)
        result = json.loads(capsys.readouterr().out)
        assert result["successful_fresh_processes"] == 12
        assert result["handshake_budget_seconds"] == script.integration.HANDSHAKE_TIMEOUT_S
    assert modes == [("sequential", 2, None), ("pyright-and-dependency-inspection", 2, "tooling")]
    assert load_events == ["start", "stop"]
    assert script.ClientSession.initialize is initialize


@pytest.mark.asyncio
async def test_startup_closes_session_after_rpc_failure(monkeypatch, tmp_path):
    closed = []

    class Session:
        async def close(self):
            closed.append(True)

    class Registry:
        async def execute(self, *args):
            raise RuntimeError("RPC failed")

    async def connect(root, deployment):
        return Registry(), None, None, None, Session(), {}

    monkeypatch.setattr(script, "connect", connect)
    monkeypatch.setattr(script, "TrustedSource", lambda *args: SimpleNamespace())
    with pytest.raises(RuntimeError, match="RPC failed"):
        await script.startup_rounds(tmp_path, 1, "sequential", [])
    assert closed == [True]
