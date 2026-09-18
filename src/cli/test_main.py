import json
import asyncio
from typing import cast

import pytest

from src.cli.main import (
    BURP_DEFAULT_PORT,
    FlagParseError,
    close_runtime_resources,
    parse_flags,
    print_help,
    redacted_argv,
)
from src.logger.session_debug import (
    SessionDebugOptions,
    create_session_debug_log,
)
from src.tools.mcp_integration import MCPSession


@pytest.mark.parametrize(
    "flag",
    [
        "--backend",
        "--model",
        "--base-url",
        "--api-key",
        "--skills",
        "--resume",
        "--log",
        "--debug-session-path",
    ],
)
def test_value_flags_reject_missing_values(flag):
    with pytest.raises(FlagParseError, match="requires a value"):
        parse_flags([flag])


def test_parse_flags_rejects_unknown_options_and_invalid_burp_ports():
    with pytest.raises(FlagParseError, match="unknown option"):
        parse_flags(["--backned", "deepseek"])

    with pytest.raises(FlagParseError, match="port must be an integer"):
        parse_flags(["--burp", "not-a-port"])

    with pytest.raises(FlagParseError, match="between 1 and 65535"):
        parse_flags(["--burp", "65536"])

    with pytest.raises(FlagParseError, match="invalid session id"):
        parse_flags(["--resume", "../other-session"])

    secret = "cli-secret-that-must-not-appear-in-errors"
    with pytest.raises(FlagParseError) as exc_info:
        parse_flags([f"--api-key={secret}"])
    assert secret not in str(exc_info.value)


def test_parse_flags_keeps_burp_optional_port_and_alias_behavior():
    default = parse_flags(["--burp", "--backend", "deepseek"])
    custom = parse_flags(["--browser-ingest", "9012"])

    assert default.burp is True
    assert default.burp_port == BURP_DEFAULT_PORT
    assert default.backend == "deepseek"
    assert custom.burp is True
    assert custom.burp_port == 9012


def test_debug_argv_redacts_api_key_before_session_logging(tmp_path):
    secret = "cli-secret-that-must-not-be-written"
    path = tmp_path / "debug.jsonl"
    log = create_session_debug_log(
        SessionDebugOptions(enabled=True, session_id="session", path=str(path))
    )

    log.write("session_start", {"argv": redacted_argv(["--api-key", secret])})

    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["argv"] == ["--api-key", "<redacted>"]
    assert secret not in path.read_text(encoding="utf-8")


def test_help_uses_the_runtime_burp_default(capsys):
    print_help()

    assert f"--burp [port]              start local Burp/KAgent bridge (default :{BURP_DEFAULT_PORT})" in capsys.readouterr().out


def test_normal_shutdown_closes_runtime_resources():
    calls = []

    class Observer:
        def stop(self):
            calls.append("stop")

        def join(self, timeout):
            calls.append(("join", timeout))

    class Session:
        async def close(self):
            calls.append("session")

    async def close_bridge():
        calls.append("bridge")

    root_ctl = asyncio.Event()
    asyncio.run(
        close_runtime_resources(
            root_ctl,
            None,
            [Observer()],
            cast(list[MCPSession], [Session()]),
            close_bridge,
        )
    )

    assert root_ctl.is_set()
    assert calls == ["stop", ("join", 1), "session", "bridge"]
