import json
import asyncio
import importlib
from typing import cast

import pytest

from src.agent.agent import Agent, AgentOptions
from src.cli.main import (
    BURP_DEFAULT_PORT,
    GROQ_AUTO_COMPACT_THRESHOLD,
    FlagParseError,
    apply_startup_target,
    close_runtime_resources,
    effective_auto_compact_threshold,
    parse_flags,
    print_help,
    redacted_argv,
    require_existing_resume_session,
)
from src.config.config import Config, DEFAULT_AUTO_COMPACT_THRESHOLD
from src.permission.permission import AlwaysAllow
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.registry import Registry as ToolRegistry
from tests.helpers.agent_fakes import FakeClient
from src.logger.session_debug import (
    SessionDebugOptions,
    create_session_debug_log,
)
from src.tools.mcp_integration import MCPSession
from src.llm.types import Message
from src.session.store import Store


cli_main = importlib.import_module("src.cli.main")


@pytest.mark.parametrize(
    "flag",
    [
        "--backend",
        "--model",
        "--base-url",
        "--target",
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


@pytest.mark.asyncio
async def test_explicit_missing_resume_exits_without_creating_session(
    tmp_path, monkeypatch, capsys
):
    session_id = "missing-session-id"
    monkeypatch.setattr(cli_main.session_store, "dir_from_path", lambda _path: tmp_path)
    monkeypatch.setattr(cli_main.sys, "argv", ["kagent", "--resume", session_id])

    assert await cli_main.main() != 0

    captured = capsys.readouterr()
    assert f"session not found: {session_id}" in captured.err
    assert "Resumed session" not in captured.out + captured.err
    assert not (tmp_path / f"{session_id}.json").exists()


@pytest.mark.asyncio
async def test_existing_explicit_resume_restores_saved_content(tmp_path, monkeypatch):
    session_id = "existing-session-id"
    store = Store.new_with_id(tmp_path, session_id)
    await store.save([Message(role="user", content="saved conversation")])
    monkeypatch.setattr(cli_main.session_store, "dir_from_path", lambda _path: tmp_path)

    restored_store = require_existing_resume_session(session_id)
    agent = Agent(AgentOptions(
        client=FakeClient([]),
        tools=ToolRegistry(),
        skills=SkillRegistry(),
        prompter=AlwaysAllow(),
        store=restored_store,
        target=Target(),
    ))
    agent.resume_saved()

    assert any(m.content == "saved conversation" for m in agent.get_history())


@pytest.mark.asyncio
async def test_new_session_still_uses_permissive_empty_load(tmp_path):
    assert parse_flags([]).resume_id == ""
    store = Store.new_with_id(tmp_path, "new-session-id")
    assert store.load().messages == []
    await store.save([Message(role="user", content="new conversation")])
    assert store.load().messages[0].content == "new conversation"


def test_target_flag_is_distinct_from_provider_base_url():
    flags = parse_flags([
        "--base-url", "https://api.example.test/v1",
        "--target", "juice.lab:3000",
    ])

    assert flags.base_url == "https://api.example.test/v1"
    assert flags.target_url == "http://juice.lab:3000"


@pytest.mark.parametrize("url", ["http://", "not-a-host", "http://[::1"])
def test_target_flag_rejects_invalid_urls(url):
    with pytest.raises(FlagParseError, match="--target requires a valid HTTP"):
        parse_flags(["--target", url])


def test_cli_target_replaces_previous_origin_and_scope_before_splash():
    agent = Agent(AgentOptions(
        client=FakeClient([]),
        tools=ToolRegistry(),
        skills=SkillRegistry(),
        prompter=AlwaysAllow(),
        store=None,
        target=Target("http://old.example"),
    ))
    agent.add_scope_origin("http://extra.example")

    apply_startup_target(agent, parse_flags(["--target", "juice.lab:3000"]).target_url)

    assert agent.target.base_url() == "http://juice.lab:3000"
    assert agent.engagement_state.is_in_scope("http://juice.lab:3000/path")
    assert not agent.engagement_state.is_in_scope("http://old.example")
    assert not agent.engagement_state.is_in_scope("http://extra.example")


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


def test_debug_argv_redacts_target_url():
    target_url = "https://user:secret@lab.example/test"
    assert redacted_argv(["--target", target_url]) == ["--target", "<redacted>"]
    assert redacted_argv([f"--target={target_url}"]) == ["--target=<redacted>"]


def test_help_uses_the_runtime_burp_default(capsys):
    print_help()

    output = capsys.readouterr().out
    assert f"--burp [port]              start local Burp/KAgent bridge (default :{BURP_DEFAULT_PORT})" in output
    assert "--target <url>" in output


@pytest.mark.parametrize(
    ("cfg", "expected"),
    [
        (Config(backend="groq"), GROQ_AUTO_COMPACT_THRESHOLD),
        (Config(backend="groq", auto_compact_threshold=4_000), 4_000),
        (Config(backend="groq", auto_compact_threshold=0), GROQ_AUTO_COMPACT_THRESHOLD),
        (Config(backend="openai-compat"), DEFAULT_AUTO_COMPACT_THRESHOLD),
        (Config(backend="kimi", model="moonshot-v1-8k"), 6_144),
        (Config(backend="kimi", model="moonshot-v1-32k"), 24_576),
        (Config(backend="kimi", model="kimi-k2.6"), 196_608),
        (Config(backend="kimi", model="unknown"), DEFAULT_AUTO_COMPACT_THRESHOLD),
        (
            Config(
                backend="kimi",
                model="moonshot-v1-8k",
                auto_compact_threshold=7_000,
            ),
            7_000,
        ),
    ],
)
def test_effective_auto_compact_threshold_selection(cfg, expected):
    assert effective_auto_compact_threshold(cfg) == expected


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


def test_parse_flags_handles_max_steps_option():
    flags = parse_flags(["--max-steps", "35"])
    assert flags.max_steps == 35

    with pytest.raises(FlagParseError, match="--max-steps requires a positive integer"):
        parse_flags(["--max-steps", "0"])

    with pytest.raises(FlagParseError, match="--max-steps requires a positive integer"):
        parse_flags(["--max-steps", "-5"])

    with pytest.raises(FlagParseError, match="--max-steps requires a positive integer"):
        parse_flags(["--max-steps", "abc"])
