import pytest
from unittest.mock import AsyncMock, patch

from src.permission.permission import Decision
from src.target.target import Target
from src.tools.private_host import (
    gate_private_request,
    parse_http_url,
    same_authorized_origin,
)


class FakePrompter:

    def __init__(
        self,
        result=Decision.ALLOW_ONCE,
    ):
        self.ask = AsyncMock(
            return_value=result
        )


# ---------------------------------------------------------------------------
# same_authorized_origin — unit tests on the matcher itself
# ---------------------------------------------------------------------------

def test_same_authorized_origin_matches_scheme_host_port():
    target = Target("http://juice.lab:3000")
    parsed = parse_http_url("http://juice.lab:3000/api")

    assert same_authorized_origin(parsed, target) is True


def test_same_authorized_origin_is_case_and_trailing_dot_insensitive():
    target = Target("http://Juice.Lab:3000")
    parsed = parse_http_url("http://juice.lab.:3000/api")

    assert same_authorized_origin(parsed, target) is True


def test_same_authorized_origin_uses_default_ports():
    target = Target("https://juice.lab")
    parsed = parse_http_url("https://juice.lab:443/api")

    assert same_authorized_origin(parsed, target) is True


def test_same_authorized_origin_rejects_different_port():
    target = Target("http://juice.lab:3000")
    parsed = parse_http_url("http://juice.lab:8080/api")

    assert same_authorized_origin(parsed, target) is False


def test_same_authorized_origin_rejects_different_scheme():
    target = Target("http://juice.lab:3000")
    parsed = parse_http_url("https://juice.lab:3000/api")

    assert same_authorized_origin(parsed, target) is False


def test_same_authorized_origin_rejects_different_host():
    target = Target("http://juice.lab:3000")
    parsed = parse_http_url("http://127.0.0.1:3000/api")

    assert same_authorized_origin(parsed, target) is False


def test_same_authorized_origin_false_when_target_empty():
    target = Target()
    parsed = parse_http_url("http://juice.lab:3000/api")

    assert same_authorized_origin(parsed, target) is False


def test_same_authorized_origin_false_when_target_is_none():
    parsed = parse_http_url("http://juice.lab:3000/api")

    assert same_authorized_origin(parsed, None) is False


# ---------------------------------------------------------------------------
# gate_private_request — session-cache policy
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_declared_private_target_is_session_cacheable():
    target = Target("http://juice.lab:3000")
    prompter = FakePrompter(Decision.ALLOW_SESSION)

    parsed = parse_http_url("http://juice.lab:3000/")

    with patch(
        "src.tools.private_host.private_host_reason",
        new=AsyncMock(
            return_value="DNS resolves to loopback IPv4 (127.0.0.1)"
        ),
    ):
        reason = await gate_private_request(
            prompter,
            parsed,
            None,
            "http",
            target=target,
        )

    assert reason
    prompter.ask.assert_called_once()

    assert prompter.ask.call_args is not None
    request = prompter.ask.call_args.args[0]

    assert request.no_session_cache is False
    assert request.cache_key == (
        "private-declared://http://juice.lab:3000"
    )


@pytest.mark.asyncio
async def test_other_private_host_is_not_session_cacheable():
    target = Target("http://juice.lab:3000")
    prompter = FakePrompter(Decision.ALLOW_SESSION)

    parsed = parse_http_url("http://127.0.0.1:8080/")

    with patch(
        "src.tools.private_host.private_host_reason",
        new=AsyncMock(return_value="loopback IPv4"),
    ):
        await gate_private_request(
            prompter,
            parsed,
            None,
            "http",
            target=target,
        )

    assert prompter.ask.call_args is not None
    request = prompter.ask.call_args.args[0]

    assert request.no_session_cache is True
    assert request.cache_key is None


@pytest.mark.asyncio
async def test_declared_target_requires_same_port():
    target = Target("http://juice.lab:3000")
    prompter = FakePrompter(Decision.ALLOW_SESSION)

    parsed = parse_http_url("http://juice.lab:8080/")

    with patch(
        "src.tools.private_host.private_host_reason",
        new=AsyncMock(return_value="loopback IPv4"),
    ):
        await gate_private_request(
            prompter,
            parsed,
            None,
            "http",
            target=target,
        )

    assert prompter.ask.call_args is not None
    request = prompter.ask.call_args.args[0]

    assert request.no_session_cache is True
    assert request.cache_key is None


@pytest.mark.asyncio
async def test_declared_target_requires_same_scheme():
    target = Target("http://juice.lab:3000")
    prompter = FakePrompter(Decision.ALLOW_SESSION)

    parsed = parse_http_url("https://juice.lab:3000/")

    with patch(
        "src.tools.private_host.private_host_reason",
        new=AsyncMock(return_value="loopback IPv4"),
    ):
        await gate_private_request(
            prompter,
            parsed,
            None,
            "http",
            target=target,
        )

    assert prompter.ask.call_args is not None
    request = prompter.ask.call_args.args[0]

    assert request.no_session_cache is True
    assert request.cache_key is None


@pytest.mark.asyncio
async def test_gate_returns_empty_reason_and_skips_prompt_for_public_host():
    target = Target("http://juice.lab:3000")
    prompter = FakePrompter(Decision.ALLOW_SESSION)

    parsed = parse_http_url("http://example.com/")

    with patch(
        "src.tools.private_host.private_host_reason",
        new=AsyncMock(return_value=""),
    ):
        reason = await gate_private_request(
            prompter,
            parsed,
            None,
            "http",
            target=target,
        )

    assert reason == ""
    prompter.ask.assert_not_called()


@pytest.mark.asyncio
async def test_gate_deny_raises_even_for_declared_target():
    target = Target("http://juice.lab:3000")
    prompter = FakePrompter(Decision.DENY)

    parsed = parse_http_url("http://juice.lab:3000/")

    with patch(
        "src.tools.private_host.private_host_reason",
        new=AsyncMock(return_value="loopback IPv4"),
    ):
        with pytest.raises(Exception, match="denied"):
            await gate_private_request(
                prompter,
                parsed,
                None,
                "http",
                target=target,
            )