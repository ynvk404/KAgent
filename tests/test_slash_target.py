"""
Tests for the /target slash-command fix in src/ui/commands/slash_handler.py.

Context / bug being guarded against:
    Before the fix, `/target <url>` updated `agent.target` synchronously
    but rebuilt the system prompt (`rebuild_system_prompt` +
    `ensure_system_prompt`) *inside* an `asyncio.create_task(...)`
    coroutine, alongside the disk-persist call (`agent.save()`). Because
    `create_task` only *schedules* the coroutine rather than running it
    to completion, `handle_slash()` could return — and the UI could show
    the "target set to ..." confirmation, and accept the next user
    message — before `agent.history[0]` (the system prompt actually sent
    to the LLM) had been updated. If the user's next message was
    processed before the event loop got around to running that task, the
    LLM would not yet see the new target in its context.

    The fix moves the synchronous, non-I/O part of the update
    (`target.set_base_url` / `target.clear`, `rebuild_system_prompt`,
    `ensure_system_prompt`) out of the async task and runs it inline in
    `handle_slash`, so `agent.history[0]` is guaranteed correct the
    moment `handle_slash` returns. Only `agent.save()` (real disk I/O)
    is left on a background task.

These tests intentionally assert *immediately* after calling
`handle_slash`, with no `await` / `sleep` in between, so they cannot
pass "by luck" the way manual testing could.

Place this file at: tests/test_slash_target.py (or wherever the
project's test suite lives) and run with:

    pytest tests/test_slash_target.py -v
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import pytest

# Real production code under test.
from src.ui.commands.slash_handler import handle_slash, normalize_target_url
from src.agent.agent import ensure_system_prompt
from src.target.target import Target
from src.llm.types import Message
from src.ui.core.state import TranscriptEntry

if TYPE_CHECKING:
    # Only imported for the type checker (Pylance/mypy), never at
    # runtime, so this doesn't drag in the full Textual App and its
    # dependencies just to run these tests.
    from src.ui.core.app import KAgent


# ---------------------------------------------------------------------------
# Minimal fakes.
#
# handle_slash's "/target" branch only ever touches:
#   agent.target            (a real Target instance)
#   agent.rebuild_system_prompt()
#   agent.history            (list[Message])
#   agent.sys_prompt          (str)
#   agent.save()              (async)
# so a lightweight duck-typed fake is enough to exercise the *real*
# slash_handler.py code path without constructing a full Agent (client,
# tool registry, skill registry, prompter, etc.).
# ---------------------------------------------------------------------------


@dataclass
class FakeAgent:
    target: Target = field(default_factory=Target)
    sys_prompt: str = "BASE SYSTEM PROMPT"
    history: list = field(default_factory=list)

    rebuild_calls: int = 0
    save_calls: int = 0
    save_should_fail: bool = False

    def __post_init__(self) -> None:
        if not self.history:
            self.history = [Message(role="system", content=self.sys_prompt)]

    def rebuild_system_prompt(self) -> None:
        """Mimics system_prompt.build_system_prompt's target-aware branch
        closely enough to test the wiring: when a target is set, the
        prompt must mention its base URL."""
        self.rebuild_calls += 1

        sb = "BASE SYSTEM PROMPT"
        if self.target and not self.target.empty():
            sb += f"\n# Active engagement\n- Target base URL: {self.target.base_url()}\n"

        self.sys_prompt = sb

    async def save(self) -> None:
        self.save_calls += 1
        if self.save_should_fail:
            raise RuntimeError("disk write failed (simulated)")


@dataclass
class FakeDispatchedEntry:
    kind: str
    text: str


class FakeApp:
    """Stands in for `KAgent`. Only `agent` and `dispatch` are used by
    handle_slash."""

    def __init__(self) -> None:
        self.agent = FakeAgent()
        self.dispatched: list[FakeDispatchedEntry] = []

    def dispatch(self, action) -> None:
        entry = getattr(action, "entry", None)
        if entry is not None:
            self.dispatched.append(FakeDispatchedEntry(kind=entry.kind, text=entry.text))

    # handle_slash also references app.dispatch and app.agent only for
    # the /target branch; other commands (not exercised here) touch more
    # attributes, so this fake intentionally stays minimal.


def as_kagent(app: FakeApp) -> "KAgent":
    """`FakeApp` intentionally duck-types the subset of `KAgent` that
    `handle_slash`'s "/target" branch touches (`.agent`, `.dispatch`).
    It does not — and should not — inherit from the real `KAgent`
    Textual App, since that would pull in the full UI stack just to
    test this one command branch. This cast tells the type checker
    that the substitution is intentional; it has no effect at runtime
    (Python itself never checks the annotation)."""
    return cast("KAgent", app)


def last_system_text(app: FakeApp) -> str | None:
    for e in reversed(app.dispatched):
        if e.kind == "system":
            return e.text
    return None


def last_error_text(app: FakeApp) -> str | None:
    for e in reversed(app.dispatched):
        if e.kind == "error":
            return e.text
    return None


# ---------------------------------------------------------------------------
# The critical regression test: no race, asserted synchronously.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_target_set_updates_history_synchronously_no_await():
    """This is the test that guards the original bug. It must pass
    without any `await`/`sleep` between `handle_slash` returning and the
    assertions — exactly mirroring the real scenario (user immediately
    sends the next message).

    Note: this test is `async def` purely so a running event loop
    exists for `handle_slash`'s internal `asyncio.create_task(...)`
    call to attach to — exactly as one is always present in the real
    app (Textual's own event loop). No `await` is used between calling
    `handle_slash` and asserting, so this still fully exercises the
    "no race" guarantee the fix provides.
    """
    app = FakeApp()

    handled = handle_slash(as_kagent(app), "/target juice.lab:3000")

    assert handled is True

    # The system prompt actually sent to the LLM on the *next* turn is
    # history[0]. It must already contain the new target the instant
    # handle_slash returns — not "eventually, once the event loop gets
    # around to it".
    assert "http://juice.lab:3000" in app.agent.history[0].content
    assert "Target base URL: http://juice.lab:3000" in app.agent.sys_prompt

    # rebuild_system_prompt must have actually run (not just scheduled).
    assert app.agent.rebuild_calls == 1

    # save() is legitimately async / best-effort — it's fine if it
    # hasn't run yet at this exact point, since it only affects
    # persistence across restarts, not what the next turn's LLM call
    # sees.
    assert app.agent.target.base_url() == "http://juice.lab:3000"


@pytest.mark.asyncio
async def test_target_clear_updates_history_synchronously_no_await():
    app = FakeApp()
    handle_slash(as_kagent(app), "/target juice.lab:3000")

    handled = handle_slash(as_kagent(app), "/target clear")

    assert handled is True
    assert app.agent.target.empty()
    assert "Target base URL" not in app.agent.history[0].content
    assert "Target base URL" not in app.agent.sys_prompt


# ---------------------------------------------------------------------------
# Background save behavior: still async, still eventually completes,
# and failures don't corrupt the already-applied in-memory state.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_target_set_save_eventually_completes():
    app = FakeApp()

    handle_slash(as_kagent(app), "/target juice.lab:3000")

    # Let any scheduled background tasks (the save) run to completion.
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    assert app.agent.save_calls == 1


@pytest.mark.asyncio
async def test_target_set_save_failure_keeps_in_memory_state_and_reports_error():
    app = FakeApp()
    app.agent.save_should_fail = True

    handle_slash(as_kagent(app), "/target juice.lab:3000")

    # In-memory state (what the LLM sees) must already be correct,
    # independent of whether the disk write succeeds.
    assert "http://juice.lab:3000" in app.agent.history[0].content

    await asyncio.sleep(0)
    await asyncio.sleep(0)

    err = last_error_text(app)
    assert err is not None
    assert "target save failed" in err
    # State should not have been rolled back because of the save error.
    assert app.agent.target.base_url() == "http://juice.lab:3000"


# ---------------------------------------------------------------------------
# Regression coverage for the other /target branches (must not have
# broken while fixing the race).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_target_no_args_shows_current_target():
    app = FakeApp()
    handle_slash(as_kagent(app), "/target juice.lab:3000")

    handled = handle_slash(as_kagent(app), "/target")

    assert handled is True
    text = last_system_text(app)
    assert text is not None
    assert "http://juice.lab:3000" in text


def test_target_no_args_when_unset():
    app = FakeApp()

    handled = handle_slash(as_kagent(app), "/target")

    assert handled is True
    text = last_system_text(app)
    assert text == "no target configured"


def test_target_invalid_url_shows_usage_and_does_not_change_state():
    app = FakeApp()

    handled = handle_slash(as_kagent(app), "/target not a valid url??")

    assert handled is True
    assert app.agent.target.empty()
    text = last_system_text(app)
    # only the usage error should be dispatched, not a "target set" message
    assert text is None or "usage:" not in (last_system_text(app) or "")
    err = last_error_text(app)
    assert err == "usage: /target <url|clear>"


@pytest.mark.asyncio
async def test_target_confirmation_message_matches_normalized_url():
    app = FakeApp()

    handle_slash(as_kagent(app), "/target juice.lab:3000")

    text = last_system_text(app)
    assert text == "target set to http://juice.lab:3000"


# ---------------------------------------------------------------------------
# Sanity check on normalize_target_url itself, since the whole feature
# depends on it accepting bare host:port input like "juice.lab:3000".
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("juice.lab:3000", "http://juice.lab:3000"),
        ("http://juice.lab:3000", "http://juice.lab:3000"),
        ("https://app.example.com", "https://app.example.com"),
        ("localhost:8080", "http://localhost:8080"),
        ("127.0.0.1", "http://127.0.0.1"),
    ],
)
def test_normalize_target_url_accepts_expected_forms(raw, expected):
    assert normalize_target_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "not a url",
        "http://",
        "http://onelabel",  # single label, no dot, not localhost/IP
    ],
)
def test_normalize_target_url_rejects_invalid_forms(raw):
    assert normalize_target_url(raw) is None