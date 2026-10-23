# Shell denylist + execution tests.

from __future__ import annotations

import sys
import asyncio
import os
import shutil
import subprocess
from unittest.mock import AsyncMock

import pytest

from src.permission.permission import AlwaysAllow
from src.tools.execution.shell import (
    BashTool,
    DENY_PATTERNS,
    ShellTool,
    run_with_capture,
    shell_invocation,
)


# ==========================================================
# Helpers
# ==========================================================


def with_platform(monkeypatch: pytest.MonkeyPatch, platform: str, fn):
    """
    Run `fn` with sys.platform forced to `platform`. is_windows() reads
    sys.platform at call time, so this exercises the Windows code paths
    from a macOS/Linux CI host without spawning anything.
    """
    monkeypatch.setattr(sys, "platform", platform)
    return fn()


# ==========================================================
# Shell denylist
# ==========================================================


DENYLIST_CASES = [
    ("rm -rf /", "rm -rf /", True),
    ("rm -fr / (flag order)", "rm -fr /", True),
    ("rm --recursive --force /", "rm --recursive --force /", True),
    ("rm -rf /*", "rm -rf /*", True),
    ("rm -rf /home (top-level)", "rm -rf /home", True),
    ('rm -rf "/etc" (quoted top-level)', 'rm -rf "/etc"', True),
    ("rm -rf /home/user (no trailing root)", "rm -rf /home/user", False),
    ("rm -rf ./build (relative)", "rm -rf ./build", False),
    ("find / -delete", "find / -delete", True),
    ("find . -exec rm", "find . -name x -exec rm {} ;", True),
    ("poweroff", "poweroff", True),
    ("fork bomb", ":(){ :|:& };:", True),
    ("mkfs", "mkfs.ext4 /dev/sda1", True),
    ("dd to /dev disk", "dd if=/dev/zero of=/dev/sda", True),
    ("redirect to /dev/sda", "cat file > /dev/sda", True),
    ("shutdown", "shutdown -h now", True),
    ("reboot", "reboot", True),
    ("normal curl", "curl -s https://example.com", False),
    ("normal ls", "ls -la /tmp", False),
    ("jq pipeline", "curl -s url | jq .", False),
]


@pytest.mark.parametrize("name,cmd,should_block", DENYLIST_CASES)
def test_shell_denylist(name, cmd, should_block):
    blocked = any(pattern.search(cmd) for pattern in DENY_PATTERNS)
    assert blocked == should_block


# ==========================================================
# ShellTool.run
# ==========================================================


def test_describes_portable_grep_usage_and_avoids_grep_p_guidance():
    desc = ShellTool().description()
    assert "grep -P" in desc
    assert "grep -E" in desc
    assert "macOS/BSD" in desc
    assert "built-in http tool" in desc
    assert "Direct subprocess" in desc
    assert "no OS sandbox or HTTP attestation" in desc


@pytest.mark.asyncio
async def test_executes_benign_command_and_returns_stdout():
    t = ShellTool()
    out = await t.run(
        {"command": "echo hello && echo world"},
        None,
        AlwaysAllow(),
    )
    assert "exit: 0" in out
    assert "hello" in out
    assert "world" in out


@pytest.mark.asyncio
async def test_rejects_blocked_command_before_spawn(monkeypatch):
    spawn = AsyncMock(side_effect=AssertionError("denylist must prevent spawn"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    t = ShellTool()
    with pytest.raises(Exception, match="blocked by denylist"):
        await t.run({"command": "rm -rf /"}, None, AlwaysAllow())
    spawn.assert_not_called()


# Compare with the same native shell, without another command transformer or
# output parser. Each subprocess runs offline in pytest's temporary directory.
PCRE_COMMANDS = [
    pytest.param(
        "printf '%s\\n' '---TITLE---'\npat=abc\n"
        'printf \'%s\\n\' abc | grep -P "$pat" | grep -q abc',
        0, id="audit-reproduction",
    ),
    pytest.param("printf 'abc\\nxyz\\n' | grep -P 'a'", 0, id="match"),
    pytest.param("printf 'abc\\n' | grep -P 'missing'", 1, id="no-match"),
    pytest.param("grep -Pr 'a' /dev/null", 1, id="recursive-flag"),
    pytest.param("printf 'abc\\n' | grep -oP 'a.'", 0, id="extract"),
    pytest.param("printf 'ABC\\n' | grep -iP 'a'", 0, id="ignore-case"),
    pytest.param("printf 'abc\\n' | grep --perl-regexp 'a'", 0, id="long-flag"),
    pytest.param("printf 'abc\\nxyz\\n' | grep -voP 'a'", 0, id="inverse-extract"),
    pytest.param("printf 'abc\\nxyz\\n' | grep -P 'a' -A1", 0, id="trailing-flags"),
    pytest.param("printf 'abc\\n' | grep -P '['", 2, id="malformed-regex"),
    pytest.param(
        'pat=$(printf abc)\nprintf \'%s\\n\' abc | grep -P $pat',
        0, id="unquoted-expansion",
    ),
    pytest.param(
        "pat=abc; printf 'abc\\n' > input.txt\n"
        'grep -P "$pat" < input.txt > output.txt; code=$?; cat output.txt; exit "$code"',
        0, id="redirections",
    ),
    pytest.param(
        "printf 'abc\\n' | grep -P '[' 2> error.txt; code=$?; cat error.txt >&2; exit \"$code\"",
        2, id="stderr-redirection",
    ),
    pytest.param(
        "printf 'abc\\n' | grep -P 'missing' | cat",
        0, id="pipeline-masks-no-match",
    ),
    pytest.param(
        "printf 'x\\n' | grep -P '@{[ `echo PWNED` ]}'",
        1, id="quoted-pattern-stays-inert",
    ),
]

SHELL_TEXT_COMMANDS = [
    pytest.param('printf \'%s\\n\' "| grep -P \'a\'"', id="quoted-pipeline"),
    pytest.param(
        "printf '%s\\n' before # | grep -P '$pat'\nprintf '%s\\n' after",
        id="comment",
    ),
    pytest.param(
        "cat <<'DATA'\n| grep -P '$pat'\nsed -r 's/a/A/'\nDATA",
        id="quoted-heredoc",
    ),
    pytest.param(
        'pat=abc\ncat <<DATA\n| grep -P "$pat"\n$pat\n$(printf expanded)\nDATA',
        id="expanded-heredoc",
    ),
    pytest.param(
        'cat <<DATA > output.txt\n| grep -P \'abc\'\nDATA\ncat < output.txt',
        id="heredoc-redirection",
    ),
    pytest.param(
        "printf '%s\\n' 'grep -P sed -r base64 -w0 readlink -f date -d xargs -r stat -c sort -V timeout 2'",
        id="gnu-flags-as-data",
    ),
    pytest.param(
        "# sed -r; base64 -w0; readlink -f .; date -d tomorrow; xargs -r; stat -c; sort -V; timeout 2\ntrue",
        id="gnu-flags-in-comment",
    ),
    pytest.param("printf 'abc\\n' | sed -r 's/a/A/'", id="native-sed"),
    pytest.param("printf 'abc' | base64 -w0", id="native-base64"),
    pytest.param("readlink -f .", id="native-readlink"),
    pytest.param("date -d '2000-01-02 UTC' +%F", id="native-date"),
    pytest.param("printf '' | xargs -r echo", id="native-xargs"),
    pytest.param("stat -c %s /dev/null", id="native-stat"),
    pytest.param("printf '1.2\\n1.10\\n' | sort -V", id="native-sort"),
    pytest.param("timeout 2 printf bounded", id="native-timeout"),
    pytest.param("kagent_f1_nonexistent_command", id="missing-utility"),
]


@pytest.fixture(params=[ShellTool, BashTool], ids=["sh", "bash"])
def native_shell_tool(request, monkeypatch, tmp_path):
    if os.name != "posix":
        pytest.skip("Native POSIX shell comparison")
    tool = request.param()
    if not os.path.isfile(tool.shell_path):
        pytest.skip(f"Native shell unavailable: {tool.shell_path}")
    monkeypatch.chdir(tmp_path)
    return tool


@pytest.fixture
def native_grep_p():
    if shutil.which("grep") is None:
        pytest.skip("Native grep unavailable")
    probe = subprocess.run(
        ["grep", "-P", "a"], input=b"abc\n", capture_output=True, timeout=5,
    )
    if probe.returncode != 0:
        pytest.skip("Native grep lacks PCRE support")


async def assert_native_shell_result(tool, command, expected_exit=None):
    direct = subprocess.run(
        [tool.shell_path, "-c", command], capture_output=True, timeout=5,
    )
    if expected_exit is not None:
        assert direct.returncode == expected_exit
    out = await tool.run({"command": command, "timeout_seconds": 5}, None, AlwaysAllow())
    expected = f"exit: {direct.returncode}\nstdout:\n{direct.stdout.decode('utf-8', errors='replace')}"
    if direct.stderr:
        expected += f"\nstderr:\n{direct.stderr.decode('utf-8', errors='replace')}"
    assert str(out) == expected
    assert out.status == ("success" if direct.returncode == 0 else "error")
    assert out.error_kind == (None if direct.returncode == 0 else "tool_exception")
    assert not out.truncated


@pytest.mark.asyncio
@pytest.mark.parametrize("command,expected_exit", PCRE_COMMANDS)
async def test_native_grep_semantics(native_shell_tool, native_grep_p, command, expected_exit):
    await assert_native_shell_result(native_shell_tool, command, expected_exit)


@pytest.mark.asyncio
@pytest.mark.parametrize("command", SHELL_TEXT_COMMANDS)
async def test_shell_text_and_native_utilities_are_not_portability_blocked(native_shell_tool, command):
    await assert_native_shell_result(native_shell_tool, command)


@pytest.mark.asyncio
async def test_unavailable_executor_raises_before_command_execution(monkeypatch):
    spawn = AsyncMock(side_effect=FileNotFoundError("fixture executor unavailable"))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    with pytest.raises(FileNotFoundError, match="executor unavailable"):
        await ShellTool(shell="/unavailable-shell").run(
            {"command": "exit 1"}, None, AlwaysAllow(),
        )
    spawn.assert_awaited_once()


@pytest.mark.asyncio
async def test_allows_portable_grep_and_sed_alternatives():
    t = ShellTool()
    out = await t.run(
        {"command": "printf 'abc\\n' | grep -E 'a.c' | sed -E 's/a/A/'"},
        None,
        AlwaysAllow(),
    )
    assert "Abc" in out


@pytest.mark.asyncio
async def test_errors_when_command_is_missing():
    t = ShellTool()
    with pytest.raises(Exception, match="command is required"):
        await t.run({}, None, AlwaysAllow())


@pytest.mark.asyncio
async def test_captures_stderr_alongside_stdout():
    t = ShellTool()
    out = await t.run(
        {"command": "echo stdout-line; echo stderr-line >&2; exit 3"},
        None,
        AlwaysAllow(),
    )
    assert "stdout-line" in out
    assert "stderr-line" in out
    assert "exit: 3" in out
    assert out.status == "error"
    assert out.error_kind == "tool_exception"


@pytest.mark.asyncio
async def test_parser_failure_on_stderr_is_error_even_when_final_exit_is_zero():
    out = await ShellTool().run(
        {
            "command": (
                "echo 'awk: line 1: syntax error at or near }' >&2; true"
            )
        },
        None,
        AlwaysAllow(),
    )

    assert "exit: 0" in out
    assert out.status == "error"
    assert out.error_kind == "tool_exception"


@pytest.mark.asyncio
async def test_reports_tool_timeouts_instead_of_surfacing_abort_error():
    t = ShellTool()
    out = await t.run(
        {"command": "sleep 2", "timeout_seconds": 1},
        None,
        AlwaysAllow(),
    )
    assert "timeout after 1s" in out
    assert out.status == "error"
    assert out.error_kind == "timeout"
    assert "AbortError" not in out


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
@pytest.mark.asyncio
async def test_timeout_kills_process_that_ignores_term_without_internal_error():
    out = await ShellTool().run(
        {
            "command": "trap '' TERM; while :; do sleep 1; done",
            "timeout_seconds": 1,
        },
        None,
        AlwaysAllow(),
    )

    assert out.status == "error"
    assert out.error_kind == "timeout"
    assert "timeout after 1s" in out
    assert "AttributeError" not in out


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
@pytest.mark.asyncio
async def test_cancelled_shell_wait_escalates_and_reaps_term_resistant_process():
    class AbortSignal:
        aborted = False

    abort_signal = AbortSignal()
    task = asyncio.create_task(
        run_with_capture(
            "/bin/sh",
            ["-c", "trap '' TERM; while :; do sleep 1; done"],
            30,
            abort_signal,
        )
    )
    await asyncio.sleep(0.1)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
@pytest.mark.asyncio
async def test_user_abort_terminates_process_that_handles_term():
    class AbortSignal:
        aborted = False

    abort_signal = AbortSignal()

    async def abort_soon():
        await asyncio.sleep(0.1)
        abort_signal.aborted = True

    abort_task = asyncio.create_task(abort_soon())
    out = await run_with_capture(
        "/bin/sh",
        ["-c", "trap 'exit 0' TERM; sleep 30"],
        30,
        abort_signal,
    )
    await abort_task

    assert out.status == "cancelled"
    assert out.error_kind == "cancelled"


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups required")
@pytest.mark.asyncio
async def test_user_abort_kills_process_that_ignores_term():
    class AbortSignal:
        aborted = False

    abort_signal = AbortSignal()

    async def abort_soon():
        await asyncio.sleep(0.1)
        abort_signal.aborted = True

    abort_task = asyncio.create_task(abort_soon())
    out = await run_with_capture(
        "/bin/sh",
        ["-c", "trap '' TERM; while :; do sleep 1; done"],
        30,
        abort_signal,
    )
    await abort_task

    assert out.status == "cancelled"
    assert out.error_kind == "cancelled"
    assert "AttributeError" not in out


# ==========================================================
# ShellTool output cap
# ==========================================================


@pytest.mark.asyncio
async def test_bounds_retained_output_to_max_output_bytes_for_huge_streams():
    t = ShellTool()
    # Emit ~1MB; the model should only ever see the 64KB head+tail budget plus
    # the truncation marker, and the process must not buffer the whole thing.
    out = await t.run(
        {"command": 'head -c 1000000 /dev/zero | tr "\\0" "a"'},
        None,
        AlwaysAllow(),
    )
    assert "truncated" in out
    # 64KB retained + small framing/marker; nowhere near the 1MB emitted.
    assert len(out) < 80 * 1024


@pytest.mark.asyncio
async def test_retains_tail_of_large_stream_where_scanner_verdicts_live():
    t = ShellTool()
    # A unique head marker, a large middle that gets elided, and a unique tail
    # marker. The old head-only cap discarded the tail; both must now survive.
    out = await t.run(
        {
            "command": (
                "printf 'HEAD_MARKER'; "
                "head -c 200000 /dev/zero | tr '\\0' 'a'; "
                "printf 'TAIL_VERDICT'"
            )
        },
        None,
        AlwaysAllow(),
    )
    assert "HEAD_MARKER" in out
    assert "TAIL_VERDICT" in out
    assert "truncated" in out


def test_arbitrary_shell_execution_cannot_be_session_trusted_or_yolo_approved():
    t = ShellTool()
    hints = t.permission_hints({"command": "id"})
    assert hints.get("noSessionCache") is True
    assert hints.get("riskTier") == "high-impact"
    assert hints.get("sessionScopeDisplay") == "this exact shell command only"


# ==========================================================
# BashTool
# ==========================================================


@pytest.mark.asyncio
async def test_runs_bash_only_constructs():
    t = BashTool()
    out = await t.run(
        {"command": "[[ -d /tmp ]] && echo bash-ok"},
        None,
        AlwaysAllow(),
    )
    assert "bash-ok" in out


# ==========================================================
# Windows shell invocation (issue #11)
# ==========================================================


@pytest.fixture(autouse=False)
def clean_windows_shell_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("PFLOW_WINDOWS_SHELL", raising=False)
    yield


def test_spawns_bin_sh_c_on_posix(monkeypatch):
    inv = with_platform(
        monkeypatch, "linux", lambda: shell_invocation("/bin/sh", "echo hi")
    )
    assert inv == ("/bin/sh", ["-c", "echo hi"])


def test_spawns_powershell_command_on_windows_instead_of_bin_sh(
    monkeypatch, clean_windows_shell_env
):
    inv = with_platform(
        monkeypatch, "win32", lambda: shell_invocation("/bin/sh", "echo hi")
    )
    cmd, argv = inv
    assert cmd == "powershell.exe"
    assert argv == ["-NoProfile", "-NonInteractive", "-Command", "echo hi"]
    # The /bin/sh path that triggered ENOENT-style spawn failures must not be
    # the target.
    assert cmd != "/bin/sh"
    assert "-c" not in argv


def test_routes_bashtool_through_powershell_on_windows_too(
    monkeypatch, clean_windows_shell_env
):
    inv = with_platform(
        monkeypatch, "win32", lambda: shell_invocation("/bin/bash", "Get-ChildItem")
    )
    cmd, _argv = inv
    assert cmd == "powershell.exe"
    assert cmd != "/bin/bash"


def test_honors_pflow_windows_shell_override_on_windows(
    monkeypatch, clean_windows_shell_env
):
    monkeypatch.setenv("PFLOW_WINDOWS_SHELL", "pwsh.exe")
    inv = with_platform(
        monkeypatch, "win32", lambda: shell_invocation("/bin/sh", "echo hi")
    )
    cmd, _argv = inv
    assert cmd == "pwsh.exe"


def test_surfaces_powershell_appropriate_guidance_on_windows(monkeypatch):
    desc = with_platform(monkeypatch, "win32", lambda: ShellTool().description())
    assert "PowerShell" in desc
    assert "/bin/sh" not in desc

    schema = with_platform(monkeypatch, "win32", lambda: ShellTool().schema())
    assert "PowerShell" in schema["properties"]["command"]["description"]
