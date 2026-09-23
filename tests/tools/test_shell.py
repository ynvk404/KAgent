# Shell denylist + execution tests.

from __future__ import annotations

import sys

import pytest

from src.permission.permission import AlwaysAllow
from src.tools.shell import (
    BashTool,
    DENY_PATTERNS,
    ShellTool,
    rewrite_portable_command,
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
async def test_rejects_blocked_command_before_spawn():
    t = ShellTool()
    with pytest.raises(Exception, match="blocked by denylist"):
        await t.run({"command": "rm -rf /"}, None, AlwaysAllow())


def test_rewrites_common_grep_p_forms_to_portable_perl():
    # The pattern travels through the PF_GREP_PAT env var, never inlined into
    # the Perl source, so a malicious pattern can't become a code-exec primitive.
    assert rewrite_portable_command("printf 'abc' | grep -P 'a'") == (
        "printf 'abc' | PF_GREP_PAT='a' perl -ne "
        "'BEGIN { $p = $ENV{PF_GREP_PAT} } print if /$p/'"
    )
    assert rewrite_portable_command("printf 'abc' | grep -oP 'a.'") == (
        "printf 'abc' | PF_GREP_PAT='a.' perl -ne "
        "'BEGIN { $p = $ENV{PF_GREP_PAT} } while (/$p/g) { print \"$&\\n\" }'"
    )
    assert rewrite_portable_command("printf 'ABC' | grep -iP 'a'") == (
        "printf 'ABC' | PF_GREP_PAT='a' perl -ne "
        "'BEGIN { $p = $ENV{PF_GREP_PAT} } print if /$p/i'"
    )
    assert rewrite_portable_command("printf 'abc' | grep --perl-regexp 'a'") == (
        "printf 'abc' | PF_GREP_PAT='a' perl -ne "
        "'BEGIN { $p = $ENV{PF_GREP_PAT} } print if /$p/'"
    )


@pytest.mark.asyncio
async def test_treats_grep_p_pattern_as_inert_data_not_perl_exec_primitive():
    # The classic payload runs `id` when inlined into a /.../ literal; as data
    # it must match nothing and never execute.
    rewritten = rewrite_portable_command("grep -P '@{[ `id` ]}' /dev/null")
    assert "`id`/" not in rewritten
    assert "PF_GREP_PAT=" in rewritten

    out = await ShellTool().run(
        {
            "command": "printf 'x\\n' | grep -P '@{[ `echo PWNED` ]}'",
            "timeout_seconds": 5,
        },
        None,
        AlwaysAllow(),
    )
    assert "PWNED" not in out


def test_does_not_rewrite_grep_p_inside_string_or_with_trailing_flags():
    # L2: literal `grep -P` inside a quoted string is not at a command position.
    assert (
        rewrite_portable_command('echo "look at grep -P xyz"')
        == 'echo "look at grep -P xyz"'
    )
    # L1: trailing context/format flags have no faithful perl translation, so
    # we leave the original in place (the portability guard then surfaces a
    # message).
    assert (
        rewrite_portable_command("grep -P 'a' -A3 file")
        == "grep -P 'a' -A3 file"
    )


@pytest.mark.asyncio
async def test_executes_rewritten_grep_p_commands_instead_of_blocking():
    t = ShellTool()
    out = await t.run(
        {"command": "printf 'abc\\nxyz\\n' | grep -oP 'a.'", "timeout_seconds": 5},
        None,
        AlwaysAllow(),
    )
    assert "ab" in out
    assert "exit: 0" in out


@pytest.mark.asyncio
async def test_blocks_known_gnu_only_commands_with_guidance():
    t = ShellTool()
    cases = [
        ("printf 'abc' | grep -Pr 'a'", "grep -P"),
        ("printf 'abc' | sed -r 's/a/A/'", "sed -r"),
        ("printf 'abc' | base64 -w0", "base64 -w"),
        ("readlink -f ./package.json", "readlink -f"),
        ("date -d tomorrow", "date -d"),
        ("printf '' | xargs -r echo", "xargs -r"),
        ("stat -c %s package.json", "stat -c"),
        ("printf '1.2\\n1.10\\n' | sort -V", "sort -V"),
        ("timeout 2 curl -s https://example.com", "timeout"),
    ]

    for command, message in cases:
        with pytest.raises(Exception, match=message):
            await t.run({"command": command}, None, AlwaysAllow())


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


def test_does_not_opt_out_of_allow_session_caching():
    t = ShellTool()
    hints = t.permission_hints({"command": "id"})
    assert hints.get("noSessionCache") is not True
    assert hints["sessionScopeDisplay"] == "this exact shell command only"


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


def test_skips_unix_grep_p_to_perl_rewrite_on_windows(monkeypatch):
    cmd = "type x | grep -P 'a'"
    assert with_platform(monkeypatch, "win32", lambda: rewrite_portable_command(cmd)) == cmd
    # Sanity: on POSIX the same input *is* rewritten, proving the guard matters.
    assert "perl -ne" in with_platform(
        monkeypatch, "linux", lambda: rewrite_portable_command(cmd)
    )


def test_surfaces_powershell_appropriate_guidance_on_windows(monkeypatch):
    desc = with_platform(monkeypatch, "win32", lambda: ShellTool().description())
    assert "PowerShell" in desc
    assert "/bin/sh" not in desc

    schema = with_platform(monkeypatch, "win32", lambda: ShellTool().schema())
    assert "PowerShell" in schema["properties"]["command"]["description"]
