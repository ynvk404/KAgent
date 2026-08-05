# Glob + grep behavior tests.

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from src.tools.search import GlobTool, GrepTool
from src.permission.permission import AlwaysAllow, AlwaysDeny


# ==========================================================
# Fixtures
# ==========================================================


@pytest.fixture
def search_tmp():
    tmp = Path(
        tempfile.mkdtemp(
            prefix="pf-search-"
        )
    )

    (tmp / "internal" / "tools").mkdir(
        parents=True,
        exist_ok=True,
    )

    (tmp / "main.go").write_text(
        "package main\nfunc main() {}\n"
    )

    (tmp / "README.md").write_text(
        "# x"
    )

    (tmp / "internal" / "tools" / "shell.go").write_text(
        'package tools\nvar denied = "rm -rf /"\n'
    )

    yield tmp

    shutil.rmtree(
        tmp,
        ignore_errors=True,
    )


@pytest.fixture
def signal():
    # Python equivalent of AbortController.signal
    return None


# ==========================================================
# GlobTool
# ==========================================================


@pytest.mark.asyncio
async def test_glob_returns_matching_files(search_tmp, signal):
    out = await GlobTool().run(
        {
            "pattern": "**/*.go",
            "path": str(search_tmp),
        },
        signal,
        AlwaysAllow(),
    )

    assert "main.go" in out
    assert str(Path("internal") / "tools" / "shell.go") in out


@pytest.mark.asyncio
async def test_glob_returns_no_matches(search_tmp, signal):
    out = await GlobTool().run(
        {
            "pattern": "**/*.rust",
            "path": str(search_tmp),
        },
        signal,
        AlwaysAllow(),
    )

    assert out == "no matches"


@pytest.mark.asyncio
async def test_glob_errors_when_pattern_missing(search_tmp, signal):
    with pytest.raises(Exception, match="required"):
        await GlobTool().run(
            {
                "path": str(search_tmp),
            },
            signal,
            AlwaysAllow(),
        )


@pytest.mark.asyncio
async def test_glob_prompts_sensitive_path(signal):
    home = Path.home()

    with pytest.raises(
        Exception,
        match="search of sensitive path denied",
    ):
        await GlobTool().run(
            {
                "pattern": "*",
                "path": str(home / ".ssh"),
            },
            signal,
            AlwaysDeny(),
        )


# ==========================================================
# GrepTool
# ==========================================================


@pytest.mark.asyncio
async def test_grep_finds_regex_match_line(search_tmp, signal):
    out = await GrepTool().run(
        {
            "pattern": "rm -rf",
            "path": str(search_tmp),
            "glob": "**/*.go",
        },
        signal,
        AlwaysAllow(),
    )

    assert "shell.go" in out
    assert "rm -rf" in out


@pytest.mark.asyncio
async def test_grep_returns_no_matches(search_tmp, signal):
    out = await GrepTool().run(
        {
            "pattern": "this_string_should_not_exist_anywhere",
            "path": str(search_tmp),
        },
        signal,
        AlwaysAllow(),
    )

    assert out == "no matches"


@pytest.mark.asyncio
async def test_grep_supports_ignore_case(search_tmp, signal):
    out = await GrepTool().run(
        {
            "pattern": "PACKAGE",
            "path": str(search_tmp),
            "glob": "**/*.go",
            "ignore_case": True,
        },
        signal,
        AlwaysAllow(),
    )

    assert "main.go" in out


@pytest.mark.asyncio
async def test_grep_invalid_regex(search_tmp, signal):
    with pytest.raises(Exception, match="invalid regex"):
        await GrepTool().run(
            {
                "pattern": "[unterminated",
                "path": str(search_tmp),
            },
            signal,
            AlwaysAllow(),
        )


@pytest.mark.asyncio
async def test_grep_prompts_sensitive_path(signal):
    home = Path.home()

    with pytest.raises(
        Exception,
        match="search of sensitive path denied",
    ):
        await GrepTool().run(
            {
                "pattern": "BEGIN",
                "path": str(home / ".ssh"),
            },
            signal,
            AlwaysDeny(),
        )


@pytest.mark.asyncio
async def test_grep_single_file(search_tmp, signal):
    out = await GrepTool().run(
        {
            "pattern": "package main",
            "path": str(search_tmp / "main.go"),
        },
        signal,
        AlwaysAllow(),
    )

    assert "main.go" in out
    assert "package main" in out


@pytest.mark.asyncio
async def test_grep_limit_matches(search_tmp, signal):
    directory = search_tmp / "many"
    directory.mkdir()

    for i in range(50):
        (
            directory / f"f{i:03}.txt"
        ).write_text(
            "needle here\n"
        )

    out = await GrepTool().run(
        {
            "pattern": "needle",
            "path": str(directory),
            "glob": "**/*.txt",
            "limit": 10,
        },
        signal,
        AlwaysAllow(),
    )

    lines = out.split("\n")

    assert "[... limited to 10 matches ...]" in lines

    assert (
        len(
            [
                line
                for line in lines
                if "needle" in line
            ]
        )
        == 10
    )


@pytest.mark.asyncio
async def test_grep_finds_matches_across_many_files(search_tmp, signal):
    directory = search_tmp / "spread"
    directory.mkdir()

    (directory / "a.txt").write_text(
        "alpha TARGET\n"
    )

    (directory / "b.txt").write_text(
        "beta\n"
    )

    (directory / "c.txt").write_text(
        "gamma TARGET\n"
    )

    out = await GrepTool().run(
        {
            "pattern": "TARGET",
            "path": str(directory),
            "glob": "**/*.txt",
        },
        signal,
        AlwaysAllow(),
    )

    assert "a.txt" in out
    assert "c.txt" in out
    assert "b.txt" not in out