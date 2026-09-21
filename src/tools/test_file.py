from __future__ import annotations

import shutil
import stat
import tempfile
from pathlib import Path

import pytest

from src.permission.permission import (
    AlwaysAllow,
    AlwaysDeny,
    Decision,
    PermissionRequest,
)
from src.tools.file import (
    FileReadTool,
    FileWriteTool,
    FileEditTool,
)

@pytest.fixture
def file_tmp():
    tmp = Path(
        tempfile.mkdtemp(
            prefix="pf-file-"
        )
    )

    yield tmp

    shutil.rmtree(
        tmp,
        ignore_errors=True,
    )

@pytest.fixture
def signal():
    return None

@pytest.mark.asyncio
async def test_file_read_regular_file(file_tmp, signal):
    path = file_tmp / "a.txt"

    path.write_text(
        "hello world"
    )

    out = await FileReadTool().run(
        {
            "path": str(path),
        },
        signal,
        AlwaysDeny(),
    )

    assert out == "hello world"


def test_file_permission_scopes_use_resolved_paths(file_tmp):
    path = file_tmp / "nested" / "notes.txt"

    assert FileWriteTool().permission_hints({"path": str(path)})[
        "sessionScopeDisplay"
    ] == f"writes to {path.resolve()}"
    assert FileEditTool().permission_hints({"path": str(path)})[
        "sessionScopeDisplay"
    ] == f"edits to {path.resolve()}"

@pytest.mark.asyncio
async def test_file_read_missing_path(signal):
    with pytest.raises(
        Exception,
        match="required",
    ):
        await FileReadTool().run(
            {},
            signal,
            AlwaysAllow(),
        )

@pytest.mark.asyncio
async def test_file_read_large_file_truncated(
    file_tmp,
    signal,
):
    path = file_tmp / "big.txt"

    size = 250 * 1024

    path.write_text(
        "a" * size
    )

    out = await FileReadTool().run(
        {
            "path": str(path),
        },
        signal,
        AlwaysAllow(),
    )

    assert "truncated" in out

    assert (
        f"{size - 200 * 1024} bytes"
        in out
    )

    assert (
        len(out)
        < 210 * 1024
    )

@pytest.mark.asyncio
async def test_file_write_creates_parent_dirs(
    file_tmp,
    signal,
):
    path = (
        file_tmp
        / "nested"
        / "b.txt"
    )

    out = await FileWriteTool().run(
        {
            "path": str(path),
            "content": "abc",
        },
        signal,
        AlwaysAllow(),
    )

    assert "wrote 3 bytes" in out

    back = await FileReadTool().run(
        {
            "path": str(path),
        },
        signal,
        AlwaysAllow(),
    )

    assert back == "abc"


@pytest.mark.asyncio
async def test_file_write_and_edit_preserve_existing_modes(file_tmp, signal):
    parent = file_tmp / "private"
    parent.mkdir(mode=0o700)
    path = parent / "secret.txt"
    path.write_text("before")
    path.chmod(0o600)

    await FileWriteTool().run(
        {"path": str(path), "content": "after"}, signal, AlwaysAllow()
    )
    await FileEditTool().run(
        {"path": str(path), "old_string": "after", "new_string": "edited"},
        signal,
        AlwaysAllow(),
    )

    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

@pytest.mark.asyncio
async def test_file_edit_replace_unique(
    file_tmp,
    signal,
):
    path = file_tmp / "c.txt"

    path.write_text(
        "foo bar baz"
    )

    await FileEditTool().run(
        {
            "path": str(path),
            "old_string": "bar",
            "new_string": "qux",
        },
        signal,
        AlwaysAllow(),
    )

    after = await FileReadTool().run(
        {
            "path": str(path),
        },
        signal,
        AlwaysAllow(),
    )

    assert after == "foo qux baz"

@pytest.mark.asyncio
async def test_file_edit_non_unique_without_replace_all(
    file_tmp,
    signal,
):
    path = file_tmp / "d.txt"

    path.write_text(
        "x x x"
    )

    with pytest.raises(
        Exception,
        match="appears 3 times",
    ):
        await FileEditTool().run(
            {
                "path": str(path),
                "old_string": "x",
                "new_string": "y",
            },
            signal,
            AlwaysAllow(),
        )

@pytest.mark.asyncio
async def test_file_edit_replace_all(
    file_tmp,
    signal,
):
    path = file_tmp / "e.txt"

    path.write_text(
        "x x x"
    )

    await FileEditTool().run(
        {
            "path": str(path),
            "old_string": "x",
            "new_string": "y",
            "replace_all": True,
        },
        signal,
        AlwaysAllow(),
    )

    after = await FileReadTool().run(
        {
            "path": str(path),
        },
        signal,
        AlwaysAllow(),
    )

    assert after == "y y y"

@pytest.mark.asyncio
async def test_file_edit_old_string_not_found(
    file_tmp,
    signal,
):
    path = file_tmp / "f.txt"

    path.write_text(
        "hello"
    )

    with pytest.raises(
        Exception,
        match="not found",
    ):
        await FileEditTool().run(
            {
                "path": str(path),
                "old_string": "missing",
                "new_string": "x",
            },
            signal,
            AlwaysAllow(),
        )
@pytest.mark.asyncio
async def test_sensitive_path_gate_asks_with_permission_request(file_tmp, signal):
    path = file_tmp / ".env"

    path.write_text(
        "API_KEY=secret"
    )

    asked: list[PermissionRequest] = []

    class Recorder:
        async def ask(self, request, _signal=None):
            asked.append(request)
            return Decision.ALLOW_ONCE

    out = await FileReadTool().run(
        {
            "path": str(path),
        },
        signal,
        Recorder(),
    )

    assert out == "API_KEY=secret"
    assert len(asked) == 1
    assert isinstance(asked[0], PermissionRequest)
    assert asked[0].no_session_cache is True

@pytest.mark.asyncio
async def test_sensitive_path_gate_denies_read(file_tmp, signal):
    path = file_tmp / ".env"

    path.write_text(
        "API_KEY=secret"
    )

    with pytest.raises(
        PermissionError,
        match="denied",
    ):
        await FileReadTool().run(
            {
                "path": str(path),
            },
            signal,
            AlwaysDeny(),
        )
