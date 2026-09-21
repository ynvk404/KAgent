from __future__ import annotations

from src.ui.widgets import terminal_size as ts
from src.ui.widgets.terminal_size import (
    DEFAULT_SIZE,
    TerminalSize,
    read_terminal_size,
)


def test_terminal_size_is_frozen():
    size = TerminalSize(columns=10, rows=20)
    assert (size.columns, size.rows) == (10, 20)

    import dataclasses

    try:
        size.columns = 5  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        pass
    else:  # pragma: no cover - defensive
        raise AssertionError("TerminalSize should be frozen")


def test_default_size():
    assert DEFAULT_SIZE == TerminalSize(columns=100, rows=30)


def test_read_terminal_size_uses_env(monkeypatch):
    monkeypatch.setenv("COLUMNS", "123")
    monkeypatch.setenv("LINES", "45")

    size = read_terminal_size()

    assert size == TerminalSize(columns=123, rows=45)


def test_read_terminal_size_falls_back_to_default(monkeypatch):
    monkeypatch.delenv("COLUMNS", raising=False)
    monkeypatch.delenv("LINES", raising=False)

    class _Size:
        columns = DEFAULT_SIZE.columns
        lines = DEFAULT_SIZE.rows

    monkeypatch.setattr(
        ts,
        "shutil",
        type(
            "FakeShutil",
            (),
            {
                "get_terminal_size": lambda fallback: _Size()
            },
        ),
    )