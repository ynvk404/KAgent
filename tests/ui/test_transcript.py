from __future__ import annotations

from dataclasses import dataclass, field
from io import StringIO
from typing import IO, Callable, cast

import pytest
from rich.console import Console

from src.ui.core.state import TranscriptEntry
from src.ui.widgets.banner import Banner, BannerData, ToolSupportPill
from src.ui.widgets.transcript import Transcript


@dataclass
class _RichLogOutput:
    lines: list[str] = field(default_factory=list)
    clear_calls: int = 0

    def write(self, text: str) -> int:
        self.lines.extend(text.splitlines())
        return len(text)

    def clear(self) -> None:
        self.clear_calls += 1
        self.lines.clear()


@dataclass
class _Overview:
    current: BannerData | None = None
    updates: int = 0

    def update(self, data: BannerData) -> None:
        self.current = data
        self.updates += 1


def _overview_writer(overview: _Overview) -> Callable[[BannerData], None]:
    return overview.update


def _rendered_overview(data: BannerData) -> str:
    output = StringIO()
    Console(file=output, force_terminal=False, width=80).print(
        Banner(data, width=80).render_panel()
    )
    return output.getvalue()


@pytest.mark.parametrize("final_state", ["yes", "no", "unknown"])
def test_banner_refresh_replaces_overview_without_clearing_transcript(
    final_state: str,
) -> None:
    output = _RichLogOutput()
    overview = _Overview()
    transcript = Transcript(
        out=cast(IO[str], output),
        clear=output.clear,
        width=lambda: 80,
        write_banner=_overview_writer(overview),
    )
    probing = BannerData(
        provider="openai", model="test-model", cwd="/workspace", tool_support="probing"
    )
    final = BannerData(
        provider="openai",
        model="test-model",
        cwd="/workspace",
        tool_support=cast(ToolSupportPill, final_state),
    )
    entries = [TranscriptEntry(kind="tool-result", text="existing tool output")]

    transcript.flush(entries, probing, generation="startup")
    assert overview.current is probing
    assert output.lines == ["↳ existing tool output", ""]

    transcript.flush(entries, final, generation="startup")

    assert overview.current is final
    assert overview.updates == 2
    assert output.clear_calls == 1
    assert output.lines == ["↳ existing tool output", ""]
    assert "probing…" not in _rendered_overview(final)
    assert "Model: test-model" in _rendered_overview(final)
    assert "[tools" not in _rendered_overview(final)
    assert "NO TOOLS" not in _rendered_overview(final)


def test_banner_updates_and_new_generations_keep_one_current_overview() -> None:
    output = _RichLogOutput()
    overview = _Overview()
    transcript = Transcript(
        out=cast(IO[str], output),
        clear=output.clear,
        width=lambda: 80,
        write_banner=_overview_writer(overview),
    )
    probing = BannerData(
        provider="openai", model="test-model", cwd="/workspace", tool_support="probing"
    )
    supported = BannerData(
        provider="openai", model="test-model", cwd="/workspace", tool_support="yes"
    )
    unknown = BannerData(
        provider="openai", model="test-model", cwd="/workspace", tool_support="unknown"
    )

    transcript.flush([TranscriptEntry(kind="assistant", text="keep this")], probing, "initial")
    transcript.flush([TranscriptEntry(kind="assistant", text="keep this")], supported, "initial")
    transcript.flush([], unknown, "after-reset", clear_message="conversation reset")

    assert overview.current is unknown
    assert overview.updates == 3
    assert output.clear_calls == 2
    assert output.lines == ["· conversation reset", ""]
    assert "Model: test-model" in _rendered_overview(unknown)
    assert "tools ?" not in _rendered_overview(unknown)


def test_new_generation_replaces_richlog_content_with_a_fresh_banner() -> None:
    output = _RichLogOutput()
    transcript = Transcript(
        out=cast(IO[str], output),
        clear=output.clear,
        width=lambda: 80,
    )
    banner = BannerData(
        provider="openai",
        model="test-model",
        cwd="/workspace",
        endpoint="https://api.example.test",
        status="ready",
    )

    transcript.flush(
        [
            TranscriptEntry(kind="error", text="old error"),
            TranscriptEntry(kind="tool-result", text="old tool output"),
        ],
        banner,
        generation="before-clear",
    )
    transcript.flush(
        [],
        banner,
        generation="after-reset",
        clear_message="conversation reset",
    )

    rendered = "\n".join(output.lines)
    assert "old error" not in rendered
    assert "old tool output" not in rendered
    assert rendered.count("conversation reset") == 1
    assert rendered.count("Welcome to KAgent") == 1
    assert rendered.index("conversation reset") < rendered.index("Welcome to KAgent")
    assert "Provider: openai" in rendered
    assert "Model: test-model" in rendered
    assert "Endpoint: https://api.example.test" in rendered
    assert "Status: ready" in rendered


def test_repeated_resets_do_not_accumulate_status_lines_or_banners() -> None:
    output = _RichLogOutput()
    transcript = Transcript(
        out=cast(IO[str], output), clear=output.clear, width=lambda: 80
    )
    banner = BannerData(provider="test", model="test", cwd=".")

    transcript.flush([], banner, generation=1, clear_message="conversation reset")
    transcript.flush([], banner, generation=2, clear_message="conversation reset")
    transcript.flush([], banner, generation=3, clear_message="conversation reset")

    assert output.clear_calls == 3
    rendered = "\n".join(output.lines)
    assert rendered.count("conversation reset") == 1
    assert rendered.count("Welcome to KAgent") == 1
