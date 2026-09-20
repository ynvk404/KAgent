from __future__ import annotations

from dataclasses import dataclass, field
from typing import IO, cast

from src.ui.core.state import TranscriptEntry
from src.ui.widgets.banner import BannerData
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
