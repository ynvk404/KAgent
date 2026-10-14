"""Light UI colors never replace authoritative status colors or emphasis."""
from dataclasses import FrozenInstanceError
from io import StringIO
from unittest.mock import Mock

import pytest
from rich.console import Console
from rich.text import Text

from src.ui import theme
from src.ui.bridges.ask_bridge import AskRequest
from src.ui.core.state import TranscriptEntry
from src.ui.render.markdown import render_markdown
from src.ui.render.modal import _input_style, _modal_text
from src.ui.theme import DARK_UI, LIGHT_UI
from src.ui.widgets.ask_modal import AskModal
from src.ui.widgets.permission_modal import PermissionModal
from src.ui.widgets.provider_picker_modal import ProviderPickerModal
from src.ui.widgets.skills_modal import SkillsModal
from src.ui.widgets.transcript import entry_view
from src.tools.common.ask import Option, Question
from tests.ui.test_permission_modal import make_req
from tests.ui.test_skills_modal import FakeAgent


@pytest.fixture(autouse=True)
def colored_terminal(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)


def rich_text(renderable) -> Text:
    output = StringIO()
    Console(file=output, width=120, color_system="truecolor", force_terminal=True,
            highlight=False, markup=False).print(renderable, end="")
    return Text.from_ansi(output.getvalue())


def style_at(text: Text, label: str):
    return text.get_style_at_offset(Console(), text.plain.index(label))


def test_legacy_palette_and_emphasis_are_exact():
    expected = {
        "PRIMARY": "#D6DEE8", "MUTED": "#7E8A9A", "ACCENT": "#38BDF8",
        "SUCCESS": "#3FB950", "WARNING": "#F59E0B", "ERROR": "#EF4444",
        "DANGER": "#F43F5E", "LINK": "#60A5FA",
    }
    assert {name: getattr(theme, name) for name in expected} == expected
    for name in ("ACCENT", "SUCCESS", "ERROR", "DANGER"):
        assert getattr(theme, "BOLD_" + name) == "bold " + expected[name]
    assert (DARK_UI.text, DARK_UI.muted, DARK_UI.accent, DARK_UI.border) == (
        theme.PRIMARY, theme.MUTED, theme.ACCENT, theme.MUTED)
    with pytest.raises(FrozenInstanceError):
        setattr(LIGHT_UI, "text", "white")


@pytest.mark.parametrize("entry", [
    TranscriptEntry("info", "Workflow · enumeration completed"),
    TranscriptEntry("info", "Candidate recorded · SQLi"),
    TranscriptEntry("info", "Validation started · XSS"),
    TranscriptEntry("finding", "Finding saved · SQLi (medium)", details=("fixture.md",)),
    TranscriptEntry("finding", "Finding saved · XSS (low)"),
    TranscriptEntry("validation", "Validation confirmed · SQLi", details=("Evidence · fixture.txt",)),
    TranscriptEntry("warning", "Validation incomplete"),
    TranscriptEntry("warning", "Permission denied"),
    TranscriptEntry("error", "Operation failed"),
    TranscriptEntry("system", "HTTP grant revoked"),
    TranscriptEntry("system", "YOLO disabled"),
    TranscriptEntry("system", "HTTP grant declined; no rights issued"),
    TranscriptEntry("info", "http", details=("Recovered after 1 failed attempt",)),
])
def test_status_rows_are_identical_between_themes(entry):
    assert entry_view(entry, ui=LIGHT_UI) == entry_view(entry, ui=DARK_UI)


def test_ordinary_text_and_observed_impact_change_only_ui_foreground():
    for kind in ("assistant", "user"):
        entry = TranscriptEntry(kind, "Finding saved, permission denied\n  ordinary quoted text")
        dark = entry_view(entry, streaming=True)
        light = entry_view(entry, streaming=True, ui=LIGHT_UI)
        assert [row.text for row in dark] == [row.text for row in light]
        assert all(row.color == (LIGHT_UI.text if kind == "assistant" else LIGHT_UI.accent)
                   for row in light)
    entry = TranscriptEntry("validation", "Validation confirmed · fixture",
                            details=("Observed impact · bounded fixture",))
    light = entry_view(entry, ui=LIGHT_UI)
    assert light[0].color == theme.BOLD_SUCCESS
    assert light[1].color == LIGHT_UI.text
    assert entry.details == ("Observed impact · bounded fixture",)


MARKDOWN = """# Findings
## Evidence
**bold** and *italic*, `OR 1=1`, [proof](https://fixture.test)
> observation
- item
```unknown-fixture-language
literal payload
```
| Input | Evidence |
| --- | --- |
| `q` | **bounded** |
"""


def test_markdown_preserves_text_bold_dim_italic_and_underline(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    dark = Text.from_ansi(render_markdown(MARKDOWN, width=100))
    light = Text.from_ansi(render_markdown(MARKDOWN, width=100, ui=LIGHT_UI))
    assert dark.plain == light.plain
    for offset in range(len(dark)):
        before = dark.get_style_at_offset(Console(), offset)
        after = light.get_style_at_offset(Console(), offset)
        for attribute in ("bold", "dim", "italic", "underline", "reverse"):
            assert getattr(before, attribute) == getattr(after, attribute), (offset, attribute)
    border = light.plain.index("╭")
    assert light.get_style_at_offset(Console(), border).color == style_at(
        Text("border", style=LIGHT_UI.border), "border").color
    assert all(getattr(span.style, "bgcolor", None) is None for span in light.spans)


@pytest.mark.parametrize("language,code", [
    ("sql", "SELECT 1 WHERE 1=1;"), ("html", '<div data-test="fixture">evidence</div>'),
    ("javascript", "const proof = 'fixture';"), ("json", '{"proof": true}'),
])
def test_pygments_emphasis_and_payload_are_unchanged(language, code):
    source = f"```{language}\n{code}\n```"
    assert render_markdown(source, ui=LIGHT_UI) == render_markdown(source)


def test_no_color_and_missing_pygments_fallback(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert render_markdown(MARKDOWN, ui=LIGHT_UI) == render_markdown(MARKDOWN)
    assert "\x1b" not in render_markdown(MARKDOWN, ui=LIGHT_UI)
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setattr("src.ui.render.markdown._supports_language", lambda _: False)
    assert render_markdown("```sql\nSELECT 1;\n```", ui=LIGHT_UI) == render_markdown(
        "```sql\nSELECT 1;\n```")


def test_markdown_cache_isolated_between_app_palettes():
    entry = TranscriptEntry("assistant", "## Evidence\n`fixture`")
    dark = entry_view(entry, ui=DARK_UI)
    light = entry_view(entry, ui=LIGHT_UI)
    assert dark != light
    assert entry_view(entry, ui=DARK_UI) == dark
    assert [Text.from_ansi(row.text).plain for row in dark] == [
        Text.from_ansi(row.text).plain for row in light]


def test_input_colors_preserve_existing_emphasis():
    for name in ("gray", "prompt", "text", "cursor", "cursor_char"):
        before = style_at(Text("x", style=_input_style(name)), "x")
        after = style_at(Text("x", style=_input_style(name, ui=LIGHT_UI)), "x")
        assert (before.bold, before.dim, before.reverse) == (after.bold, after.dim, after.reverse)
    assert _input_style("gray", ui=LIGHT_UI) == LIGHT_UI.muted
    assert _input_style("cursor_char", ui=LIGHT_UI) == "reverse"


@pytest.mark.parametrize("selected", [False, True])
def test_ask_active_state_and_error_keep_their_styles(selected):
    modal = AskModal(AskRequest(Question(header="Choice", question="Choose",
        options=[Option("One", "first"), Option("Two", "● active")]), Mock(), Mock()))
    modal.idx = int(selected)
    dark, light = rich_text(_modal_text(modal)), rich_text(_modal_text(modal, ui=LIGHT_UI))
    assert dark.plain == light.plain
    assert style_at(dark, "● active") == style_at(light, "● active")


def test_provider_selection_changes_without_recoloring_active():
    modal = ProviderPickerModal(AskRequest(Question(header="provider", question="Provider",
        options=[Option("OpenAI", "● active")]), Mock(), Mock()), current_backend="openai")
    dark, light = rich_text(_modal_text(modal)), rich_text(_modal_text(modal, ui=LIGHT_UI))
    assert dark.plain == light.plain
    assert style_at(dark, "● active") == style_at(light, "● active")
    assert style_at(light, "[ Official ]").bold is True


def test_dark_provider_header_keeps_legacy_accent_override_behavior():
    modal = ProviderPickerModal(AskRequest(Question(header="provider", question="Provider",
        options=[Option("OpenAI", "fixture")]), Mock(), Mock()))
    rendered = rich_text(_modal_text(modal, accent_style="red"))
    assert style_at(rendered, "[ Official ]") == style_at(
        Text("header", style=theme.BOLD_ACCENT), "header")


def test_skills_state_markers_and_error_keep_original_colors():
    agent = FakeAgent()
    modal = SkillsModal(agent, Mock())
    for disabled, busy, marker in ((False, False, "[on]"), (True, False, "[off]"),
                                  (False, True, "[…]") ):
        agent.skills.disabled = {"web_scan"} if disabled else set()
        modal.busy_name = "web_scan" if busy else None
        modal.error = "fixture failure"
        dark, light = rich_text(_modal_text(modal)), rich_text(_modal_text(modal, ui=LIGHT_UI))
        assert dark.plain == light.plain
        assert style_at(dark, marker) == style_at(light, marker)
        assert style_at(dark, "error:") == style_at(light, "error:")


def test_skill_description_markers_do_not_gain_emphasis_in_light():
    agent = FakeAgent()
    agent.skills.items[0].description = "ordinary examples [off], [on], […]"
    modal = SkillsModal(agent, Mock())
    dark, light = rich_text(_modal_text(modal)), rich_text(_modal_text(modal, ui=LIGHT_UI))
    assert dark.plain == light.plain
    start = dark.plain.index("ordinary examples")
    for offset in range(start, start + len(agent.skills.items[0].description)):
        before = dark.get_style_at_offset(Console(), offset)
        after = light.get_style_at_offset(Console(), offset)
        assert (before.bold, before.dim, before.italic, before.underline) == (
            after.bold, after.dim, after.italic, after.underline)


def test_permission_preview_status_and_callbacks_are_unchanged():
    req = make_req(tool="mcp_browser", summary="Review interaction", detail="fixture preview",
                   offer_browser_grant="interaction")
    modal = PermissionModal(req)
    dark, light = rich_text(modal.render()), rich_text(modal.render(ui=LIGHT_UI))
    assert dark.plain == light.plain
    for label in ("Review interaction", "Click/type may submit"):
        assert style_at(dark, label) == style_at(light, label)
    assert req.detail == "fixture preview"
    req.resolve.assert_not_called()
    req.reject.assert_not_called()
