"""Help cell layout and the mounted TUI's scroll/resize path, entirely offline."""
from __future__ import annotations

from typing import cast

import pytest
from rich.cells import cell_len

from src.agent.agent import Agent
from src.ui.commands.slash_handler import build_help_document, build_help_text, handle_slash
from src.ui.commands.slash_items import SLASH_ITEMS
from src.ui.core.app import KAgent
from src.ui.render.help import HelpDocument, HelpSection, render_help
from src.ui.widgets.transcript import entry_view
from tests.ui.test_input_rendering import app  # Offline full-app fixture, including panel CSS.
from tests.ui.test_slash_handler import HelpAgent


VIEWPORTS = [(160, 40), (100, 30), (48, 20)]


@pytest.fixture
def document() -> HelpDocument:
    return build_help_document(
        cast(Agent, HelpAgent()), lambda: {"backend": "offline", "model": "fixture"},
    )


def compact(text: str) -> str:
    return "".join(text.split())


def assert_command_cells(lines: list[str], document: HelpDocument, prefix: str = "") -> int:
    """Recover both cells independently; detect lost, crossed, or clipped text."""
    start = next(line for line in lines if line.startswith(prefix + "/help "))
    description_column = start.index("commands + keys")
    section_positions = [lines.index(prefix + section.title) for section in document.sections]
    assert section_positions == sorted(section_positions)
    for section_index, section in enumerate(document.sections[:3]):
        body = lines[section_positions[section_index] + 1:section_positions[section_index + 1]]
        starts = [next(i for i, line in enumerate(body)
                       if line[:description_column].strip().split(maxsplit=1)[0:1] == [label.split()[0]])
                  for label, _ in section.rows]
        assert starts == sorted(starts)
        for row_index, (label, description) in enumerate(section.rows):
            end = starts[row_index + 1] if row_index + 1 < len(starts) else len(body)
            row = body[starts[row_index]:end]
            assert row[0].startswith(prefix + label.split()[0])
            assert compact("".join(line[:description_column] for line in row)) == compact(label)
            assert compact("".join(line[description_column:] for line in row)) == compact(description)
    return description_column


def test_help_sections_and_catalog_preserve_current_commands(document: HelpDocument) -> None:
    assert [section.title for section in document.sections] == [
        "Everyday", "Workflow", "Advanced", "Skill picker", "Input",
    ]
    labels = [label for section in document.sections[:3] for label, _ in section.rows]
    names = [label.split()[0] for label in labels]
    assert len(names) == len(set(names)) == len(SLASH_ITEMS)
    assert set(names) == {item.name for item in SLASH_ITEMS}
    scope = next(item for item in SLASH_ITEMS if item.name == "/scope")
    assert scope.args is not None and "tcp-add" in scope.args
    assert ("/scope [...]", "manage HTTP/TCP scope") in document.sections[0].rows
    assert (
        "/permissions [...]",
        "permissions + grants",
    ) in document.sections[2].rows
    assert (
        "/burp [...]",
        "Burp bridge/captures",
    ) in document.sections[2].rows
    burp = next(item for item in SLASH_ITEMS if item.name == "/burp")
    assert burp.args is not None and "use [id|cancel]" in burp.args
    assert "at most 50" not in document.summary
    assert build_help_text(cast(Agent, HelpAgent()), lambda: {"backend": "offline", "model": "fixture"}) == document.plain_text()


def test_help_omits_file_attachment_shortcut(document: HelpDocument) -> None:
    labels = [label for label, _ in document.sections[-1].rows]
    assert not any(label.startswith("@") for label in labels)


@pytest.mark.parametrize("width", [160, 100, 48])
def test_help_renderer_keeps_complete_commands_and_descriptions_in_cells(
    document: HelpDocument, width: int,
) -> None:
    lines = render_help(document, width).splitlines()
    assert max(map(cell_len, lines)) <= width - 2
    assert_command_cells(lines, document)
    # Literal syntax is preserved through Rich rather than interpreted as markup.
    assert "[" in "\n".join(lines) and "|" in "\n".join(lines)


def test_help_rendering_sanitizes_before_cell_wrapping() -> None:
    document = HelpDocument("summary", (HelpSection("section", (
        ("/example [bold]", "Authorization: Bearer private-help-token\x1b[2J"),
    )),), "footer")
    rendered = render_help(document, 40)
    assert "/example" in rendered and "[bold]" in rendered
    assert "private-help-token" not in rendered
    assert "\x1b" not in rendered


@pytest.mark.parametrize("width", [3, 7, 12, 24])
def test_extremely_narrow_help_retains_text_without_horizontal_overflow(width: int) -> None:
    document = HelpDocument("summary", (HelpSection("section", (("/long-command", "complete description"),)),), "footer")
    rendered = render_help(document, width)
    assert max(map(cell_len, rendered.splitlines())) <= max(1, width - 2)
    if width < 8:
        assert compact("/long-command") in compact(rendered)
        assert compact("complete description") in compact(rendered)
    else:
        body = rendered.split("section\n", 1)[1].split("\n\nfooter", 1)[0].splitlines()
        column = body[0].index("comp")
        assert compact("".join(line[:column] for line in body)) == "/long-command"
        assert compact("".join(line[column:] for line in body)) == "completedescription"


def assert_mounted_help(app: KAgent) -> HelpDocument:
    log = app.transcript_log
    entry = app.state.transcript[-1]
    assert entry.help_document is not None
    lines = [line.text for line in log.lines]
    expected = [line.text for line in entry_view(entry, width=log.transcript_content_width)]
    # Every pre-laid-out row is stored as exactly one RichLog strip.
    assert lines == expected
    assert max(map(cell_len, lines)) <= log.transcript_content_width
    assert log.virtual_size.width <= log.scrollable_content_region.width
    assert log.scroll_x == log.max_scroll_x == 0
    assert_command_cells(lines, entry.help_document, prefix="  ")
    return entry.help_document


async def assert_visible_scope(app: KAgent, pilot) -> None:
    log = app.transcript_log
    index = next(i for i, line in enumerate(log.lines) if line.text.startswith("  /scope"))
    log.scroll_to(y=index, animate=False, immediate=True, force=True)
    await pilot.pause()
    visible = log.render_line(0).text
    assert visible.startswith("  /scope")
    # Check the compositor as well as RichLog's stored rows for left-edge loss.
    screen_line = app.screen._compositor.render_strips()[log.region.y].text
    assert "/scope" in screen_line


@pytest.mark.parametrize("size", VIEWPORTS)
async def test_help_in_full_tui_has_aligned_cells_and_scrolls_without_losing_command_heads(
    app: KAgent, size,
) -> None:
    async with app.run_test(size=size) as pilot:
        assert handle_slash(app, "/help")
        await pilot.pause()
        assert_mounted_help(app)
        await assert_visible_scope(app, pilot)
        app.transcript_log.scroll_end(animate=False, immediate=True, x_axis=False)
        await pilot.pause()
        assert app.transcript_log.is_vertical_scroll_end
        assert any("Type /" in app.transcript_log.render_line(y).text
                   for y in range(app.transcript_log.size.height))


@pytest.mark.parametrize("follow_tail", [False, True])
async def test_existing_help_reflows_on_resize_and_preserves_scroll_intent(
    app: KAgent, follow_tail: bool,
) -> None:
    async with app.run_test(size=VIEWPORTS[0]) as pilot:
        assert handle_slash(app, "/help")
        await pilot.pause()
        entry = app.state.transcript[-1]
        original = [line.text for line in app.transcript_log.lines]
        if not follow_tail:
            await assert_visible_scope(app, pilot)
        for width, height in [*VIEWPORTS[1:], VIEWPORTS[0]]:
            await pilot.resize_terminal(width, height)
            await pilot.pause()
            assert app.state.transcript[-1] is entry
            assert_mounted_help(app)
            if follow_tail:
                assert app.transcript_log.is_vertical_scroll_end
            else:
                assert not app.transcript_log.is_vertical_scroll_end
                # A changed table wrap need not retain the exact top row, but
                # history must remain scrollable without losing command heads.
                await assert_visible_scope(app, pilot)
        assert [line.text for line in app.transcript_log.lines] == original
