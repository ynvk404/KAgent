from __future__ import annotations

import re

import pytest

from ui.render.markdown import render_markdown

ESC = "\x1b"
_ANSI_RE = re.compile(rf"{ESC}\[[0-9;]*m")

BOLD = f"{ESC}[1m"
ITALIC = f"{ESC}[3m"
CYAN = f"{ESC}[36m"


def strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


@pytest.fixture(autouse=True)
def _no_color_unset(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "")


class TestRenderMarkdown:
    def test_returns_input_unchanged_when_no_markdown_syntax(self):
        plain = "hello world, nothing fancy here"
        assert render_markdown(plain) == plain

    def test_renders_bold_star(self):
        out = render_markdown("confirmed **IDOR** in /api")
        assert BOLD in out
        assert "IDOR" in out
        assert strip_ansi(out) == "confirmed IDOR in /api"

    def test_renders_bold_underscore_alt_syntax(self):
        out = render_markdown("this is __also bold__")
        assert BOLD in out
        assert strip_ansi(out) == "this is also bold"

    def test_renders_italic_star_and_underscore(self):
        assert ITALIC in render_markdown("makes *italics*")
        assert ITALIC in render_markdown("makes _italics_")

    def test_does_not_treat_star_inside_words_as_italic(self):
        assert strip_ansi(render_markdown("foo*bar*baz")) == "foo*bar*baz"
        assert strip_ansi(render_markdown("snake_case_token")) == "snake_case_token"

    def test_renders_inline_code(self):
        out = render_markdown("hit `/api/users/1` to repro")
        assert "/api/users/1" in out
        assert CYAN in out

    def test_renders_h1_as_bold(self):
        out = render_markdown("# Findings\nbody")
        assert BOLD in out.split("\n")[0]
        assert strip_ansi(out) == "Findings\nbody"

    def test_renders_h2_as_bold(self):
        out = render_markdown("## Recon\nbody")
        assert BOLD in out.split("\n")[0]

    def test_rewrites_bullet_markers(self):
        out = render_markdown("- one\n- two")
        assert strip_ansi(out) == "\u2022 one\n\u2022 two"

    def test_preserves_indentation_on_bullets(self):
        out = render_markdown("  - nested")
        assert strip_ansi(out) == "  \u2022 nested"

    def test_renders_blockquote_with_bar_prefix(self):
        out = render_markdown("> heads up")
        assert strip_ansi(out) == "\u2502 heads up"

    def test_preserves_code_fence_content_verbatim(self):
        input_ = '```\n**not bold here** plain text\n```'
        out = render_markdown(input_)
        assert "**not bold here**" in strip_ansi(out)

    def test_syntax_highlights_fenced_bash_block(self):
        input_ = "```bash\ncurl -s [https://example.com](https://example.com) | jq .\n```"
        out = render_markdown(input_)
        ansi_count = len(re.findall(rf"{ESC}\[", out))
        assert ansi_count > 1
        assert "curl" in strip_ansi(out)
        assert "https://example.com" in strip_ansi(out)

    def test_syntax_highlights_fenced_python_block(self):
        input_ = '```python\nimport socket\nsocket.gethostbyname("x")\n```'
        out = render_markdown(input_)
        assert "import socket" in strip_ansi(out)
        assert "gethostbyname" in strip_ansi(out)

    def test_falls_back_to_dim_for_unknown_languages(self):
        input_ = "```madeup-lang-9999\nplain content\n```"
        out = render_markdown(input_)
        assert "plain content" in strip_ansi(out)
        assert ESC in out

    def test_handles_unterminated_code_fences_gracefully(self):
        input_ = "```bash\necho still flushed even without closing fence"
        out = render_markdown(input_)
        assert "echo still flushed even without closing fence" in strip_ansi(out)

    def test_adds_line_number_gutter_to_multiline_blocks(self):
        lines = ["ls", "pwd", "whoami", "uname -a", "id"]
        input_ = f"```bash\n{chr(10).join(lines)}\n```"
        out = render_markdown(input_)
        stripped = strip_ansi(out)
        assert "1\u2502" in stripped
        assert "5\u2502" in stripped
        for l in lines:
            assert l in stripped

    def test_numbers_every_fenced_block_including_single_line(self):
        input_ = '```python\nprint("Hello, World!")\n```'
        stripped = strip_ansi(render_markdown(input_))
        assert "1\u2502" in stripped
        assert 'print("Hello, World!")' in stripped

    def test_accepts_up_to_3_leading_spaces_before_fence(self):
        input_ = '   ```python\nprint("hi")\n   ```'
        out = render_markdown(input_)
        stripped = strip_ansi(out)
        assert "1\u2502" in stripped
        assert 'print("hi")' in stripped
        assert "```" not in stripped

    def test_renders_fenced_blocks_bare_gutter_no_chrome(self):
        input_ = '```python\nprint("Hello, World!")\n```'
        stripped = strip_ansi(render_markdown(input_))
        assert "\u2500\u2500\u2500 python" not in stripped
        assert not re.search(r"^\u2500+$", stripped, re.MULTILINE)
        assert "```" not in stripped
        assert '1\u2502 print("Hello, World!")' in stripped

    def test_emits_nothing_for_empty_fenced_block(self):
        assert render_markdown("```\n```") == ""

    def test_accepts_tab_indented_fence(self):
        input_ = "\t```bash\necho hi\n\t```"
        assert "1\u2502" in strip_ansi(render_markdown(input_))

    def test_handles_bold_inside_heading(self):
        out = render_markdown("# Title with **bold** word")
        assert strip_ansi(out) == "Title with bold word"

    def test_does_not_eat_code_inside_bold(self):
        out = render_markdown("**inline `code` mix**")
        assert strip_ansi(out) == "inline code mix"

    def test_passes_empty_string_through_unchanged(self):
        assert render_markdown("") == ""

    def test_hides_standalone_proposed_plan_wrapper_tags(self):
        input_ = "<proposed_plan>\n# Summary\n- recon target\n</proposed_plan>"
        stripped = strip_ansi(render_markdown(input_))
        assert "Summary" in stripped
        assert "\u2022 recon target" in stripped
        assert "<proposed_plan>" not in stripped
        assert "</proposed_plan>" not in stripped

    def test_keeps_newlines_for_transcript_windowing(self):
        out = render_markdown("line1\nline2\nline3")
        assert len(out.split("\n")) == 3

    def test_renders_link_as_label_and_url(self):
        out = render_markdown("see [the advisory](https://example.com/cve)")
        stripped = strip_ansi(out)
        assert stripped == "see the advisory (https://example.com/cve)"
        assert out != stripped
        assert "](" not in stripped

    def test_collapses_link_with_label_equal_to_url(self):
        stripped = strip_ansi(render_markdown("[https://x.test](https://x.test)"))
        assert stripped == "https://x.test"

    def test_underscores_in_link_url_do_not_trigger_italics(self):
        stripped = strip_ansi(render_markdown("[x](https://a.test/foo_bar_baz)"))
        assert stripped == "x (https://a.test/foo_bar_baz)"

    def test_renders_pipe_table_as_aligned_grid(self):
        input_ = "\n".join([
            "| Vuln | Severity |",
            "| --- | --- |",
            "| IDOR | High |",
            "| XSS | Medium |",
        ])
        lines = strip_ansi(render_markdown(input_)).split("\n")
        assert len(lines) == 4
        assert "Vuln" in lines[0]
        assert "Severity" in lines[0]
        assert "\u253c" in lines[1]
        assert re.match(r"^\u2500+\u253c\u2500+$", lines[1])
        assert lines[2].index("\u2502") == lines[3].index("\u2502")
        assert "IDOR" in lines[2]
        assert "Medium" in lines[3]

    def test_leaves_lone_pipe_line_untouched(self):
        stripped = strip_ansi(render_markdown("a | b without a separator row"))
        assert stripped == "a | b without a separator row"