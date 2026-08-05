from __future__ import annotations

import frontmatter
from typing import cast
from src.skills.template import render_skill_template
KNOWN_TOOL_NAMES = {
    "http",
    "shell",
    "file_write",
}


def test_render_skill_template_frontmatter():

    post = frontmatter.loads(
        render_skill_template("my-skill")
    )

    assert post["name"] == "my-skill"

    assert isinstance(
        post["description"],
        str,
    )

    description = post["description"]
    assert isinstance(description, str)
    assert len(description) <= 1024
    assert post.content.strip()

def test_render_skill_template_allowed_tools():

    post = frontmatter.loads(
        render_skill_template("x")
    )

    tools = post["allowed-tools"]

    assert isinstance(
        tools,
        list,
    )

    for tool in tools:
        assert tool in KNOWN_TOOL_NAMES

    assert "tools" not in post.metadata