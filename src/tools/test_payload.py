from __future__ import annotations

import json
from pathlib import Path

import pytest

from permission.permission import Decision, YoloPrompter
from skills.registry import Registry
from tools.payloads import ReadPayloadsTool


class DummyInnerPrompter:

    async def ask(
        self,
        request,
        signal=None,
    ):
        return Decision.ALLOW_ONCE


@pytest.fixture
def noop_prompter():
    return YoloPrompter(
        DummyInnerPrompter(),
        True,
    )


@pytest.fixture
def skill_setup(tmp_path: Path):

    root = tmp_path / "skills"

    skill_dir = (
        root /
        "demo"
    )

    payload_dir = (
        skill_dir /
        "payloads"
    )

    (
        payload_dir /
        "sub"
    ).mkdir(
        parents=True
    )


    # SKILL.md
    (
        skill_dir /
        "SKILL.md"
    ).write_text(
        "---\n"
        "name: demo\n"
        "description: test skill\n"
        "---\n"
        "# body\n",
        encoding="utf-8",
    )


    # payload files

    (
        payload_dir /
        "alpha.txt"
    ).write_text(
        "one\ntwo\nthree\n",
        encoding="utf-8",
    )


    (
        payload_dir /
        "sub" /
        "beta.txt"
    ).write_text(
        "nested\nlines\n",
        encoding="utf-8",
    )


    registry = Registry()

    registry.load_dir(
        root
    )


    tool = ReadPayloadsTool(
        registry
    )


    return {
        "tool": tool,
        "skill_dir": skill_dir,
    }



@pytest.mark.asyncio
async def test_lists_payload_files_sorted(
    skill_setup,
    noop_prompter,
):

    tool = skill_setup["tool"]


    out = await tool.run(
        {
            "skill": "demo",
            "action": "list",
        },
        None,
        noop_prompter,
    )


    parsed = json.loads(
        out
    )


    assert "alpha.txt" in parsed
    assert "sub/beta.txt" in parsed

    assert parsed == sorted(parsed)



@pytest.mark.asyncio
async def test_reads_payload_file(
    skill_setup,
    noop_prompter,
):

    tool = skill_setup["tool"]


    out = await tool.run(
        {
            "skill": "demo",
            "file": "alpha.txt",
        },
        None,
        noop_prompter,
    )


    assert "demo/alpha.txt" in out
    assert "one" in out
    assert "three" in out



@pytest.mark.asyncio
async def test_rejects_path_escape(
    skill_setup,
    noop_prompter,
):

    tool = skill_setup["tool"]


    out = await tool.run(
        {
            "skill": "demo",
            "file": "../SKILL.md",
        },
        None,
        noop_prompter,
    )


    assert "escapes" in out.lower()



    out_abs = await tool.run(
        {
            "skill": "demo",
            "file": "/etc/passwd",
        },
        None,
        noop_prompter,
    )


    assert "escapes" in out_abs.lower()



@pytest.mark.asyncio
async def test_rejects_unknown_skill(
    skill_setup,
    noop_prompter,
):

    tool = skill_setup["tool"]


    out = await tool.run(
        {
            "skill": "no-such-skill",
            "action": "list",
        },
        None,
        noop_prompter,
    )


    assert "not loaded" in out



@pytest.mark.asyncio
async def test_handles_missing_payload_directory(
    tmp_path: Path,
    noop_prompter,
):

    root = (
        tmp_path /
        "skills"
    )


    skill_dir = (
        root /
        "bare"
    )


    skill_dir.mkdir(
        parents=True
    )


    (
        skill_dir /
        "SKILL.md"
    ).write_text(
        "---\n"
        "name: bare\n"
        "description: no payloads\n"
        "---\n"
        "# body\n",
        encoding="utf-8",
    )


    registry = Registry()

    registry.load_dir(
        root
    )


    tool = ReadPayloadsTool(
        registry
    )


    out = await tool.run(
        {
            "skill": "bare",
            "action": "list",
        },
        None,
        noop_prompter,
    )


    assert "no payloads" in out