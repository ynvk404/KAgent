from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.permission.permission import Decision, YoloPrompter
from src.skills.registry import Registry
from src.tools.payloads import ReadPayloadsTool


REPO_ROOT = Path(__file__).resolve().parents[2]


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
        "allowed-tools: []\n"
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
        "allowed-tools: []\n"
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

    assert out == (
        'skill "bare" has no payload sources; '
        "expected payloads/ directory or payloads.txt file"
    )


@pytest.fixture(scope="module")
def shipped_payload_tool():
    registry = Registry()
    registry.load_dir(REPO_ROOT / "skills")
    return ReadPayloadsTool(registry)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "skill_name",
    [
        "sql-injection",
        "cross-site-scripting",
        "ssti",
    ],
)
async def test_reads_top_level_payloads_from_shipped_skills(
    shipped_payload_tool,
    noop_prompter,
    skill_name,
):
    listed = await shipped_payload_tool.run(
        {
            "skill": skill_name,
            "action": "list",
        },
        None,
        noop_prompter,
    )
    assert json.loads(listed) == ["payloads.txt"]

    out = await shipped_payload_tool.run(
        {
            "skill": skill_name,
            "file": "payloads.txt",
        },
        None,
        noop_prompter,
    )

    assert f"# {skill_name}/payloads.txt" in out
    assert "PHASE 1" in out
    assert not out.startswith("error:")


@pytest.mark.asyncio
async def test_shipped_payload_reader_rejects_traversal(
    shipped_payload_tool,
    noop_prompter,
):
    out = await shipped_payload_tool.run(
        {
            "skill": "sql-injection",
            "file": "../SKILL.md",
        },
        None,
        noop_prompter,
    )

    assert out == 'error: path "../SKILL.md" escapes <skill>/payloads/'
