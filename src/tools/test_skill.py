"""
ReadSkillFileTool tests.

Port từ:
agent/src/tools/skillFile.test.ts
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from src.permission.permission import (
    Decision,
    PermissionRequest,
)

from src.skills.registry import Registry
from src.tools.skill_file import ReadSkillFileTool


# ============================================================
# Dummy Prompter
# ============================================================

class DummyPrompter:
    """
    Stand-in for Prompter.
    ReadSkillFileTool không yêu cầu permission,
    nhưng interface run() vẫn cần truyền vào.
    """

    async def ask(
        self,
        request: PermissionRequest,
        signal=None,
    ) -> Decision:
        return Decision.ALLOW_ONCE


noop_signal = None
noop_prompter = DummyPrompter()


# ============================================================
# Fixture
# ============================================================

def make_fixture() -> ReadSkillFileTool:
    """
    Tạo một skill giả:

    demo/
    ├── SKILL.md
    ├── payloads/
    │   └── alpha.txt
    ├── scripts/
    │   └── check.sh
    └── data/
        └── config.json
    """

    root = Path(
        tempfile.mkdtemp(
            prefix="pf-skillfile-"
        )
    )

    skill = root / "demo"


    (skill / "payloads").mkdir(
        parents=True
    )

    (skill / "scripts").mkdir()

    (skill / "data").mkdir()


    (skill / "SKILL.md").write_text(
        "---\n"
        "name: demo\n"
        "description: t\n"
        "---\n"
        "body\n",
        encoding="utf-8",
    )


    (skill / "payloads" / "alpha.txt").write_text(
        "one\ntwo\n",
        encoding="utf-8",
    )


    (skill / "scripts" / "check.sh").write_text(
        "#!/bin/sh\n"
        "echo ok\n",
        encoding="utf-8",
    )


    (skill / "data" / "config.json").write_text(
        '{"v":1}\n',
        encoding="utf-8",
    )


    registry = Registry()

    # tương đương:
    # reg.loadDir(root)
    registry.load_dir(
        root
    )


    return ReadSkillFileTool(
        registry
    )


# ============================================================
# Tests
# ============================================================


@pytest.mark.asyncio
async def test_lists_all_aux_files_but_hides_skill_md():

    tool = make_fixture()


    out = await tool.run(
        {
            "skill": "demo",
            "action": "list",
        },
        noop_signal,
        noop_prompter,
    )


    parsed = json.loads(out)


    assert "payloads/alpha.txt" in parsed
    assert "scripts/check.sh" in parsed
    assert "data/config.json" in parsed

    # SKILL.md được load bằng load_skill()
    # không đọc qua tool này
    assert "SKILL.md" not in parsed



@pytest.mark.asyncio
async def test_reads_files_from_any_subdir_under_skill():

    tool = make_fixture()


    out = await tool.run(
        {
            "skill": "demo",
            "path": "scripts/check.sh",
        },
        noop_signal,
        noop_prompter,
    )


    assert "demo/scripts/check.sh" in out
    assert "echo ok" in out



@pytest.mark.asyncio
async def test_refuses_parent_directory_traversal():

    tool = make_fixture()


    out = await tool.run(
        {
            "skill": "demo",
            "path": "../../etc/passwd",
        },
        noop_signal,
        noop_prompter,
    )


    assert "escapes" in out.lower()



@pytest.mark.asyncio
async def test_refuses_absolute_paths():

    tool = make_fixture()


    out = await tool.run(
        {
            "skill": "demo",
            "path": "/etc/passwd",
        },
        noop_signal,
        noop_prompter,
    )


    assert "escapes" in out.lower()



@pytest.mark.asyncio
async def test_refuses_reading_skill_md_directly():

    tool = make_fixture()


    out = await tool.run(
        {
            "skill": "demo",
            "path": "SKILL.md",
        },
        noop_signal,
        noop_prompter,
    )


    assert "load_skill" in out

@pytest.mark.asyncio
async def test_requires_skill_argument():

    tool = make_fixture()

    out = await tool.run(
        {},
        noop_signal,
        noop_prompter,
    )

    assert "skill is required" in out



@pytest.mark.asyncio
async def test_requires_path_for_read_action():

    tool = make_fixture()

    out = await tool.run(
        {
            "skill": "demo",
            "action": "read",
        },
        noop_signal,
        noop_prompter,
    )

    assert "path is required" in out



@pytest.mark.asyncio
async def test_rejects_unknown_action():

    tool = make_fixture()

    out = await tool.run(
        {
            "skill": "demo",
            "action": "delete",
        },
        noop_signal,
        noop_prompter,
    )

    assert "unknown action" in out



@pytest.mark.asyncio
async def test_respects_line_limit():

    tool = make_fixture()

    out = await tool.run(
        {
            "skill": "demo",
            "path": "payloads/alpha.txt",
            "limit": 1,
        },
        noop_signal,
        noop_prompter,
    )

    assert "one" in out