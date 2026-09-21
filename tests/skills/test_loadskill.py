from pathlib import Path
import tempfile

import pytest

from src.skills.registry import (
    Registry,
    parse_skill,
    materialize_skill_body,
)
from src.skills.load_skill import LoadSkillTool

def make_tmp_skills():
    root = Path(
        tempfile.mkdtemp(
            prefix="pf-loadskill-"
        )
    )

    alpha = root / "alpha"
    alpha.mkdir()
    (alpha / "SKILL.md").write_text(
        """---
name: alpha
description: regular skill
tools:
  - shell
  - http
---

# alpha body

use ${SKILL_DIR}/script.sh
""",
        encoding="utf-8"
    )

    beta = root / "beta"
    beta.mkdir()
    (beta / "SKILL.md").write_text(
        """---
name: beta
description: user-only skill
allowed-tools: []
disable-model-invocation: true
---

# beta body
""",
        encoding="utf-8"
    )

    reg = Registry()
    reg.load_dir(root)

    return root, reg

def test_parse_disable_model_invocation_kebab():
    root = Path(
        tempfile.mkdtemp(
            prefix="pf-parse-"
        )
    )
    skill = root / "kebab"
    skill.mkdir()

    file = skill / "SKILL.md"
    file.write_text(
        """---
name: kebab
description: x
allowed-tools: []
disable-model-invocation: true
---

# body
""",
        encoding="utf-8"
    )

    s = parse_skill(file)
    assert s.disable_model_invocation is True

def test_parse_disable_model_invocation_camel():
    root = Path(
        tempfile.mkdtemp(
            prefix="pf-parse-"
        )
    )
    skill = root / "camel"
    skill.mkdir()

    file = skill / "SKILL.md"
    file.write_text(
        """---
name: camel
description: y
allowed-tools: []
disableModelInvocation: true
---

# body
""",
        encoding="utf-8"
    )

    s = parse_skill(file)
    assert s.disable_model_invocation is True

def test_parse_disable_default_false():
    root = Path(
        tempfile.mkdtemp(
            prefix="pf-parse-"
        )
    )
    skill = root / "plain"
    skill.mkdir()

    file = skill / "SKILL.md"
    file.write_text(
        """---
name: plain
description: z
allowed-tools: []
---

# body
""",
        encoding="utf-8"
    )

    s = parse_skill(file)
    assert s.disable_model_invocation is False

def test_materialize_replace_skill_dir():
    root, reg = make_tmp_skills()

    skill = reg.get("alpha")
    assert skill is not None

    body = materialize_skill_body(skill)

    assert "${SKILL_DIR}" not in body
    assert str(root / "alpha") in body
    assert body.startswith("# Skill: alpha")

def test_materialize_replace_multiple():
    root = Path(
        tempfile.mkdtemp(
            prefix="pf-multi-"
        )
    )
    folder = root / "multi"
    folder.mkdir()

    (folder / "SKILL.md").write_text(
        """---
name: multi
description: x
allowed-tools: []
---

${SKILL_DIR}/a

${SKILL_DIR}/b

${SKILL_DIR}/c
""",
        encoding="utf-8"
    )

    reg = Registry()
    reg.load_dir(root)

    skill = reg.get("multi")
    assert skill is not None

    body = materialize_skill_body(skill)

    assert "${SKILL_DIR}" not in body
    assert body.count(str(folder)) == 3

@pytest.mark.asyncio
async def test_load_skill_normal():
    _, reg = make_tmp_skills()

    tool = LoadSkillTool(reg)
    result = await tool.run({"name": "alpha"})

    assert "# Skill: alpha" in result
    assert "# alpha body" in result
    assert "${SKILL_DIR}" not in result


def test_load_skill_preserves_full_playbook_in_working_context():
    _, reg = make_tmp_skills()

    assert LoadSkillTool(reg).context_reduction_policy() == "preserve"

@pytest.mark.asyncio
async def test_load_skill_disabled():
    _, reg = make_tmp_skills()

    reg.set_disabled("alpha", True)

    tool = LoadSkillTool(reg)

    with pytest.raises(
        ValueError,
        match="disabled"
    ):
        await tool.run({"name": "alpha"})

@pytest.mark.asyncio
async def test_load_skill_user_only():
    _, reg = make_tmp_skills()

    tool = LoadSkillTool(reg)

    with pytest.raises(
        ValueError,
        match="disable-model-invocation"
    ):
        await tool.run({"name": "beta"})

@pytest.mark.asyncio
async def test_available_excludes_hidden():
    _, reg = make_tmp_skills()

    tool = LoadSkillTool(reg)

    with pytest.raises(ValueError) as exc:
        await tool.run({"name": "not-exist"})

    msg = str(exc.value)

    assert "alpha" in msg
    assert "beta" not in msg
