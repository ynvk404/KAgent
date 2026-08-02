from __future__ import annotations

"""
Skill Registry

Chức năng:
- Quản lý danh sách skill
- Load skill từ thư mục
- Parse SKILL.md có YAML frontmatter
- Enable / disable skill
- Render skill body cho LLM
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import re
import yaml


# ============================================================
# Model
# ============================================================

@dataclass
class Skill:
    """
    Một skill của Agent.

    Mỗi skill:
    - có tên
    - mô tả
    - danh sách tool được phép
    - đường dẫn file
    - nội dung markdown
    """
    name: str
    description: str
    tools: list[str]
    disable_model_invocation: bool
    path: str
    body: str


# ============================================================
# Registry
# ============================================================

class Registry:

    def __init__(self):
        # lưu skill
        self.skills: dict[str, Skill] = {}
        # skill bị disable
        self.disabled: set[str] = set()

    # --------------------------------------------------------
    # Add
    # --------------------------------------------------------

    def add(self, skill: Skill):
        """Thêm skill vào registry."""
        self.skills[skill.name] = skill

    # --------------------------------------------------------
    # Get
    # --------------------------------------------------------

    def get(self, name: str) -> Skill | None:
        return self.skills.get(name)

    # --------------------------------------------------------
    # Has
    # --------------------------------------------------------

    def has(self, name: str) -> bool:
        return name in self.skills

    # --------------------------------------------------------
    # List
    # --------------------------------------------------------

    def list(self) -> list[Skill]:
        """Trả về toàn bộ skill."""
        return sorted(
            self.skills.values(),
            key=lambda x: x.name
        )

    # --------------------------------------------------------
    # Enabled skills
    # --------------------------------------------------------

    def list_enabled(self) -> list[Skill]:
        """Skill model được phép nhìn thấy."""
        return [
            skill
            for skill in self.list()
            if skill.name not in self.disabled
        ]

    # --------------------------------------------------------
    # Disabled persistence
    # --------------------------------------------------------

    def set_disabled_names(self, names: Iterable[str]):
        self.disabled = set(names)

    def disabled_names(self) -> list[str]:
        return sorted(self.disabled)

    def is_disabled(self, name: str) -> bool:
        return name in self.disabled

    # --------------------------------------------------------
    # Clear
    # --------------------------------------------------------

    def clear(self):
        """
        Xóa toàn bộ skill.
        Không xóa disabled.
        """
        self.skills.clear()

    # --------------------------------------------------------
    # Enable / Disable
    # --------------------------------------------------------

    def set_disabled(self, name: str, on: bool) -> bool:
        old = name in self.disabled

        if on and not old:
            self.disabled.add(name)
            return True

        if not on and old:
            self.disabled.remove(name)
            return True

        return False

    # --------------------------------------------------------
    # Load directory
    # --------------------------------------------------------

    def load_dir(self, directory: str | Path):
        """
        Load:

        skills/
          sqlmap/
             SKILL.md
          nmap/
             SKILL.md
        """
        directory = Path(directory)

        if not directory.exists():
            return

        try:
            entries = directory.iterdir()
        except Exception:
            return

        for item in entries:
            # bỏ file ẩn
            if item.name.startswith("."):
                continue

            # bỏ template
            if item.name.startswith("_"):
                continue

            if not item.is_dir():
                continue

            skill_file = item / "SKILL.md"

            if not skill_file.exists():
                continue

            try:
                skill = parse_skill(skill_file)
                self.add(skill)
            except Exception as e:
                print(f"[skills] skip {skill_file}: {e}")


# ============================================================
# Parse SKILL.md
# ============================================================

def parse_skill(path: str | Path) -> Skill:
    path = Path(path)
    raw = path.read_text(encoding="utf-8")

    # tách YAML frontmatter
    metadata = {}
    body = raw

    if raw.startswith("---"):
        parts = raw.split("---", 2)
        if len(parts) >= 3:
            metadata = yaml.safe_load(parts[1]) or {}
            body = parts[2]

    name = metadata.get("name")
    if not name:
        name = path.parent.name

    description = metadata.get("description", "")

    # allowed-tools
    # hỗ trợ:
    # allowed-tools
    # allowedTools
    # tools
    tools = (
        metadata.get("allowed-tools")
        or metadata.get("allowedTools")
        or metadata.get("tools")
        or []
    )

    if not isinstance(tools, list):
        tools = []

    tools = [x for x in tools if isinstance(x, str)]

    disable = (
        metadata.get("disable-model-invocation") is True
        or metadata.get("disableModelInvocation") is True
    )

    return Skill(
        name=name,
        description=description,
        tools=tools,
        disable_model_invocation =disable,
        path=str(path),
        body=body.lstrip("\n")
    )


# ============================================================
# Materialize body
# ============================================================

def materialize_skill_body(skill: Skill) -> str:
    """
    Thay:
    ${SKILL_DIR}
    bằng path thật.
    """
    directory = str(Path(skill.path).parent)
    body = skill.body.replace("${SKILL_DIR}", directory)

    return f"# Skill: {skill.name}\n\n" + body


# ============================================================
# Factory
# ============================================================

def new_registry():
    return Registry()