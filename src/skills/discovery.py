"""
Skill discovery

Port từ KAgent discovery.ts

Chức năng:
- Xác định các thư mục chứa skill
- Quy định thứ tự ưu tiên khi load skill

Thứ tự:
1. ./skills                (built-in)
2. ./.kagent/skills (project local)
3. ~/.kagent/builtin-skills
4. ~/.kagent/skills
5. thư mục cấu hình thêm

Skill load sau sẽ ghi đè skill trước
"""

from pathlib import Path
from typing import Iterable


# ============================================================
# Built-in skills
# ============================================================

def builtin_skills_dir() -> str:
    """
    Thư mục skill mặc định của project.

    Tương đương:

    resolve(process.cwd(), 'skills')
    """

    return str(
        Path.cwd() / "skills"
    )


# ============================================================
# Search directories
# ============================================================

def skill_search_dirs(
    configured: list[str] | None = None,
    cwd: str | None = None,
    home: str | None = None,
) -> list[str]:
    """
    Trả về danh sách thư mục tìm skill.

    Thứ tự quan trọng:
    - phía sau override phía trước
    - giống Registry.add() trong TS
    """

    if configured is None:
        configured = []

    if cwd is None:
        cwd = str(Path.cwd())

    if home is None:
        home = str(Path.home())


    dirs = [

        # built-in project skills
        Path(cwd) / "skills",


        # skill riêng của project
        Path(cwd)
        / ".kagent"
        / "skills",


        # skill cài bởi installer
        Path(home)
        / ".kagent"
        / "builtin-skills",


        # skill cá nhân
        Path(home)
        / ".kagent"
        / "skills",
    ]


    # skill truyền thêm từ config
    dirs.extend(
        Path(d)
        for d in configured
    )


    return [
        str(d.resolve())
        for d in dirs
    ]