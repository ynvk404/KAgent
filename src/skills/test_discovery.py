"""
Test cho skill discovery

Port từ discovery.test.ts của KAgent

Kiểm tra:
- thứ tự ưu tiên thư mục skill
- project local
- user skill
- configured skill

Lưu ý:
Dùng Path.resolve() để tương thích Windows/Linux
"""

from pathlib import Path

from src.skills.discovery import skill_search_dirs


# ============================================================
# Test thứ tự ưu tiên
# ============================================================

def test_skill_search_dirs_order():
    """
    builtin → project → managed → personal → configured

    Thư mục phía sau có quyền override phía trước
    """

    dirs = skill_search_dirs(
        ["/cfg/skills"],
        "/proj",
        "/home"
    )


    assert dirs == [

        str(Path("/proj/skills").resolve()),

        str(Path("/proj/.kagent/skills").resolve()),

        str(Path("/home/.kagent/builtin-skills").resolve()),

        str(Path("/home/.kagent/skills").resolve()),

        str(Path("/cfg/skills").resolve())

    ]



# ============================================================
# Test chứa các thư mục mặc định
# ============================================================

def test_contains_default_skill_dirs():

    dirs = skill_search_dirs(
        [],
        "/proj",
        "/home"
    )


    assert str(
        Path("/proj/.kagent/skills").resolve()
    ) in dirs


    assert str(
        Path("/home/.kagent/builtin-skills").resolve()
    ) in dirs


    assert str(
        Path("/home/.kagent/skills").resolve()
    ) in dirs



# ============================================================
# Test configured đứng cuối
# ============================================================

def test_configured_dirs_have_highest_priority():

    dirs = skill_search_dirs(
        [
            "/a",
            "/b"
        ],
        "/proj",
        "/home"
    )


    assert dirs[-2:] == [

        str(Path("/a").resolve()),

        str(Path("/b").resolve())

    ]