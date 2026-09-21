from pathlib import Path

from src.skills.discovery import skill_search_dirs

def test_skill_search_dirs_order():
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


def test_relative_configured_dirs_resolve_from_supplied_cwd(monkeypatch):
    monkeypatch.chdir("/")

    dirs = skill_search_dirs(["custom-skills"], "/project", "/home")

    assert dirs[-1] == "/project/custom-skills"
