"""
Test Skill Registry

Kiểm tra:
- Load skill từ thư mục
- Parse YAML frontmatter
- Body tách khỏi metadata
- Sort skill
- Disable / enable skill
"""


from pathlib import Path

import pytest

from skills.registry import (
    Registry,
    parse_skill,
)



# ============================================================
# Lấy thư mục skills
# ============================================================

@pytest.fixture
def skills_dir():

    """
    Giả sử:

    project/
    |
    ├── skills/
    │    ├── recon/
    │    │    └── SKILL.md
    │    ├── webvuln/
    │    └── ssrf/
    |
    └── src/
         └── skills/
              └── test_registry.py

    """

    return (
        Path(__file__)
        .parents[2]
        /
        "skills"
    )



# ============================================================
# Test load skill
# ============================================================


def test_load_recon_webvuln_ssrf(
    skills_dir
):

    r = Registry()

    r.load_dir(
        skills_dir
    )


    names = [
        x.name
        for x in r.list()
    ]


    assert "recon" in names

    assert "webvuln" in names

    assert "ssrf" in names




# ============================================================
# Test body tách frontmatter
# ============================================================


def test_body_separated(
    skills_dir
):

    skill = parse_skill(

        skills_dir
        /
        "recon"
        /
        "SKILL.md"

    )


    assert skill.name == "recon"


    assert len(skill.body) > 100


    assert "---\nname:" not in skill.body





# ============================================================
# Test sort
# ============================================================


def test_list_sorted(
    skills_dir
):

    r = Registry()

    r.load_dir(
        skills_dir
    )


    names = [
        x.name
        for x in r.list()
    ]


    assert names == sorted(names)





# ============================================================
# Test missing directory
# ============================================================


def test_missing_directory():

    r = Registry()


    r.load_dir(
        "/nonexistent/path"
    )


    assert r.list() == []





# ============================================================
# Test disable enable
# ============================================================


def test_disable_enable(
    skills_dir
):

    r = Registry()


    r.load_dir(
        skills_dir
    )


    names = [
        x.name
        for x in r.list()
    ]


    assert "recon" in names



    # disable skill không tồn tại
    assert (
        r.set_disabled(
            "no-such-skill",
            True
        )
        is True
    )



    # disable recon

    assert (
        r.set_disabled(
            "recon",
            True
        )
        is True
    )



    enabled = [
        x.name
        for x in r.list_enabled()
    ]


    assert "recon" not in enabled



    # list vẫn có

    assert (
        "recon"
        in
        [
            x.name
            for x in r.list()
        ]
    )



    assert (
        r.is_disabled(
            "recon"
        )
        is True
    )



    # disable lần nữa không đổi

    assert (
        r.set_disabled(
            "recon",
            True
        )
        is False
    )



    # enable lại

    assert (
        r.set_disabled(
            "recon",
            False
        )
        is True
    )



    assert (
        r.is_disabled(
            "recon"
        )
        is False
    )



# ============================================================
# Test replace disabled names
# ============================================================


def test_set_disabled_names(
    skills_dir
):

    r = Registry()


    r.load_dir(
        skills_dir
    )


    r.set_disabled(
        "recon",
        True
    )



    r.set_disabled_names(
        [
            "ssrf",
            "webvuln"
        ]
    )



    assert (
        r.is_disabled(
            "recon"
        )
        is False
    )


    assert (
        r.is_disabled(
            "ssrf"
        )
        is True
    )


    assert (
        r.is_disabled(
            "webvuln"
        )
        is True
    )



    assert (
        r.disabled_names()
        ==
        [
            "ssrf",
            "webvuln"
        ]
    )