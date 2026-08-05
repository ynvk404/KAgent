import os
import tempfile
from pathlib import Path

from .mentions import (
    find_active_mention,
    parse_mention_path,
    list_mention_dir,
    mention_candidates,
)

def test_find_active_mention_start():
    assert find_active_mention("@READ") == {
        "at": 0,
        "partial": "READ",
    }


def test_find_active_mention_after_space():
    assert find_active_mention("look at @READ") == {
        "at": 8,
        "partial": "READ",
    }


def test_find_active_mention_closed():
    assert find_active_mention(
        "look at @README.md and tell me"
    ) is None


def test_find_active_mention_no_at():
    assert find_active_mention("hello") is None


def test_find_active_mention_email():
    assert find_active_mention(
        "user@example.com"
    ) is None


def test_find_active_mention_url():
    assert find_active_mention(
        "@https://example.com"
    ) is None


def test_find_active_mention_empty():
    assert find_active_mention("@") == {
        "at": 0,
        "partial": "",
    }

    assert find_active_mention("look at @") == {
        "at": 8,
        "partial": "",
    }

def test_parse_path():

    assert parse_mention_path(
        "src/ag"
    ) == (
        "src/",
        "ag",
    )

    assert parse_mention_path(
        "src/"
    ) == (
        "src/",
        "",
    )

    assert parse_mention_path(
        "READ"
    ) == (
        "",
        "READ",
    )

    assert parse_mention_path("") == (
        "",
        "",
    )


def test_parse_parent():

    assert parse_mention_path("../") == (
        "../",
        "",
    )

    assert parse_mention_path("../tools/x") == (
        "../tools/",
        "x",
    )

    assert parse_mention_path("../../tools/") == (
        "../../tools/",
        "",
    )


def test_parse_absolute():

    assert parse_mention_path("/etc/host") == (
        "/etc/",
        "host",
    )

def test_list_dir():

    with tempfile.TemporaryDirectory() as root:

        root = Path(root)

        (root / "src").mkdir()
        (root / "src" / "agent").mkdir()

        (root / "src" / "agent" / "agent.ts").write_text("//")
        (root / "src" / "agent" / "mentions.ts").write_text("//")
        (root / "README.md").write_text("#")
        (root / ".hidden").write_text("x")

        old = Path.cwd()

        try:
            os.chdir(root)

            out = list_mention_dir("", "", 20)

            names = [x.display for x in out]

            assert "README.md" in names
            assert "src/" in names
            assert ".hidden" not in names

        finally:
            os.chdir(old)


def test_hidden():

    with tempfile.TemporaryDirectory() as root:

        root = Path(root)

        (root / ".hidden").write_text("x")

        old = Path.cwd()

        try:
            os.chdir(root)

            out = list_mention_dir("", ".", 20)

            names = [x.display for x in out]

            assert ".hidden" in names

        finally:
            os.chdir(old)

def test_candidates():

    with tempfile.TemporaryDirectory() as tmp:

        tmp = Path(tmp)

        (tmp / "unique-thing.txt").write_text("x")

        old = Path.cwd()

        try:
            os.chdir(tmp)

            out = mention_candidates(
                "unique",
                5,
            )

            assert len(out) == 1
            assert out[0] == "unique-thing.txt"

        finally:
            os.chdir(old)