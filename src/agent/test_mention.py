import os
import tempfile
from pathlib import Path

from . import mentions
from .mentions import (
    INLINE_BYTE_CAP,
    expand_file_mentions,
    find_active_mention,
    parse_mention_path,
    list_mention_dir,
    mention_candidates,
    resolve_mention,
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

def test_expand_file_mentions_refuses_sensitive_paths():
    with tempfile.TemporaryDirectory() as tmp:
        secret = Path(tmp) / ".env"
        secret.write_text("OPENAI_API_KEY=sk-live-do-not-leak\n")

        out = expand_file_mentions(f"look at @{secret}")

        assert "sk-live-do-not-leak" not in out
        assert "Refusing to inline sensitive path" in out


def test_expand_file_mentions_still_inlines_regular_files():
    with tempfile.TemporaryDirectory() as tmp:
        note = Path(tmp) / "note.txt"
        note.write_text("plain content\n")

        out = expand_file_mentions(f"look at @{note}")

        assert "plain content" in out


def test_expand_file_mentions_reads_only_the_inline_cap_for_large_files(
    tmp_path,
    monkeypatch,
):
    large = tmp_path / "large.txt"
    extra = 4096
    large.write_bytes(b"a" * (INLINE_BYTE_CAP + extra))
    original_open = open
    reads: list[int] = []

    class TrackingReader:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            self.file.__enter__()
            return self

        def __exit__(self, *args):
            return self.file.__exit__(*args)

        def read(self, size=-1):
            reads.append(size)
            return self.file.read(size)

    def tracked_open(*args, **kwargs):
        return TrackingReader(original_open(*args, **kwargs))

    monkeypatch.setattr(mentions, "open", tracked_open, raising=False)

    out = expand_file_mentions(f"look at @{large}")

    assert reads == [INLINE_BYTE_CAP]
    assert f"[... truncated {extra} bytes ...]" in out
    assert "a" * INLINE_BYTE_CAP in out


def test_positive_basename_cache_refreshes_after_cooldown(tmp_path, monkeypatch):
    first = tmp_path / "a"
    first.mkdir()
    (first / "config.py").write_text("first")

    monkeypatch.setattr(mentions, "mention_index", None)
    monkeypatch.setattr(mentions, "index_cwd", "")
    monkeypatch.chdir(tmp_path)

    resolved, note = resolve_mention("config.py")

    assert note == ""
    assert resolved == str(first / "config.py")

    second = tmp_path / "b"
    second.mkdir()
    (second / "config.py").write_text("second")
    monkeypatch.setattr(mentions, "index_built_at", 0)

    resolved, note = resolve_mention("config.py")

    assert resolved == ""
    assert "Ambiguous file mention" in note
    assert str(first / "config.py") in note
    assert str(second / "config.py") in note


def test_walk_closes_scandir_iterator_when_an_index_cap_is_reached(
    monkeypatch,
):
    class TrackingScandir:
        entered = False
        exited = False
        yielded = False

        def __enter__(self):
            self.entered = True
            return self

        def __exit__(self, *args):
            self.exited = True

        def __iter__(self):
            return self

        def __next__(self):
            if self.yielded == 2:
                raise StopIteration
            self.yielded += 1
            return type(
                "Entry",
                (),
                {
                    "is_dir": lambda *_args, **_kwargs: False,
                    "is_file": lambda *_args, **_kwargs: True,
                    "name": "entry.txt",
                    "path": "/unused/entry.txt",
                },
            )()

    entries = TrackingScandir()
    monkeypatch.setattr(mentions.os, "scandir", lambda _: entries)

    mentions.walk(
        "/unused",
        {},
        {"files": mentions.INDEX_FILE_CAP - 1, "dirs": 0},
        depth=0,
    )

    assert entries.entered is True
    assert entries.exited is True
