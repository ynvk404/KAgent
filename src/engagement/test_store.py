from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from src.engagement.store import (
    ENGAGEMENT_CHAR_LIMIT,
    EngagementStore,
)


@pytest.fixture
def temp_dirs():
    with tempfile.TemporaryDirectory(prefix="pf-engage-cwd-") as cwd, \
         tempfile.TemporaryDirectory(prefix="pf-engage-home-") as home:
        yield Path(cwd), Path(home)


def write_engagement(root: Path, body: str) -> None:
    directory = root / ".kagent"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "engagement.md").write_text(body, encoding="utf-8")


def test_returns_empty_string_when_no_files_exist(temp_dirs):
    cwd, home = temp_dirs

    assert EngagementStore(cwd=cwd, home=home).load() == ""


def test_merges_personal_then_project_notes(temp_dirs):
    cwd, home = temp_dirs

    write_engagement(home, "Global rule: stay in scope")
    write_engagement(cwd, "Target: app.example.com only")

    out = EngagementStore(cwd=cwd, home=home).load()

    assert out.index("Global rule") < out.index("Target: app.example.com")


def test_loads_project_notes_even_when_personal_is_absent(temp_dirs):
    cwd, home = temp_dirs

    write_engagement(cwd, "Out of scope: *.corp.internal")

    out = EngagementStore(cwd=cwd, home=home).load()

    assert "Out of scope: *.corp.internal" in out


def test_truncates_combined_notes_past_char_limit_with_marker(temp_dirs):
    cwd, home = temp_dirs

    write_engagement(cwd, "x" * (ENGAGEMENT_CHAR_LIMIT + 500))

    out = EngagementStore(cwd=cwd, home=home).load()

    assert len(out) <= ENGAGEMENT_CHAR_LIMIT
    assert "engagement notes truncated" in out


def test_truncation_preserves_project_scope_after_large_personal_notes(temp_dirs):
    cwd, home = temp_dirs
    project_scope = "Out of scope: *.corp.internal"

    write_engagement(home, "x" * ENGAGEMENT_CHAR_LIMIT)
    write_engagement(cwd, project_scope)

    out = EngagementStore(cwd=cwd, home=home).load()

    assert project_scope in out
    assert len(out) <= ENGAGEMENT_CHAR_LIMIT
    assert "engagement notes truncated" in out


def test_same_personal_and_project_file_is_not_duplicated(tmp_path):
    write_engagement(tmp_path, "Target: app.example.com only")

    out = EngagementStore(cwd=tmp_path, home=tmp_path).load()

    assert out == "Target: app.example.com only"


def test_invalid_utf8_notes_are_logged_and_ignored(tmp_path, caplog):
    import logging

    project = tmp_path / "project"
    notes = project / ".kagent" / "engagement.md"
    notes.parent.mkdir(parents=True)
    notes.write_bytes(b"\xff\xfe")

    with caplog.at_level(logging.WARNING, logger="kagent.engagement.store"):
        loaded = EngagementStore(cwd=project, home=tmp_path / "home").load()

    assert loaded == ""
    assert any("engagement.md" in record.getMessage() for record in caplog.records)

def test_unreadable_notes_are_reported_not_silently_dropped(tmp_path, caplog):
    import logging

    project = tmp_path / "project"
    (project / ".kagent").mkdir(parents=True)
    notes = project / ".kagent" / "engagement.md"
    notes.write_text("in scope: example.com", encoding="utf-8")
    notes.chmod(0o000)

    try:
        with caplog.at_level(logging.WARNING, logger="kagent.engagement.store"):
            loaded = EngagementStore(cwd=project, home=tmp_path / "home").load()
    finally:
        notes.chmod(0o600)

    assert loaded == ""
    assert any("engagement.md" in r.getMessage() for r in caplog.records)
