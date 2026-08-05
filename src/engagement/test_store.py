from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from src.engagement.store import (
    ENGAGEMENT_CHAR_LIMIT,
    EngagementStore,
)


# ==========================================================
# Fixtures
# ==========================================================

@pytest.fixture
def temp_dirs():
    with tempfile.TemporaryDirectory(prefix="pf-engage-cwd-") as cwd, \
         tempfile.TemporaryDirectory(prefix="pf-engage-home-") as home:
        yield Path(cwd), Path(home)


# ==========================================================
# Helpers
# ==========================================================

def write_engagement(root: Path, body: str) -> None:
    directory = root / ".kagent"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "engagement.md").write_text(body, encoding="utf-8")


# ==========================================================
# Tests
# ==========================================================

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

    assert len(out) < ENGAGEMENT_CHAR_LIMIT + 200
    assert "engagement notes truncated" in out