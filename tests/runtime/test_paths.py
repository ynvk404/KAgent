from pathlib import Path

import pytest

from src.engagement.store import EngagementStore
from src.intelligence.store import IntelligenceScenario, IntelligenceStore
from src.memory.store import AddMemoryInput, MemoryStore
from src.paths import (
    legacy_project_data_root,
    project_data_root,
    project_root,
    user_data_root,
)


@pytest.fixture
def marked_project(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "project"
    nested = root / "src" / "package"
    nested.mkdir(parents=True)
    (root / ".git").mkdir()
    return root, nested


def test_project_paths_are_stable_from_nested_working_directories(
    marked_project: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, nested = marked_project

    for working_dir in (root, root / "src", nested):
        monkeypatch.chdir(working_dir)
        assert project_root() == root
        assert project_data_root() == root / ".kagent"


def test_markerless_directory_is_its_own_project_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("src.paths.PROJECT_MARKERS", (".never-a-project-marker",))
    project = tmp_path / "markerless"
    project.mkdir()

    assert project_root(project) == project
    assert legacy_project_data_root(project) is None


def test_project_root_environment_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "explicit-root"
    nested = tmp_path / "elsewhere" / "src"
    root.mkdir()
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    monkeypatch.setenv("KAGENT_PROJECT_ROOT", str(root))

    assert project_root() == root
    assert project_data_root() == root / ".kagent"


def test_user_data_root_is_independent_of_cwd(
    marked_project: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _, nested = marked_project
    home = tmp_path / "home"
    monkeypatch.chdir(nested)

    assert user_data_root(home) == home / ".kagent"


@pytest.mark.asyncio
async def test_stores_write_to_project_root_not_nested_cwd(
    marked_project: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, nested = marked_project
    home = tmp_path / "home"
    monkeypatch.chdir(nested)

    intelligence = IntelligenceStore(home=home)
    memory = MemoryStore(home=str(home))
    engagement = EngagementStore(home=home)

    await intelligence.append(IntelligenceScenario(id="path-test", title="Path test"))
    memory.add(AddMemoryInput(text="project path test"))

    assert intelligence.project_path == root / ".kagent/intelligence/scenarios.jsonl"
    assert memory.project_dir == root / ".kagent/memory"
    assert engagement.project_path == root / ".kagent/engagement.md"
    assert not (nested / ".kagent").exists()


def test_legacy_nested_project_data_remains_readable(
    marked_project: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, nested = marked_project
    monkeypatch.chdir(nested)
    legacy = nested / ".kagent" / "engagement.md"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("legacy nested rule", encoding="utf-8")

    store = EngagementStore(home=tmp_path / "home")

    assert store.project_path == root / ".kagent" / "engagement.md"
    assert "legacy nested rule" in store.load()
