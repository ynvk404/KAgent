"""Version lookup and CLI reporting use project metadata consistently."""
from __future__ import annotations

import importlib
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
version_module = importlib.import_module("src.version")


def test_version_lookup_prefers_installed_distribution_metadata(monkeypatch):
    monkeypatch.setattr(version_module.metadata, "version", lambda name: "9.8.7")

    assert version_module.get_version() == "9.8.7"


def test_version_lookup_falls_back_to_source_pyproject(tmp_path, monkeypatch):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "kagent"\nversion = "3.4.5"\n', encoding="utf-8"
    )
    monkeypatch.setattr(version_module, "__file__", str(source_dir / "version.py"))

    def package_missing(name: str) -> str:
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr(version_module.metadata, "version", package_missing)

    assert version_module.get_version() == "3.4.5"


def test_version_lookup_uses_unknown_when_metadata_and_pyproject_are_missing(
    tmp_path, monkeypatch
):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    monkeypatch.setattr(version_module, "__file__", str(source_dir / "version.py"))

    def package_missing(name: str) -> str:
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr(version_module.metadata, "version", package_missing)

    assert version_module.get_version() == "unknown"


def test_cli_version_flag_reports_project_version():
    result = subprocess.run(
        [sys.executable, "-m", "src.cli.main", "--version"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.strip() == version_module.describe()
