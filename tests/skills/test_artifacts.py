from pathlib import Path

import pytest

from src.skills.artifacts import (
    completion_artifact_path,
    resolve_canonical_artifact,
    resolve_project_artifact,
    target_identifier,
)


def test_target_identifier_is_deterministic_and_preserves_nondefault_port():
    assert target_identifier("HTTP://Juice.Lab:3000/") == "juice-lab-3000"
    assert target_identifier("http://juice.lab:3000") == "juice-lab-3000"
    assert target_identifier("http://juice.lab") == "juice-lab"
    assert target_identifier("http://juice.lab:3000") != target_identifier(
        "http://juice.lab"
    )


def test_completion_artifact_path_renders_canonical_relative_path():
    assert completion_artifact_path(
        "artifacts/sql-injection/{target}/results.md", "https://App.Example:8443/"
    ) == "artifacts/sql-injection/app-example-8443/results.md"


def test_completion_artifact_rejects_escape_and_unknown_fields(tmp_path: Path):
    with pytest.raises(ValueError, match="inside the project"):
        resolve_project_artifact(tmp_path, "../outside.md")
    with pytest.raises(ValueError, match=r"only the \{target\} field"):
        completion_artifact_path("{skill}/{target}/results.md", "target.test")


def test_new_artifact_path_is_confined_to_dedicated_root(tmp_path: Path):
    expected = tmp_path / "artifacts/sql-injection/target/results.md"
    assert resolve_canonical_artifact(
        tmp_path, "artifacts/sql-injection/target/results.md"
    ) == expected
    with pytest.raises(ValueError, match="under artifacts"):
        resolve_canonical_artifact(tmp_path, "sql-injection/target/results.md")
    with pytest.raises(ValueError, match="inside the project"):
        resolve_canonical_artifact(tmp_path, "../outside.md")
    with pytest.raises(ValueError, match="under artifacts"):
        resolve_canonical_artifact(tmp_path, "artifacts/../outside.md")
