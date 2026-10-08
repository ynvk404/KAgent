"""Keep new benchmark canonical storage inside each test's temporary project."""
import pytest


@pytest.fixture(autouse=True)
def benchmark_project_root(tmp_path, monkeypatch):
    monkeypatch.setenv('KAGENT_PROJECT_ROOT', str(tmp_path))
