"""Full cleanup removes only declared project outputs; never follows symlinks."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/cleanup.py"


def put(root: Path, relative: str, content: str = "fixture") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def project(root: Path) -> Path:
    put(root, "pyproject.toml", "[project]\nname='kagent'\n")
    put(root, "AGENTS.md")
    put(root, "src/paths.py")
    destination = root / "scripts/cleanup.py"
    destination.parent.mkdir(parents=True)
    shutil.copyfile(SCRIPT, destination)
    return root


def cleanup(root: Path, *args: str):
    return subprocess.run([sys.executable, str(root / "scripts/cleanup.py"), *args],
                          cwd=root, text=True, capture_output=True)


def outputs(root: Path) -> list[Path]:
    return [put(root, relative) for relative in (
        "docs/agent-assessed-evidence.md", "docs/old/nested/handoff.md",
        "artifacts/audits/old/report.md", "artifacts/reports/old.pdf",
        "artifacts/checkpoints/snapshot.zip", "artifacts/findings/finding.md",
        "artifacts/benchmarks/run/report/table.csv", "artifacts/runs/archive/run.json",
        "artifacts/.hidden-output", "logs/agent.log", "htmlcov/index.html",
        "benchmarks/scenario1/reset/evidence/source-boundary.json",
        "benchmarks/scenario1/reset/evidence/final-focused/verification.json",
        ".kagent/evidence/proof.proof", ".kagent/observations/run.json",
        ".kagent/permissions/run.json", ".kagent/sessions/run.json",
        ".kagent/coverage/run.json", ".kagent/context/run.json",
        ".kagent/tool-results/run/data.txt", ".kagent/reasoning-run.jsonl",
        ".kagent/benchmark-prep.json", ".kagent/metrics.jsonl",
        ".kagent/.kagent.cfg.tmp.fixture", ".kagent.cfg.tmp.fixture",
        "findings/legacy.md", "sessions/legacy.json", "reports/old.pdf",
        "evidence/old.proof", "captures/old.json", "sql-injection/old.md",
        ".pytest_cache/nodeids", ".mypy_cache/cache.json", ".ruff_cache/cache",
        ".coverage", ".coverage.parallel",
        "src/ui/__pycache__/old.cpython-314.pyc", "src/stray.pyc",
        "tests/__pycache__/old.pyc", "scripts/__pycache__/old.pyc",
        "benchmarks/__pycache__/old.pyc", "__pycache__/old.pyc",
    )]


def protected(root: Path) -> list[Path]:
    return [put(root, relative, f"preserve {relative}") for relative in (
        "src/ui/app.py", "src/report/model.py", "tests/test_report.py",
        "skills/recon/SKILL.md", "skills/sql-injection/payloads.txt",
        "components/cwe_mcp/server.py", "integrations/burp/kagent_burp.py",
        "benchmarks/scenario1/core/dataset.py", "benchmarks/docs/scenario1.md",
        "benchmarks/scenario1/reset/java/ResetGate.java",
        "benchmarks/scenario1/reset/evidence/.gitignore",
        ".kagent/config.json", ".kagent/memory/notes.md",
        ".kagent/intelligence/scenarios.jsonl", ".kagent/engagement.md",
        ".kagent/skills/personal/SKILL.md", "config.local.json", ".env",
        ".git/HEAD", ".vscode/settings.json", "assets/logo.png",
        "venv-linux/lib/__pycache__/dependency.pyc", "venv/bin/python",
        ".coverage_policy", "readme.md", "requirements.txt",
    )]


def test_cleanup_removes_all_outputs_preserves_inputs_and_is_repeatable(tmp_path):
    root = project(tmp_path / "repo")
    disposable = outputs(root)
    keep = protected(root)
    before = {p: p.read_bytes() for p in keep}
    result = cleanup(root)
    assert result.returncode == 0, result.stderr
    assert all(not p.exists() for p in disposable)
    assert {p: p.read_bytes() for p in keep} == before
    assert (root / "scripts/cleanup.py").read_bytes() == SCRIPT.read_bytes()
    second = cleanup(root)
    assert second.returncode == 0, second.stderr
    assert "Removed 0 files" in second.stdout


def test_dry_run_and_help_do_not_modify_files(tmp_path):
    root = project(tmp_path / "repo")
    files = outputs(root) + protected(root)
    before = {p: p.read_bytes() for p in files}
    result = cleanup(root, "--dry-run")
    assert result.returncode == 0, result.stderr
    assert "[DRY-RUN] docs" in result.stdout
    assert "[DRY-RUN] artifacts" in result.stdout
    assert "Would remove" in result.stdout
    assert cleanup(root, "--help").returncode == 0
    assert {p: p.read_bytes() for p in files} == before


@pytest.mark.parametrize("relative", ["docs", "artifacts", ".kagent", "benchmarks/scenario1"])
def test_symlink_root_or_parent_blocks_entire_cleanup_before_mutation(tmp_path, relative):
    root = project(tmp_path / "repo")
    sentinel = put(root, "artifacts/reports/sentinel.pdf") if relative != "artifacts" else put(root, "docs/sentinel.md")
    outside = tmp_path / "outside"
    other = put(outside, "evidence/keep.json")
    link = root / relative
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(outside, target_is_directory=True)
    result = cleanup(root)
    assert result.returncode != 0
    assert "symlink" in result.stderr
    assert sentinel.read_text() == "fixture"
    assert other.read_text() == "fixture"


def test_nested_symlinks_are_unlinked_without_deleting_external_data(tmp_path):
    root = project(tmp_path / "repo")
    external = put(tmp_path / "outside", "keep.md")
    artifact = root / "artifacts/linked"
    artifact.parent.mkdir()
    artifact.symlink_to(external.parent, target_is_directory=True)
    evidence = root / "benchmarks/scenario1/reset/evidence/linked.json"
    evidence.parent.mkdir(parents=True)
    evidence.symlink_to(external)
    result = cleanup(root)
    assert result.returncode == 0, result.stderr
    assert not artifact.is_symlink() and not evidence.is_symlink()
    assert external.read_text() == "fixture"


def test_rejects_other_working_directory_and_unknown_flags(tmp_path):
    result = subprocess.run([sys.executable, str(SCRIPT)], cwd=tmp_path, text=True, capture_output=True)
    assert result.returncode != 0
    assert "repository root" in result.stderr
    root = project(tmp_path / "repo")
    sentinel = put(root, "docs/keep.md")
    assert cleanup(root, "--path", "/").returncode != 0
    assert sentinel.exists()


@pytest.mark.skipif(os.name != "posix", reason="benchmark runner uses POSIX flock")
@pytest.mark.parametrize("scope", ["all", "benchmark"])
def test_active_runner_lock_blocks_all_deletion(tmp_path, scope):
    import fcntl
    root = project(tmp_path / "repo")
    sentinel = put(root, "docs/keep.md")
    transient = put(root, ".kagent/evidence/keep.proof")
    lock = put(root, "artifacts/benchmarks/target.runner.lock", "")
    with lock.open("rb") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = cleanup(root, "--scope", scope)
        assert result.returncode != 0
        assert "benchmark is running" in result.stderr
        assert sentinel.exists() and transient.exists() and lock.exists()
    assert cleanup(root, "--scope", scope).returncode == 0
    assert not transient.exists() and not lock.exists()


@pytest.mark.parametrize("mode", ["smoke", "official"])
def test_benchmark_cli_requires_no_deleted_historical_audit(mode):
    from benchmarks.scenario1.__main__ import parser
    args = ["run", "--mode", mode, "--dataset", "fixture", "--manifest", "fixture/selection.json",
            "--target", "http://127.0.0.1:3000", "--context-path", "/benchmark",
            "--target-state", "external-reset"]
    assert parser().parse_args(args).reset_audit is None
    assert parser().parse_args([*args, "--reset-audit", "external/audit.json"]).reset_audit == Path("external/audit.json")


@pytest.mark.parametrize("scope", ["runtime", "benchmark"])
def test_narrow_scopes_preserve_history_inputs_and_durable_state(tmp_path, scope):
    root = project(tmp_path / "repo")
    keep = protected(root)
    keep += [put(root, name) for name in (
        "docs/current.md", "artifacts/audits/report.md", "artifacts/checkpoints/backup.zip",
        "artifacts/runs/archive/session.json", "artifacts/unknown/keep.txt",
        "benchmarks/scenario1/reset/evidence/historical.json", "src/__pycache__/cache.pyc",
        ".kagent/intelligence/scenarios.jsonl.lock",
    )]
    transient = [put(root, name) for name in (
        ".kagent/coverage/session.json", ".kagent/evidence/proof.proof",
        ".kagent/observations/session.json", ".kagent/permissions/session.json",
        ".kagent/sessions/session.json", ".kagent/context/session.md",
        ".kagent/tool-results/session/full.txt", ".kagent.cfg.tmp.test",
        ".kagent/.kagent.cfg.tmp.test", "artifacts/recon/target/results.md",
        "artifacts/xxe/results.md", "artifacts/worker/log.txt", "artifacts/findings/finding.md",
    )]
    benchmark = [put(root, name) for name in (
        ".kagent/benchmark-prep.json", ".kagent/reasoning-run.jsonl",
        ".kagent/metrics.jsonl", "artifacts/benchmarks/run/report.csv",
    )]
    before = {p: p.read_bytes() for p in keep}
    everything = {p: p.read_bytes() for p in keep + transient + benchmark}
    result = cleanup(root, "--scope", scope, "--dry-run")
    assert result.returncode == 0, result.stderr
    assert {p: p.read_bytes() for p in everything} == everything
    result = cleanup(root, "--scope", scope)
    assert result.returncode == 0, result.stderr
    assert all(not p.exists() for p in transient)
    assert {p: p.read_bytes() for p in keep} == before
    assert all(p.exists() == (scope == "runtime") for p in benchmark)
    assert (root / ".kagent/coverage").is_dir()
    assert (root / "artifacts/recon").is_dir()
    assert cleanup(root, "--scope", scope).returncode == 0


@pytest.mark.parametrize("scope", ["all", "benchmark"])
def test_intelligence_reset_is_explicit_scoped_and_dry_run_safe(tmp_path, scope):
    root = project(tmp_path / "repo")
    intelligence = [put(root, ".kagent/intelligence/" + name) for name in (
        "scenarios.jsonl", "scenarios.jsonl.lock",
    )]
    keep = [put(root, name) for name in (
        ".kagent/memory/notes.md", ".kagent/intelligence/custom-notes.md",
        ".kagent/engagement.md", ".kagent/skills/custom/SKILL.md",
    )]
    args = ("--scope", scope, "--reset-intelligence")
    result = cleanup(root, *args, "--dry-run")
    assert result.returncode == 0, result.stderr
    assert all(p.exists() for p in intelligence + keep)
    result = cleanup(root, *args)
    assert result.returncode == 0, result.stderr
    assert all(not p.exists() for p in intelligence)
    assert all(p.exists() for p in keep)


def test_runtime_scope_cannot_reset_intelligence(tmp_path):
    root = project(tmp_path / "repo")
    sentinel = put(root, ".kagent/evidence/keep.proof")
    result = cleanup(root, "--scope", "runtime", "--reset-intelligence")
    assert result.returncode != 0
    assert "requires --scope benchmark or all" in result.stderr
    assert sentinel.exists()


@pytest.mark.parametrize("scope", ["runtime", "benchmark"])
def test_narrow_scope_rejects_symlink_before_deleting_state(tmp_path, scope):
    root = project(tmp_path / "repo")
    sentinel = put(root, ".kagent/evidence/keep.proof")
    external = put(tmp_path / "outside", "keep.md")
    link = root / "artifacts/recon"
    link.parent.mkdir()
    link.symlink_to(external.parent, target_is_directory=True)
    result = cleanup(root, "--scope", scope)
    assert result.returncode != 0
    assert "symlink" in result.stderr
    assert sentinel.exists() and external.exists()
