from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"


def test_scripts_syntax():
    scripts = [
        SCRIPTS_DIR / "lib" / "cleanup-common.sh",
        SCRIPTS_DIR / "reset-runtime.sh",
        SCRIPTS_DIR / "reset-benchmark.sh",
    ]
    for script in scripts:
        assert script.exists(), f"Script {script} does not exist"
        res = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert res.returncode == 0, f"Syntax check failed for {script}: {res.stderr}"


def test_fails_outside_repo_root(tmp_path: Path):
    res = subprocess.run(
        [str(SCRIPTS_DIR / "reset-runtime.sh")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0
    assert "must be executed from the KAgent repository root" in res.stderr


def _setup_mock_repo(root: Path) -> None:
    # Markers
    (root / "pyproject.toml").write_text("[project]\nname='kagent'\n", encoding="utf-8")
    (root / "AGENTS.md").write_text("# Guide\n", encoding="utf-8")
    (root / "src").mkdir(parents=True)
    (root / "src" / "paths.py").write_text("APP_DIR_NAME = '.kagent'\n", encoding="utf-8")

    # Copy scripts into mock repo
    shutil.copytree(SCRIPTS_DIR, root / "scripts")

    # Create transient runtime files
    (root / ".kagent" / "coverage").mkdir(parents=True)
    (root / ".kagent" / "coverage" / "session1.json").write_text("{}", encoding="utf-8")

    (root / ".kagent" / "evidence" / "hash123").mkdir(parents=True)
    (root / ".kagent" / "evidence" / "hash123" / "proof.proof").write_text("proof", encoding="utf-8")

    (root / ".kagent" / "observations").mkdir(parents=True)
    (root / ".kagent" / "observations" / "obs1.json").write_text("{}", encoding="utf-8")

    (root / ".kagent" / "permissions").mkdir(parents=True)
    (root / ".kagent" / "permissions" / "perm1.json").write_text("{}", encoding="utf-8")

    (root / ".kagent.cfg.tmp.12345").write_text("tmp", encoding="utf-8")

    # Skill artifacts
    (root / "artifacts" / "recon" / "target-1").mkdir(parents=True)
    (root / "artifacts" / "recon" / "target-1" / "summary.md").write_text("recon", encoding="utf-8")
    (root / "artifacts" / "sql-injection").mkdir(parents=True)
    (root / "artifacts" / "sql-injection" / "results.md").write_text("results", encoding="utf-8")
    (root / "artifacts" / "findings").mkdir(parents=True)
    (root / "artifacts" / "findings" / "sqli-vuln.md").write_text("finding", encoding="utf-8")
    (root / "artifacts" / "worker").mkdir(parents=True)
    (root / "artifacts" / "worker" / "log.txt").write_text("log", encoding="utf-8")

    # Protected paths
    (root / ".kagent" / "intelligence").mkdir(parents=True)
    (root / ".kagent" / "intelligence" / "scenarios.jsonl").write_text('{"id": 1}\n', encoding="utf-8")
    (root / ".kagent" / "intelligence" / "scenarios.jsonl.lock").write_text("", encoding="utf-8")

    (root / ".kagent" / "memory").mkdir(parents=True)
    (root / ".kagent" / "memory" / "note.md").write_text("memory", encoding="utf-8")

    (root / ".kagent" / "engagement.md").write_text("# scope\n", encoding="utf-8")

    (root / "artifacts" / "audits" / "milestone-1").mkdir(parents=True)
    (root / "artifacts" / "audits" / "milestone-1" / "REPORT.md").write_text("audit", encoding="utf-8")

    (root / "artifacts" / "checkpoints").mkdir(parents=True)
    (root / "artifacts" / "checkpoints" / "stage.zip").write_text("zip", encoding="utf-8")

    (root / "benchmarks" / "internal").mkdir(parents=True)
    (root / "benchmarks" / "internal" / "planner_cases.json").write_text("[]", encoding="utf-8")
    (root / "benchmarks" / "internal" / "REASONING.md").write_text("# spec", encoding="utf-8")

    # Benchmark outputs
    (root / ".kagent" / "reasoning-run-01.jsonl").write_text('{"req": 1}\n', encoding="utf-8")
    (root / ".kagent" / "metrics.jsonl").write_text('{"metric": 1}\n', encoding="utf-8")


def test_dry_run_leaves_files_intact(tmp_path: Path):
    _setup_mock_repo(tmp_path)
    res = subprocess.run(
        ["./scripts/reset-runtime.sh", "--dry-run"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "Would delete:" in res.stdout
    assert "DRY-RUN mode" in res.stdout

    # Assert nothing was deleted
    assert (tmp_path / ".kagent" / "coverage" / "session1.json").exists()
    assert (tmp_path / ".kagent" / "evidence" / "hash123" / "proof.proof").exists()
    assert (tmp_path / "artifacts" / "recon" / "target-1" / "summary.md").exists()
    assert (tmp_path / ".kagent" / "intelligence" / "scenarios.jsonl").exists()


def test_reset_runtime_clears_transient_and_preserves_durable(tmp_path: Path):
    _setup_mock_repo(tmp_path)
    res = subprocess.run(
        ["./scripts/reset-runtime.sh"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "Runtime reset complete." in res.stdout

    # Transient runtime files deleted
    assert not (tmp_path / ".kagent" / "coverage" / "session1.json").exists()
    assert not (tmp_path / ".kagent" / "evidence" / "hash123" / "proof.proof").exists()
    assert not (tmp_path / ".kagent" / "observations" / "obs1.json").exists()
    assert not (tmp_path / ".kagent" / "permissions" / "perm1.json").exists()
    assert not (tmp_path / ".kagent.cfg.tmp.12345").exists()
    assert not (tmp_path / "artifacts" / "recon" / "target-1" / "summary.md").exists()
    assert not (tmp_path / "artifacts" / "sql-injection" / "results.md").exists()
    assert not (tmp_path / "artifacts" / "findings" / "sqli-vuln.md").exists()
    assert not (tmp_path / "artifacts" / "worker" / "log.txt").exists()

    # Directory structures preserved
    assert (tmp_path / ".kagent" / "coverage").is_dir()
    assert (tmp_path / ".kagent" / "evidence").is_dir()
    assert (tmp_path / ".kagent" / "observations").is_dir()
    assert (tmp_path / ".kagent" / "permissions").is_dir()
    assert (tmp_path / "artifacts" / "recon").is_dir()

    # Durable & benchmark files strictly preserved
    assert (tmp_path / ".kagent" / "intelligence" / "scenarios.jsonl").exists()
    assert (tmp_path / ".kagent" / "intelligence" / "scenarios.jsonl.lock").exists()
    assert (tmp_path / ".kagent" / "memory" / "note.md").exists()
    assert (tmp_path / ".kagent" / "engagement.md").exists()
    assert (tmp_path / "artifacts" / "audits" / "milestone-1" / "REPORT.md").exists()
    assert (tmp_path / "artifacts" / "checkpoints" / "stage.zip").exists()
    assert (tmp_path / "benchmarks" / "internal" / "planner_cases.json").exists()
    assert (tmp_path / "benchmarks" / "internal" / "REASONING.md").exists()

    # Idempotent second run
    res2 = subprocess.run(
        ["./scripts/reset-runtime.sh"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert res2.returncode == 0


def test_reset_benchmark_preserves_intelligence_by_default(tmp_path: Path):
    _setup_mock_repo(tmp_path)
    res = subprocess.run(
        ["./scripts/reset-benchmark.sh"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "Benchmark reset complete." in res.stdout

    # Benchmark outputs deleted
    assert not (tmp_path / ".kagent" / "reasoning-run-01.jsonl").exists()
    assert not (tmp_path / ".kagent" / "metrics.jsonl").exists()

    # Transient runtime files deleted
    assert not (tmp_path / ".kagent" / "coverage" / "session1.json").exists()

    # Intelligence preserved by default
    assert (tmp_path / ".kagent" / "intelligence" / "scenarios.jsonl").exists()
    assert (tmp_path / ".kagent" / "intelligence" / "scenarios.jsonl.lock").exists()

    # Ground truth preserved
    assert (tmp_path / "benchmarks" / "internal" / "planner_cases.json").exists()
    assert (tmp_path / "benchmarks" / "internal" / "REASONING.md").exists()
    assert (tmp_path / "artifacts" / "audits" / "milestone-1" / "REPORT.md").exists()


def test_reset_benchmark_resets_intelligence_when_requested(tmp_path: Path):
    _setup_mock_repo(tmp_path)
    res = subprocess.run(
        ["./scripts/reset-benchmark.sh", "--reset-intelligence"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0

    # Intelligence reset
    assert not (tmp_path / ".kagent" / "intelligence" / "scenarios.jsonl").exists()
    assert not (tmp_path / ".kagent" / "intelligence" / "scenarios.jsonl.lock").exists()

    # Ground truth and audits STILL preserved
    assert (tmp_path / "benchmarks" / "internal" / "planner_cases.json").exists()
    assert (tmp_path / "benchmarks" / "internal" / "REASONING.md").exists()
    assert (tmp_path / "artifacts" / "audits" / "milestone-1" / "REPORT.md").exists()
    assert (tmp_path / "artifacts" / "checkpoints" / "stage.zip").exists()
    assert (tmp_path / ".kagent" / "memory" / "note.md").exists()
