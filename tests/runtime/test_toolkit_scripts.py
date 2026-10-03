from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"

ALL_SCRIPTS = [
    SCRIPTS_DIR / "lib" / "cleanup-common.sh",
    SCRIPTS_DIR / "reset-runtime.sh",
    SCRIPTS_DIR / "reset-benchmark.sh",
    SCRIPTS_DIR / "doctor.sh",
    SCRIPTS_DIR / "setup.sh",
    SCRIPTS_DIR / "archive-run.sh",
    SCRIPTS_DIR / "prepare-benchmark.sh",
]


def test_all_scripts_syntax():
    for script in ALL_SCRIPTS:
        assert script.exists(), f"Script {script} does not exist"
        res = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert res.returncode == 0, f"Syntax check failed for {script}: {res.stderr}"


def test_doctor_read_only_and_pass():
    res = subprocess.run(
        [str(SCRIPTS_DIR / "doctor.sh"), "--no-color"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"doctor.sh failed: {res.stderr}\n{res.stdout}"
    assert "KAgent environment is HEALTHY" in res.stdout
    assert "Planner benchmark cases present" in res.stdout
    assert "API_KEY" not in res.stdout or "configured" in res.stdout  # No actual secret printed


def test_setup_check_only():
    res = subprocess.run(
        [str(SCRIPTS_DIR / "setup.sh"), "--check-only"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"setup.sh --check-only failed: {res.stderr}\n{res.stdout}"
    assert "Setup check passed" in res.stdout


def test_archive_run_dry_run():
    res = subprocess.run(
        [str(SCRIPTS_DIR / "archive-run.sh"), "--latest", "--dry-run"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"archive-run.sh --dry-run failed: {res.stderr}\n{res.stdout}"
    assert "DRY-RUN mode enabled" in res.stdout
    assert "Would archive:" in res.stdout


def test_prepare_benchmark_dry_run():
    res = subprocess.run(
        [str(SCRIPTS_DIR / "prepare-benchmark.sh"), "--dry-run"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"prepare-benchmark.sh --dry-run failed: {res.stderr}\n{res.stdout}"
    assert "[READY]" in res.stdout
    assert "Planner Benchmark:" in res.stdout


def _setup_mock_project(root: Path) -> None:
    # Markers
    (root / "pyproject.toml").write_text("[project]\nname='kagent'\n", encoding="utf-8")
    (root / "AGENTS.md").write_text("# Guide\n", encoding="utf-8")
    (root / "src").mkdir(parents=True)
    (root / "src" / "paths.py").write_text("APP_DIR_NAME = '.kagent'\n", encoding="utf-8")
    (root / "src" / "version").mkdir(parents=True)
    (root / "src" / "version" / "version.py").write_text('VERSION = "0.2.0"\ndef describe(): return "kagent 0.2.0"\n', encoding="utf-8")
    (root / "src" / "cli").mkdir(parents=True)
    (root / "src" / "cli" / "main.py").write_text("def cli_main(): pass\n", encoding="utf-8")

    # Copy scripts into mock repo
    shutil.copytree(SCRIPTS_DIR, root / "scripts")

    # Benchmarks
    (root / "benchmarks" / "internal").mkdir(parents=True)
    (root / "benchmarks" / "internal" / "planner_cases.json").write_text('[{"prompt": "test", "expected": "none"}]', encoding="utf-8")
    (root / "benchmarks" / "internal" / "REASONING.md").write_text("# Reasoning Spec\n", encoding="utf-8")

    # Runtime directories
    (root / ".kagent" / "sessions").mkdir(parents=True)
    (root / ".kagent" / "coverage").mkdir(parents=True)
    (root / ".kagent" / "evidence" / "key1").mkdir(parents=True)
    (root / ".kagent" / "observations").mkdir(parents=True)
    (root / ".kagent" / "permissions").mkdir(parents=True)
    (root / ".kagent" / "intelligence").mkdir(parents=True)
    (root / ".kagent" / "intelligence" / "scenarios.jsonl").write_text('{"item": 1}\n', encoding="utf-8")
    (root / ".kagent" / "memory").mkdir(parents=True)
    (root / ".kagent" / "memory" / "note.md").write_text("permanent memory", encoding="utf-8")

    (root / "artifacts" / "recon" / "juice-lab-3000").mkdir(parents=True)
    (root / "artifacts" / "recon" / "juice-lab-3000" / "summary.md").write_text("recon summary", encoding="utf-8")
    (root / "artifacts" / "audits" / "audit-1").mkdir(parents=True)
    (root / "artifacts" / "audits" / "audit-1" / "REPORT.md").write_text("audit report", encoding="utf-8")
    (root / "artifacts" / "checkpoints").mkdir(parents=True)
    (root / "artifacts" / "checkpoints" / "stage.zip").write_text("zip data", encoding="utf-8")

    # Create a mock session
    session_id = "test-session-1234-uuid"
    session_data = {
        "updated_at": "2026-10-03T09:00:00Z",
        "id": session_id,
        "target": {"baseURL": "http://juice.lab:3000"},
        "workflow": {
            "evidence": [
                {
                    "id": "ev1",
                    "path": ".kagent/evidence/key1/proof1.proof",
                }
            ],
            "completed_artifacts": {
                "recon": "artifacts/recon/juice-lab-3000/summary.md"
            },
        },
        "messages": [],
    }
    (root / ".kagent" / "sessions" / f"{session_id}.json").write_text(json.dumps(session_data), encoding="utf-8")
    (root / ".kagent" / "coverage" / f"{session_id}.json").write_text('{"entries": []}', encoding="utf-8")
    (root / ".kagent" / "observations" / f"{session_id}.json").write_text('{"records": []}', encoding="utf-8")
    (root / ".kagent" / "permissions" / f"{session_id}.json").write_text('{"journal": []}', encoding="utf-8")
    (root / ".kagent" / "evidence" / "key1" / "proof1.proof").write_text("proof content", encoding="utf-8")


def test_archive_run_isolated(tmp_path: Path):
    _setup_mock_project(tmp_path)
    session_id = "test-session-1234-uuid"

    res = subprocess.run(
        ["./scripts/archive-run.sh", "-s", session_id],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"archive-run.sh failed: {res.stderr}\n{res.stdout}"
    assert "successfully archived" in res.stdout

    archive_root = tmp_path / "artifacts" / "runs" / f"run-{session_id}"
    assert archive_root.is_dir()
    assert (archive_root / "session" / f"{session_id}.json").exists()
    assert (archive_root / "coverage" / f"{session_id}.json").exists()
    assert (archive_root / "observations" / f"{session_id}.json").exists()
    assert (archive_root / "permissions" / f"{session_id}.json").exists()
    assert (archive_root / "evidence" / "key1" / "proof1.proof").exists()
    assert (archive_root / "artifacts" / "recon" / "juice-lab-3000" / "summary.md").exists()
    assert (archive_root / "run-metadata.json").exists()

    # Verify that intelligence, memory, audits, checkpoints are NOT in the archive
    assert not (archive_root / "intelligence").exists()
    assert not (archive_root / "scenarios.jsonl").exists()
    assert not (archive_root / "memory").exists()
    assert not (archive_root / "audits").exists()
    assert not (archive_root / "checkpoints").exists()


def test_prepare_benchmark_isolated(tmp_path: Path):
    _setup_mock_project(tmp_path)

    res = subprocess.run(
        ["./scripts/prepare-benchmark.sh", "--skip-doctor"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"prepare-benchmark.sh failed: {res.stderr}\n{res.stdout}"
    assert "[READY]" in res.stdout

    # Verify benchmark prep metadata file was created
    prep_meta = tmp_path / ".kagent" / "benchmark-prep.json"
    assert prep_meta.exists()
    data = json.loads(prep_meta.read_text(encoding="utf-8"))
    assert data["status"] == "ready"
    assert data["planner_cases_count"] == 1
    assert data["intelligence_mode"] == "retained"

    # Verify ground truth was preserved
    assert (tmp_path / "benchmarks" / "internal" / "planner_cases.json").exists()
    assert (tmp_path / "benchmarks" / "internal" / "REASONING.md").exists()
    assert (tmp_path / ".kagent" / "intelligence" / "scenarios.jsonl").exists()
