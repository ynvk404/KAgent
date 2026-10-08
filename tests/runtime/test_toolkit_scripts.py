from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"

ALL_SCRIPTS = [
    SCRIPTS_DIR / "doctor.sh",
    SCRIPTS_DIR / "setup.sh",
]


def test_all_scripts_syntax():
    for script in ALL_SCRIPTS:
        assert script.exists(), f"Script {script} does not exist"
        res = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        assert res.returncode == 0, f"Syntax check failed for {script}: {res.stderr}"


def test_doctor_read_only_and_pass():
    secret = "doctor-test-secret-never-print"
    res = subprocess.run(
        [str(SCRIPTS_DIR / "doctor.sh"), "--no-color"],
        cwd=REPO_ROOT,
        env={**os.environ, "OPENAI_API_KEY": secret},
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"doctor.sh failed: {res.stderr}\n{res.stdout}"
    assert "KAgent environment is HEALTHY" in res.stdout
    assert "Planner benchmark" not in res.stdout
    assert secret not in res.stdout + res.stderr


def test_setup_check_only():
    res = subprocess.run(
        [str(SCRIPTS_DIR / "setup.sh"), "--check-only"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0, f"setup.sh --check-only failed: {res.stderr}\n{res.stdout}"
    assert "Setup check passed" in res.stdout


def test_doctor_reuses_setup_validation_and_propagates_failure(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='kagent'\n")
    (tmp_path / "AGENTS.md").write_text("# guide")
    (tmp_path / "src").mkdir()
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy2(SCRIPTS_DIR / "doctor.sh", scripts / "doctor.sh")
    setup = scripts / "setup.sh"
    setup.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > setup-args.txt\nexit 1\n')
    setup.chmod(0o755)
    venv = tmp_path / "mock-venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin")
    python = venv / "bin/python3"
    python.write_text("#!/bin/sh\nexit 0\n")
    python.chmod(0o755)
    result = subprocess.run([str(scripts / "doctor.sh"), "--no-color"], cwd=tmp_path,
                            env={**os.environ, "VIRTUAL_ENV": str(venv)},
                            text=True, capture_output=True)
    assert result.returncode == 1
    assert "Environment setup check failed" in result.stdout
    assert (tmp_path / "setup-args.txt").read_text().splitlines() == [
        "--check-only", "--venv-path", str(venv),
    ]


def test_setup_check_only_rejects_missing_venv_without_creating_it(tmp_path):
    missing = tmp_path / "missing-venv"
    result = subprocess.run([str(SCRIPTS_DIR / "setup.sh"), "--check-only", "--venv-path", str(missing)],
                            cwd=REPO_ROOT, text=True, capture_output=True)
    assert result.returncode == 1
    assert "does not exist" in result.stderr
    assert not missing.exists()
