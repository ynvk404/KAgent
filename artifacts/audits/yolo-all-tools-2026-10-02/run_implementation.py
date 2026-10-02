"""Offline implementation checks, separate from immutable historical audit output."""
from pathlib import Path
import os
import sys

root = Path(__file__).resolve().parents[3]
os.chdir(root)
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
os.environ["PATH"] = str(root / "venv-linux/bin") + os.pathsep + os.environ.get("PATH", "")
sys.path.insert(0, str(root))
import pytest

arguments = sys.argv[1:] or ["tests/security", "tests/tools", "tests/data", "tests/agent", "tests/ui", "tests/runtime", "tests/state", "tests/skills", "tests/browser"]
output_name = "implementation-focused-results.xml" if sys.argv[1:] else "implementation-results.xml"
raise SystemExit(pytest.main(["-q", "-p", "no:cacheprovider", *arguments,
                             f"--basetemp=/tmp/kagent-yolo-implementation-{os.getpid()}",
                             f"--junitxml=artifacts/audits/yolo-all-tools-2026-10-02/{output_name}"]))
