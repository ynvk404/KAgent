"""Repair regression with activated existing venv; no provider API calls."""
from pathlib import Path
import os
import sys

ROOT = Path(__file__).resolve().parents[3]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
os.environ['PATH'] = str(ROOT/'venv-linux/bin') + os.pathsep + os.environ.get('PATH','')
import pytest

groups = ['tests/security','tests/tools','tests/data','tests/agent','tests/ui','tests/runtime','tests/state','tests/skills','tests/browser','tests/llm','tests/integration/test_mcp_integration.py']
raise SystemExit(pytest.main(['-q', '-p', 'no:cacheprovider', *groups,
    '--junitxml=artifacts/audits/yolo-all-tools-2026-10-02/repair-2026-10-02/regression-final-serial.xml']))
