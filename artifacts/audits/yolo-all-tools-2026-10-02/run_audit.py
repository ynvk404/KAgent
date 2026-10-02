from pathlib import Path
import os
import sys

root = Path('/mnt/d/DOANTOTNGHIEP/kagent')
os.chdir(root)
sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
sys.path.insert(0, str(root))
os.environ['PATH'] = str(root / 'venv-linux/bin') + os.pathsep + os.environ.get('PATH', '')
import pytest

paths = [
    'artifacts/audits/yolo-all-tools-2026-10-02/test_current_boundaries.py',
    'artifacts/audits/prompt-injection-2026-10-01/test_characterization.py',
    'tests/security', 'tests/tools/test_discovery_tools.py',
    'tests/data/test_memory_store.py', 'tests/data/test_intelligence_store.py',
    'tests/tools/test_tools_registry.py', 'tests/tools/test_plugin.py',
    'tests/agent/test_post_compaction.py', 'tests/agent/test_resume_after_compaction.py',
]
raise SystemExit(pytest.main(['-q', '-p', 'no:cacheprovider', *paths,
                             '--basetemp=/tmp/kagent-all-yolo-audit',
                             '--junitxml=artifacts/audits/yolo-all-tools-2026-10-02/results.xml']))
