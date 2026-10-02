"""Recheck checklist 3–8 offline, serially; preserve earlier result files."""
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
os.chdir(ROOT)
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
os.environ['PATH'] = str(ROOT / 'venv-linux/bin') + os.pathsep + os.environ.get('PATH', '')
stamp = datetime.now(ZoneInfo('Asia/Ho_Chi_Minh')).strftime('%Y%m%d-%H%M%S')
OUTPUT = Path(__file__).resolve().parent / ('checklist-' + stamp)
OUTPUT.mkdir()

groups = {
    'mode_cli_policy': [
        'tests/security/test_cli_repair_entrypoint.py',
        'tests/security/test_execution_policy.py',
        'tests/security/test_action_approval.py',
    ],
    'http_grants_lifecycle': ['tests/security/test_http_grants.py'],
    'files_evidence': [
        'tests/security/test_cli_evidence_repair.py',
        'tests/security/test_evidence_reads.py',
        'tests/security/test_sensitive_paths.py',
        'tests/tools/test_file.py',
    ],
    'workers_mcp_findings_controls': [
        'tests/security/test_offline_worker.py',
        'tests/security/test_repair_runtime.py',
        'tests/security/test_repair_controls.py',
        'tests/tools/test_shell.py',
        'tests/tools/test_plugin.py',
        'tests/integration/test_mcp_integration.py',
    ],
    'finding_memory_resume': [
        'tests/security/test_yolo_results_resume.py',
        'tests/security/test_yolo_memory_transport.py',
        'tests/tools/test_workflow.py',
        'tests/tools/test_finding.py',
        'tests/data/test_intelligence_store.py',
    ],
    'network_regression': [
        'tests/tools/test_http.py',
        'tests/tools/test_web.py',
        'tests/tools/test_web_response_lifecycle.py',
        'tests/tools/test_discovery_tools.py',
        'tests/security/test_private_host.py',
    ],
}
results = {'scope': 'checklist 3–8 selected offline controls, not all-tools/live acceptance',
           'model_api_calls': 0, 'live_pentest_calls': 0, 'product_changes': False,
           'groups': {}, 'checks': {}}


def save():
    (OUTPUT / 'results.json').write_text(json.dumps(results, indent=2, ensure_ascii=False) + '\n')


for name, paths in groups.items():
    command = [sys.executable, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
               *paths, '--junitxml=' + str(OUTPUT / (name + '.xml'))]
    print('Running ' + name, flush=True)
    with (OUTPUT / (name + '.log')).open('w') as log:
        check = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=False)
    counts = {key: 0 for key in ['tests', 'failures', 'errors', 'skipped']}
    xml = OUTPUT / (name + '.xml')
    if xml.exists():
        for suite in ET.parse(xml).getroot().iter('testsuite'):
            for key in counts:
                counts[key] += int(suite.get(key, '0'))
    counts['passed'] = counts['tests'] - counts['failures'] - counts['errors'] - counts['skipped']
    results['groups'][name] = {'exit_code': check.returncode, **counts, 'paths': paths}
    print(name + ': ' + json.dumps(results['groups'][name]), flush=True)
    save()

# Typecheck only after all test processes finish (real-UID NPROC is shared).
for name, command in [('pyright', [str(ROOT / 'venv-linux/bin/pyright')]),
                      ('diff_check', ['git', 'diff', '--check']),
                      ('status', ['git', 'status', '--short']),
                      ('head', ['git', 'rev-parse', 'HEAD'])]:
    print('Running ' + name, flush=True)
    check = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    output = check.stdout + check.stderr
    (OUTPUT / (name + '.txt')).write_text(output)
    results['checks'][name] = {'exit_code': check.returncode, 'output': output}
    save()
    print(name + ': exit ' + str(check.returncode), flush=True)

print('Results: ' + str(OUTPUT), flush=True)
raise SystemExit(int(any(group['exit_code'] != 0 for group in results['groups'].values())
                    or any(results['checks'][key]['exit_code'] != 0 for key in ['pyright', 'diff_check'])))
