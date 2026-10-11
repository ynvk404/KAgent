"""Descriptions must match the isolated worker's actual filesystem contract."""
from src.agent.system_prompt import BASE_SYSTEM_PROMPT
from src.permission.worker.worker import OfflineWorker
from src.tools.execution.shell import ShellTool


def test_shell_guidance_names_worker_paths_and_native_writer(monkeypatch):
    monkeypatch.setattr('src.tools.execution.shell.is_windows', lambda: False)
    description = ShellTool().description()
    assert '/work' in description and 'artifacts/worker' in description
    assert 'file_write' in description
    assert '/work' in BASE_SYSTEM_PROMPT and 'host paths' in BASE_SYSTEM_PROMPT


def test_worker_maps_project_readonly_and_only_worker_artifacts_writable(tmp_path):
    worker = OfflineWorker(tmp_path, (), '/usr/bin/bwrap', '/usr/bin/prlimit')
    _, args = worker.wrap('/bin/sh', ['-c', 'pwd'])
    assert ['--ro-bind', str(tmp_path), '/work'] == args[args.index(str(tmp_path)) - 1:args.index(str(tmp_path)) + 2]
    index = args.index('/work/artifacts/worker')
    assert args[index - 2:index + 1] == ['--bind', str(tmp_path / 'artifacts/worker'), '/work/artifacts/worker']
    assert args[args.index('--chdir') + 1] == '/work'
