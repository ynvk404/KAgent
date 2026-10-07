"""The optional CWE component must not crash slash-command dispatch."""
from __future__ import annotations

import builtins
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from src.ui.commands.cwe_enrichment import enrich_cwe


@pytest.mark.asyncio
@pytest.mark.parametrize('rest', [[], ['candidate-a', 'candidate-b']])
async def test_invalid_arguments_do_not_load_optional_component(rest, monkeypatch):
    original_import = builtins.__import__

    def without_component(name, *args, **kwargs):
        if name == 'src.findings.cwe_enrichment':
            pytest.fail('invalid arguments must be checked before loading CWE')
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', without_component)
    output = []
    await enrich_cwe(SimpleNamespace(dispatch=output.append), rest)
    assert len(output) == 1
    assert output[0].entry.kind == 'error'
    assert output[0].entry.text == 'CWE enrichment: usage: /enrich-cwe <candidate-id>'


@pytest.mark.asyncio
@pytest.mark.parametrize('missing', [
    'components', 'components.cwe_mcp', 'components.cwe_mcp.contract', 'other_dependency',
])
async def test_missing_component_reports_repair_without_exception_payload(missing, monkeypatch):
    original_import = builtins.__import__

    def without_component(name, *args, **kwargs):
        if name == 'src.findings.cwe_enrichment':
            raise ModuleNotFoundError('sensitive filesystem or credential detail', name=missing)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', without_component)
    output = []
    await enrich_cwe(SimpleNamespace(dispatch=output.append), ['candidate-a'])
    assert len(output) == 1
    assert output[0].entry.kind == 'error'
    message = output[0].entry.text
    assert 'sensitive' not in message
    if missing.startswith('components'):
        assert 'python -m pip install --no-deps -e .' in message
        assert 'restart KAgent' in message
    else:
        assert message == 'CWE enrichment: ModuleNotFoundError'


def test_slash_dispatch_survives_missing_components_in_fresh_interpreter():
    # pytest adds the repository to sys.path and can hide stale editable
    # metadata. Block components before any UI import in a fresh process.
    code = r'''
import asyncio
import importlib.abc
import sys
from types import SimpleNamespace

class MissingComponents(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'components' or fullname.startswith('components.'):
            raise ModuleNotFoundError('components is not installed', name=fullname)

sys.path.insert(0, sys.argv[1])
sys.meta_path.insert(0, MissingComponents())
from src.ui.core.app import KAgent
from src.ui.commands.slash_handler import handle_slash

async def check():
    output = []
    app = SimpleNamespace(agent=SimpleNamespace(), dispatch=output.append,
        _cwe_enrichment_closing=False, _cwe_enrichment_tasks=set())
    app.start_cwe_enrichment = lambda rest: KAgent.start_cwe_enrichment(app, rest)
    for command in ('/enrich-cwe ', '/enrich-cwe candidate-a'):
        assert handle_slash(app, command)
        await asyncio.gather(*tuple(app._cwe_enrichment_tasks))
        await asyncio.sleep(0)
        assert not app._cwe_enrichment_tasks
    assert len(output) == 2
    assert all(item.entry.kind == 'error' for item in output)
    assert 'usage: /enrich-cwe <candidate-id>' in output[0].entry.text
    assert 'python -m pip install --no-deps -e .' in output[1].entry.text

asyncio.run(check())
'''
    result = subprocess.run(
        [sys.executable, '-I', '-c', code, str(Path(__file__).resolve().parents[2])],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
