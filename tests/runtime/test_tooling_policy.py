"""Legacy tooling configuration normalizes into the existing native policy."""
from dataclasses import fields
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from src.agent.agent import AgentOptions
from src.agent.system_prompt import BuildOptions, build_system_prompt
from src.config.config import Config, config_from_dict, config_to_dict, load as load_config, save
from src.skills.registry import Registry
from tests.runtime.test_cli_exit_diagnostics import offline_cli

LEGACY = [{}, {'tooling_profile': 'minimal'}, {'tooling_profile': 'full'}, {'tooling_profile': None}]


@pytest.mark.parametrize('legacy', LEGACY)
async def test_load_legacy_without_eager_write_and_drop_key_only_on_explicit_save(tmp_path, monkeypatch, legacy):
    path = tmp_path / 'config.json'
    monkeypatch.setenv('kagent_CONFIG', str(path))
    raw = {'backend': 'deepseek', 'model': 'fixture-model', 'disabled_skills': ['recon'], **legacy}
    path.write_text(json.dumps(raw))
    before, modified = path.read_bytes(), path.stat().st_mtime_ns
    cfg = load_config()
    assert path.read_bytes() == before and path.stat().st_mtime_ns == modified
    assert cfg == config_from_dict({k: v for k, v in raw.items() if k != 'tooling_profile'})
    assert 'tooling_profile' not in config_to_dict(cfg) and not hasattr(cfg, 'tooling_profile')
    await save(cfg)
    assert 'tooling_profile' not in json.loads(path.read_text())
    assert load_config() == cfg and cfg.disabled_skills == ['recon']


@pytest.mark.parametrize('profile', ['full', 'compact'])
def test_prompt_profiles_are_still_distinct_supported_options(profile):
    assert 'prompt_profile' in {field.name for field in fields(BuildOptions)}
    assert 'tooling_profile' not in {field.name for field in fields(BuildOptions)}
    assert 'tooling_profile' not in {field.name for field in fields(Config)}
    prompt = build_system_prompt(BuildOptions(Registry(), False, None, prompt_profile=profile))
    assert 'authorized' in prompt.lower() and 'http' in prompt.lower() and 'workflow' in prompt.lower()
    assert 'Tooling profile:' not in prompt
    if profile == 'compact': assert len(prompt) < 12000
    else: assert len(prompt) > 20000


@pytest.mark.parametrize('legacy', LEGACY)
@pytest.mark.parametrize('resume', [False, True])
async def test_cli_starts_or_resumes_without_tooling_picker_or_config_write(offline_cli, tmp_path, monkeypatch, legacy, resume):
    from src.llm.core.types import Message
    from src.session.store import Store
    cli = offline_cli.cli
    path = tmp_path / 'legacy-config.json'
    path.write_text(json.dumps({'backend': 'deepseek', 'model': 'fake-model', **legacy}))
    monkeypatch.setenv('kagent_CONFIG', str(path))
    monkeypatch.setattr(cli.config, 'load', load_config)
    write = AsyncMock(side_effect=AssertionError('startup must not rewrite tooling configuration'))
    monkeypatch.setattr(cli.config, 'save', write)
    before = path.read_bytes()
    argv = ['kagent', '--target', 'http://juice.lab:3000']
    if resume:
        store = Store.new_with_id(tmp_path / 'sessions', 'resumed-session')
        await store.save([Message('system', 'previous'), Message('user', 'retained request')])
        argv.extend(['--resume', 'resumed-session'])
    monkeypatch.setattr(cli.sys, 'argv', argv)
    observed = []
    async def run_app(app):
        agent = app.agent
        assert not hasattr(agent, 'tooling_profile')
        assert agent.prompt_profile in {'full', 'compact'}
        assert {'http', 'service_discovery', 'content_discovery', 'shell', 'workflow', 'load_skill'} <= set(agent.tools.names())
        assert not hasattr(cli, 'run_first_run_picker')
        if resume: assert any(m.content == 'retained request' for m in agent.history)
        observed.append(True)
    monkeypatch.setattr(cli.KAgent, 'run_async', run_app)
    assert await cli.main() == 0
    assert observed and path.read_bytes() == before
    write.assert_not_awaited()
    assert offline_cli.client.requests == []
