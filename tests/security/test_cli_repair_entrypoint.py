"""Actual main()/Textual wiring with FakeLLM and real CLI protected profile."""
import importlib
import json
import logging
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from src.config.config import Config, Backend
from src.llm.runtime.probe import ProbeResult
from src.permission.runtime.execution import ExecutionBlocked
from src.permission.permission import Decision, UserControlledRefusal
from src.ui.core.state import SetPerm
from src.workflow.state import Candidate
from tests.helpers.agent_fakes import FakeClient
from tests.security.test_repair_runtime import lab


@pytest.fixture
def cli_runtime(tmp_path, monkeypatch):
    # Patch the module owning main()'s globals, not the lazy entrypoint facade.
    cli = importlib.import_module('src.cli.runtime')
    home = tmp_path / 'home'
    # Explicit cwd also disables legacy reads from the real working directory.
    intelligence = cli.IntelligenceStore(cwd=tmp_path, home=home)
    memory = cli.MemoryStore(cwd=str(tmp_path), home=str(home))
    engagement = cli.EngagementStore(cwd=tmp_path, home=home)
    monkeypatch.setattr(cli, 'IntelligenceStore', lambda: intelligence)
    monkeypatch.setattr(cli, 'MemoryStore', lambda: memory)
    monkeypatch.setattr(cli, 'EngagementStore', lambda: engagement)
    # Real CLI startup must exercise logging against disposable user data.
    # Restore handlers so later tests cannot inherit this fixture's file sink.
    monkeypatch.setattr(cli.logger, 'default_log_path', lambda: home / '.kagent/logs/kagent.log')
    base = logging.getLogger(cli.logger.BASE_LOGGER_NAME)
    handlers, level, disabled = list(base.handlers), base.level, base.disabled
    yield cli
    for handler in list(base.handlers):
        if handler not in handlers:
            base.removeHandler(handler)
            handler.close()
    base.handlers[:] = handlers
    base.level, base.disabled = level, disabled


@pytest.mark.asyncio
async def test_cli_tui_real_factory_evidence_network_off_and_revoke(lab, tmp_path, monkeypatch, cli_runtime):
    cli = cli_runtime
    _, _, _, _, origin, requests = lab
    cfg = Config(backend=Backend.DEEPSEEK, model='deepseek-flash', api_keys={'deepseek':'FAKE_TEST_ONLY'},
                 skills_dirs=[str(Path(__file__).resolve().parents[2] / 'skills')],
                 streaming_enabled=False)
    monkeypatch.setattr(cli.config, 'load', lambda:cfg)
    monkeypatch.setattr(cli.llm_factory, 'new_from_config', lambda config:FakeClient([]))
    probe = AsyncMock(return_value=ProbeResult('yes'))
    monkeypatch.setattr(cli, 'probe_tool_support', probe)
    monkeypatch.setattr(cli.sys, 'argv', ['kagent','--target',origin,'--yolo','--no-stream'])
    monkeypatch.setenv('KAGENT_PROJECT_ROOT', str(tmp_path))
    monkeypatch.setattr(cli.session_store, 'dir_from_path', lambda _:tmp_path / '.kagent/sessions')
    checked = []

    async def run_app(app):
        async with app.run_test(size=(120,40)):
            assert app.input_static.display and app.transcript_panel.display and app.status_bar.display
            agent = app.agent
            policy = agent.prompter.execution_policy
            assert tmp_path / '.kagent' in policy.protected
            dialogs = []
            original = app.dispatch
            def dispatch(action):
                if isinstance(action, SetPerm) and action.req is not None:
                    dialogs.append(action.req)
                    action.req.resolve(Decision.DENY)
                original(action)
            app.dispatch = dispatch
            output = await agent.tools.execute('http', {'url':origin+'/new?q=1%3D1','phase':'impact'}, None, agent.prompter)
            assert output.http_status == 200
            candidate, _ = agent.workflow.add_candidate(Candidate(candidate_class='xss',target=origin,endpoint='/render'))
            for source in ['proof.txt','.env']:
                await agent.tools.execute('file_write', {'path':str(tmp_path/source),'content':'FAKE_CLI_EVIDENCE'}, None, agent.prompter)
                evidence = json.loads(await agent.tools.execute('workflow', {'action':'record_evidence','candidate_id':candidate.id,'evidence_path':source}, None, agent.prompter))['evidence']
                result = await agent.tools.execute('workflow', {'action':'record_result','candidate_id':candidate.id,'skill_name':'cross-site-scripting','outcome':'insufficient-evidence','evidence_refs':[evidence['id']], 'force':True}, None, agent.prompter)
                assert '"result"' in result, result
                with pytest.raises(ExecutionBlocked):
                    await agent.tools.execute('file_read', {'path':str(tmp_path/evidence['path'])}, None, agent.prompter)
            assert not dialogs
            app.apply_yolo(False)
            with pytest.raises(UserControlledRefusal):
                await agent.tools.execute('http', {'url':origin+'/off','phase':'validation'}, None, agent.prompter)
            assert len(dialogs) == 1
            app.apply_yolo(True)
            policy.revoke('http')
            with pytest.raises(UserControlledRefusal):
                await agent.tools.execute('http', {'url':origin+'/revoked','phase':'recon'}, None, agent.prompter)
            assert len(dialogs) == 1 and len(requests) == 1
            checked.append(True)

    monkeypatch.setattr(cli.KAgent, 'run_async', run_app)
    assert await cli.main() == 0 and checked
    probe.assert_awaited_once()
    log_path = cli.logger.default_log_path()
    assert log_path.is_relative_to(tmp_path) and log_path.is_file()
    assert 'FAKE_TEST_ONLY' not in log_path.read_text()
