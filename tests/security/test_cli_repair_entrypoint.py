"""Actual main()/Textual wiring with FakeLLM and real CLI protected profile."""
import importlib
import json
from pathlib import Path
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest

from src.config.config import Config, Backend, ToolingProfile
from src.llm.probe import ProbeResult
from src.permission.execution import ExecutionBlocked
from src.permission.permission import Decision, UserControlledRefusal
from src.ui.core.state import SetPerm
from src.workflow.state import Candidate
from tests.helpers.agent_fakes import FakeClient
from tests.security.test_repair_runtime import lab


@pytest.mark.asyncio
async def test_cli_tui_real_factory_evidence_network_off_and_revoke(lab, tmp_path, monkeypatch):
    cli = importlib.import_module('src.cli.main')
    _, _, _, _, origin, requests = lab
    cfg = Config(backend=Backend.DEEPSEEK, model='deepseek-flash', api_keys={'deepseek':'FAKE_TEST_ONLY'},
                 skills_dirs=[str(Path(__file__).resolve().parents[2] / 'skills')],
                 streaming_enabled=False, tooling_profile=ToolingProfile.MINIMAL)
    monkeypatch.setattr(cli.config, 'load', lambda:cfg)
    monkeypatch.setattr(cli.llm_factory, 'new_from_config', lambda config:FakeClient([]))
    monkeypatch.setattr(cli, 'probe_tool_support', AsyncMock(return_value=ProbeResult('yes')))
    monkeypatch.setattr(cli.sys, 'argv', ['kagent','--target',origin,'--yolo','--no-stream'])
    monkeypatch.setenv('KAGENT_PROJECT_ROOT', str(tmp_path))
    monkeypatch.setattr(cli.session_store, 'dir_from_path', lambda _:tmp_path / '.kagent/sessions')
    checked = []

    async def run_app(app):
        async with app.run_test(size=(120,40)):
            assert app.startup_splash is None
            assert app.input_static.display and app.transcript_panel.display
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
            candidate, _ = agent.workflow.add_candidate(Candidate(candidate_class='xxe',target=origin,endpoint='/xml'))
            for source in ['proof.txt','.env']:
                await agent.tools.execute('file_write', {'path':str(tmp_path/source),'content':'FAKE_CLI_EVIDENCE'}, None, agent.prompter)
                evidence = json.loads(await agent.tools.execute('workflow', {'action':'record_evidence','candidate_id':candidate.id,'evidence_path':source}, None, agent.prompter))['evidence']
                result = await agent.tools.execute('workflow', {'action':'record_result','candidate_id':candidate.id,'skill_name':'xxe','outcome':'insufficient-evidence','evidence_refs':[evidence['id']], 'force':True}, None, agent.prompter)
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
