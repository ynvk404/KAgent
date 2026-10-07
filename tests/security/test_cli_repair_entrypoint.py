"""Actual main()/Textual wiring with FakeLLM and real CLI protected profile."""
import importlib
import asyncio
import json
import threading
from pathlib import Path
from dataclasses import replace
from unittest.mock import AsyncMock

import pytest

from src.config.config import Config, Backend, ToolingProfile
from src.llm.runtime.probe import ProbeResult
from src.llm.core.types import ChatResponse, Message, ToolCall, FunctionCall
from src.permission.runtime.execution import ExecutionBlocked
from src.permission.permission import Decision, UserControlledRefusal
from src.ui.core.state import SetPerm
from src.workflow.state import Candidate
import src.permission.worker.worker as worker_module
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
    return cli


@pytest.mark.asyncio
async def test_cli_tui_real_factory_evidence_network_off_and_revoke(lab, tmp_path, monkeypatch, cli_runtime):
    cli = cli_runtime
    _, _, _, _, origin, requests = lab
    cfg = Config(backend=Backend.DEEPSEEK, model='deepseek-flash', api_keys={'deepseek':'FAKE_TEST_ONLY'},
                 skills_dirs=[str(Path(__file__).resolve().parents[2] / 'skills')],
                 streaming_enabled=False, tooling_profile=ToolingProfile.MINIMAL)
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
    probe.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize('cancel', [False, True])
async def test_cli_file_then_shell_slow_inspection_ui_and_escape(tmp_path, monkeypatch, cancel, cli_runtime):
    """Reproduce the manual checklist with the CLI policy and a scripted model."""
    cli = cli_runtime
    cfg = Config(backend=Backend.DEEPSEEK, model='deepseek-flash', api_keys={'deepseek':'FAKE_TEST_ONLY'},
        skills_dirs=[str(Path(__file__).resolve().parents[2] / 'skills')],
        streaming_enabled=False, tooling_profile=ToolingProfile.MINIMAL)
    proof = tmp_path / 'artifacts/worker/checklist/payloads.txt'
    payload = "' OR 1=1--\n<script>CHECKLIST_FAKE</script>\n{{7*7}}"
    scripted = []
    for name, args in [('file_write', {'path':str(proof), 'content':payload}),
                       ('file_read', {'path':str(proof)}),
                       ('shell', {'command':'cat artifacts/worker/checklist/payloads.txt; printf WORKER_OK > artifacts/worker/checklist/worker-ok.txt'})]:
        scripted.append(ChatResponse(message=Message(role='assistant', content='', tool_calls=[
            ToolCall(id=name, function=FunctionCall(name=name, arguments=json.dumps(args)))]), finish_reason='tool_calls'))
    scripted.append(ChatResponse(message=Message(role='assistant', content='Offline checklist completed.'), finish_reason='stop'))
    fake = FakeClient(scripted)
    monkeypatch.setattr(cli.config, 'load', lambda:cfg)
    monkeypatch.setattr(cli.llm_factory, 'new_from_config', lambda config:fake)
    probe = AsyncMock(return_value=ProbeResult('yes'))
    monkeypatch.setattr(cli, 'probe_tool_support', probe)
    monkeypatch.setattr(cli.sys, 'argv', ['kagent','--yolo','--no-stream'])
    monkeypatch.setenv('KAGENT_PROJECT_ROOT', str(tmp_path))
    monkeypatch.setattr(cli.session_store, 'dir_from_path', lambda _:tmp_path / '.kagent/sessions')
    checked = []

    async def run_app(app):
        async with app.run_test(size=(120,40)) as pilot:
            assert app.agent.prompter.execution_policy.worker is not None
            assert tmp_path / '.kagent' in app.agent.prompter.execution_policy.protected
            dialogs = []
            original_dispatch = app.dispatch
            def dispatch(action):
                if isinstance(action, SetPerm) and action.req is not None:
                    dialogs.append(action.req)
                    action.req.resolve(Decision.DENY)
                original_dispatch(action)
            app.dispatch = dispatch
            original_walk = worker_module.os.walk
            loop = asyncio.get_running_loop()
            started = asyncio.Event()
            release = threading.Event()
            finished = threading.Event()

            def slow_walk(path, **kwargs):
                if Path(path) == tmp_path:
                    loop.call_soon_threadsafe(started.set)
                    try:
                        assert release.wait(6), 'UI did not respond while inspecting'
                        yield from original_walk(path, **kwargs)
                    finally:
                        finished.set()
                else:
                    yield from original_walk(path, **kwargs)

            monkeypatch.setattr(worker_module.os, 'walk', slow_walk)
            turn = asyncio.create_task(app.run_agent_turn('Run the offline file and shell checklist only.'))
            try:
                await asyncio.wait_for(started.wait(), 4)
                assert proof.read_text() == payload and app.state.busy
                await pilot.pause(1.1)
                assert app.status_bar.elapsed_seconds >= 1
                if cancel:
                    await pilot.press('escape')
                    with pytest.raises(asyncio.CancelledError):
                        await asyncio.wait_for(turn, 2)
                else:
                    release.set()
                    await asyncio.wait_for(turn, 3)
                assert not app.state.busy and app.run_abort_event is None
                assert not app.agent.is_running()
                marker = tmp_path / 'artifacts/worker/checklist/worker-ok.txt'
                if cancel:
                    assert not marker.exists()
                else:
                    assert marker.read_text() == 'WORKER_OK'
                assert not dialogs and app.agent.prompter.execution_policy.active == 0
                assert fake.idx == (3 if cancel else 4)
                checked.append(True)
            finally:
                release.set()
                turn.cancel()
                await asyncio.gather(turn, return_exceptions=True)
                await asyncio.to_thread(finished.wait, 2)

    monkeypatch.setattr(cli.KAgent, 'run_async', run_app)
    assert await cli.main() == 0 and checked
    probe.assert_awaited_once()
