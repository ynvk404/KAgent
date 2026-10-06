from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from src.agent.agent import Agent, AgentOptions
from src.coverage.store import CoverageStore
from src.findings.store import Store as FindingsStore
from src.permission.permission import AlwaysAllow
from src.report.model import ReportError
from src.session.store import SessionMemory, Store as SessionStore
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.workflow.finding import ConfirmFindingTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.ui.commands import report_handler as handler
from src.ui.commands.slash_handler import handle_slash
from tests.helpers.agent_fakes import FakeClient
from tests.report.test_builder import finding_fixture


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    state, c, r, f, path = finding_fixture(tmp_path)
    coverage = CoverageStore(str(tmp_path / ".kagent/coverage/report.json"))
    coverage.loaded = True
    coverage.path.parent.mkdir(parents=True)
    coverage.path.write_bytes(b'{"version":1,"entries":[]}')
    session = SessionStore(tmp_path / "session.json", "report-session")
    session.path.write_bytes(b'{"canonical":"unchanged"}')
    finding_store = FindingsStore(project_directory=tmp_path)
    tools = Registry()
    tools.register(ConfirmFindingTool(finding_store, workflow=state))
    tools.register(WorkflowTool(state, Target("https://target.test"), coverage=coverage, evidence_root=tmp_path))
    client = FakeClient([])
    agent = Agent(AgentOptions(client=client, tools=tools, skills=SkillRegistry(), prompter=AlwaysAllow(), store=session,
                              target=Target("https://target.test"), workflow=state))
    agent.memory = SessionMemory()
    notices = []
    config = dict(active_provider_name="Official test provider", backend="openai", api_key="CONFIG_SECRET", base_url="https://me:SECRET@provider.test")
    app = SimpleNamespace(agent=agent, dispatch=notices.append, read_config=lambda: deepcopy(config), resume_summary="", notices=notices)
    def forbidden(*args, **kwargs): raise AssertionError("forbidden canonical mutation/tool call")
    for name in ("save", "resume_saved", "_whole_target_state", "_reconcile_requested_goals", "_planner_context", "rebuild_system_prompt"):
        monkeypatch.setattr(agent, name, forbidden)
    for owner, names in ((coverage, ("load", "mark", "flush", "_quarantine")), (finding_store, ("save",)),
                         (session, ("save", "load")), (agent.tools, ("run",)), (client, ("chat",))):
        for name in names:
            if hasattr(owner, name): monkeypatch.setattr(owner, name, forbidden)
    app.coverage = coverage; app.finding_store = finding_store
    app.root = tmp_path; app.config = config
    return app


def invariant(app):
    agent = app.agent
    rights = agent.engagement_state.http_permissions
    permissions = {key: deepcopy(value) for key, value in vars(rights).items()
                   if key not in {"engagement", "clock", "constraint_journal", "_target_origin", "_target_revision"}}
    return dict(target=agent.target.to_dict(), revision=agent.target.revision,
        engagement=agent.engagement_state.to_dict(), workflow=agent.workflow.to_dict(), permissions=permissions,
        coverage=deepcopy(app.coverage.entries), loaded=app.coverage.loaded, dirty=app.coverage.dirty,
        load_task=app.coverage.load_task, saving=app.coverage.saving, save_error=app.coverage.last_save_error,
        canonical_files={str(p.relative_to(app.root)):p.read_bytes() for p in app.root.rglob("*") if p.is_file() and "reports" not in p.parts},
        session_save_count=agent.store.save_count, session_id=agent.store.id,
        history=deepcopy(agent.history), memory=deepcopy(agent.memory), pending=deepcopy(agent.pending_skills),
        active=deepcopy(agent.active_skills), running=agent.running, client=id(agent.client), config=deepcopy(app.config),
        llm_calls=deepcopy(agent._llm_call_counts), client_calls=len(agent.client.requests))


@pytest.mark.parametrize("scenario", ["success", "failure", "empty", "resumed", "repeated", "running"])
async def test_report_preserves_canonical_state_for_all_exports(runtime, monkeypatch, scenario):
    app = runtime
    if scenario == "failure":
        def fail(*args): raise ReportError("Fixed safe test failure.")
        monkeypatch.setattr(handler, "_prepare", fail)
    elif scenario == "empty": app.agent.workflow.clear()
    elif scenario == "resumed": app.resume_summary = "restored session"
    elif scenario == "running": app.agent.running = True
    before = invariant(app)
    task = handler.start_report(app, ["assessment.pdf"])
    assert task is not None
    await task
    if scenario == "repeated":
        again = handler.start_report(app, ["assessment.pdf"])
        assert again is not None
        await again
    assert invariant(app) == before
    pdfs = list((app.root / "artifacts/reports").glob("*.pdf"))
    if scenario == "failure": assert not pdfs
    else:
        assert len(pdfs) == (2 if scenario == "repeated" else 1)
        assert any("PDF report saved" in action.entry.text for action in app.notices)
    assert "CONFIG_SECRET" not in str(app.notices)


async def test_cancelled_offload_is_drained_and_never_publishes(runtime, monkeypatch):
    app = runtime; started = threading.Event(); release = threading.Event()
    real = handler._prepare
    def blocked(*args):
        started.set()
        release.wait(timeout=10)
        return real(*args)
    monkeypatch.setattr(handler, "_prepare", blocked)
    before = invariant(app)
    task = handler.start_report(app, [])
    assert task is not None
    await asyncio.to_thread(started.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()  # Repeated cancellation must not abandon the thread.
    assert handler.start_report(app, []) is None
    release.set()
    with pytest.raises(asyncio.CancelledError): await task
    assert invariant(app) == before
    assert not list((app.root / "artifacts/reports").iterdir())
    assert id(app) not in handler._IN_FLIGHT


async def test_changed_target_during_worker_aborts_publication(runtime, monkeypatch):
    app = runtime; started = threading.Event(); release = threading.Event()
    real = handler._prepare
    def blocked(*args):
        started.set(); release.wait(timeout=10); return real(*args)
    monkeypatch.setattr(handler, "_prepare", blocked)
    task = handler.start_report(app, [])
    assert task is not None
    await asyncio.to_thread(started.wait, 5)
    app.agent.target.set_base_url("https://different.test")
    release.set(); await task
    assert not list((app.root / "artifacts/reports").iterdir())
    assert any("Assessment changed" in n.entry.text for n in app.notices)


async def test_capture_precedes_task_scheduling_and_progress_is_detached(runtime, monkeypatch):
    app = runtime
    real = handler._prepare
    captured = []
    def observe(source, *args):
        captured.append(source); return real(source, *args)
    monkeypatch.setattr(handler, "_prepare", observe)
    task = handler.start_report(app, [])
    assert task is not None
    app.agent.workflow.validation_results[-1].notes = "LATER_MUTATION"
    await task
    assert captured[0].results[-1].get("notes") is None
    assert any("PDF report saved" in n.entry.text for n in app.notices)


@pytest.mark.parametrize("raw", ["/report", "/report report.pdf", "/report ../x.pdf", "/report one.pdf two.pdf", "/report pdf"])
async def test_recognized_slash_never_falls_through(runtime, raw):
    assert handle_slash(runtime, raw) is True
    task = handler._IN_FLIGHT.get(id(runtime))
    if task: await task
    assert runtime.agent.client.requests == []


def test_missing_target_rejects_before_directory_creation(runtime):
    runtime.agent.target.clear()
    assert handler.start_report(runtime, []) is None
    assert not (runtime.root / "artifacts/reports").exists()
    assert any("no valid active target" in n.entry.text for n in runtime.notices)


async def test_cancellation_before_worker_starts_releases_guard(runtime):
    before = invariant(runtime)
    task = handler.start_report(runtime, [])
    assert task is not None
    task.cancel()
    with pytest.raises(asyncio.CancelledError): await task
    await asyncio.sleep(0)
    assert id(runtime) not in handler._IN_FLIGHT
    assert invariant(runtime) == before
    assert not (runtime.root / "artifacts/reports").exists()


async def test_safe_exception_and_filename_display_never_echo_source_secrets(runtime, monkeypatch):
    def fail(*args): raise OSError("PASSWORD_SECRET_PROVIDER_URL")
    monkeypatch.setattr(handler, "_prepare", fail)
    task = handler.start_report(runtime, [])
    assert task is not None
    await task
    assert "PASSWORD_SECRET_PROVIDER_URL" not in str(runtime.notices)


def test_asyncio_run_shutdown_drains_eventual_stage_without_publication(runtime, monkeypatch):
    app = runtime
    started, release = threading.Event(), threading.Event()
    real_prepare = handler._prepare
    produced = []
    exports = []
    before = invariant(app)

    def blocked(*args):
        started.set()
        assert release.wait(timeout=10), "shutdown failed to release the report worker"
        doc, stage = real_prepare(*args)
        produced.append(stage)
        return doc, stage

    async def release_on_shutdown():
        try:
            await asyncio.Event().wait()
        finally:
            release.set()

    async def main():
        task = handler.start_report(app, ["shutdown.pdf"])
        assert task is not None
        exports.append(task)
        asyncio.create_task(release_on_shutdown())
        assert await asyncio.to_thread(started.wait, 5)
        # Returning triggers asyncio.run's cancellation of ALL remaining Tasks,
        # including a to_thread worker Task in the original implementation.

    monkeypatch.setattr(handler, "_prepare", blocked)
    try:
        asyncio.run(main())
    finally:
        release.set()
    assert exports[0].cancelled()
    assert len(produced) == 1 and produced[0].closed
    assert list((app.root / "artifacts/reports").iterdir()) == []
    assert not any("PDF report saved" in notice.entry.text for notice in app.notices)
    assert id(app) not in handler._IN_FLIGHT
    assert invariant(app) == before
