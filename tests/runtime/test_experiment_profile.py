"""Offline operational-profile tests; all --apply calls use tmp_path fixtures."""
import asyncio
import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import experiment_profile as profile
from src.intelligence.store import IntelligenceScenario, IntelligenceStore
from tests.runtime.test_cli_exit_diagnostics import offline_cli


@pytest.fixture
def layout(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    repo, home = tmp_path / "repo", tmp_path / "home"
    (repo / "src").mkdir(parents=True)
    (repo / "src/example.py").write_text("# unchanged runtime\n")
    (repo / "skills/recon").mkdir(parents=True)
    (repo / "skills/recon/SKILL.md").write_text("# unchanged skill\n")
    home.mkdir()
    config = home / ".kagent/config.json"
    config.parent.mkdir()
    config.write_text(json.dumps({"backend": "deepseek", "model": "deepseek-flash",
                                  "api_keys": {"deepseek": "fixture-secret"}}))
    for root, scope in ((repo, "project"), (home, "personal")):
        path = root / ".kagent/intelligence/scenarios.jsonl"
        path.parent.mkdir(parents=True)
        row = IntelligenceScenario(id="old-" + scope, title="Old Juice Shop canary",
                                   triggers=["juice", "shop", "canary"],
                                   lesson="old-private-lab-canary",
                                   scope="project" if scope == "project" else "personal")
        path.write_text(json.dumps(row.to_wire()) + "\n")
    session = home / ".kagent/sessions/old-session.json"
    session.parent.mkdir()
    session.write_text(json.dumps({"messages": [{"role": "user", "content": "old-history-canary"}]}))
    notes = home / ".kagent/engagement.md"
    notes.write_text("old-engagement-canary")
    (repo / "artifacts").mkdir()
    (repo / "artifacts/prior-report.md").write_text("old-report-canary")
    return repo, home, config, tmp_path / "run-1"


def make_plan(layout: tuple[Path, Path, Path, Path]):
    return profile.plan(*layout, "http://127.0.0.1:8081")


def original_bytes(layout):
    repo, home, _, _ = layout
    return {p: p.read_bytes() for root in (repo, home) for p in root.rglob("*") if p.is_file()}


def test_default_dry_run_is_read_only_and_does_not_disclose_credentials(layout, monkeypatch, capsys):
    repo, home, config, run = layout
    before = original_bytes(layout)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("kagent_CONFIG", str(config))
    assert profile.main(["--repo", str(repo), "--run-dir", str(run)]) == 0
    out = capsys.readouterr().out
    assert "fixture-secret" not in out
    assert json.loads(out)["existing_files_to_modify"] == []
    assert not run.exists() and original_bytes(layout) == before


def test_apply_creates_verified_backups_and_leaves_every_original_unchanged(layout):
    before = original_bytes(layout)
    value = make_plan(layout)
    receipt = profile.apply(value)
    assert profile.verify(receipt) == value
    for row in value["backup_sources"]:
        backup = layout[3] / "backup" / (row["label"] + ".jsonl")
        assert backup.read_bytes() == Path(row["path"]).read_bytes()
        assert backup.stat().st_mode & 0o777 == 0o600
    assert original_bytes(layout) == before
    assert value["deletions"] == []
    assert not (layout[3] / "profile-home/.kagent/config.json").exists()


@pytest.mark.parametrize("which", ["config", "project-store", "runtime", "skill"])
def test_stale_inputs_fail_before_creating_run(layout, which):
    value = make_plan(layout)
    target = {"config": layout[2], "project-store": layout[0] / ".kagent/intelligence/scenarios.jsonl",
              "runtime": layout[0] / "src/example.py", "skill": layout[0] / "skills/recon/SKILL.md"}[which]
    target.write_bytes(target.read_bytes() + b"\n")
    with pytest.raises(ValueError):
        profile.apply(value)
    assert not layout[3].exists()


def test_no_run_reuse_or_overwrite(layout):
    value = make_plan(layout)
    receipt = profile.apply(value)
    before = receipt.read_bytes()
    with pytest.raises(ValueError):
        profile.apply(value)
    assert receipt.read_bytes() == before


def test_scenario3_profiles_and_run_outputs_are_separate(layout):
    run = layout[3].parent / "experiments/scenario3/runs/fixture-run"
    value = make_plan((*layout[:3], run))
    receipt = profile.apply(value)
    assert receipt == run.parent.parent / "profiles/fixture-run/profile.json"
    assert (receipt.parent / "whole-target-request.txt").is_file()
    assert not (run / "profile.json").exists()
    assert (run / "backup").is_dir()
    assert (run / "project").is_dir()
    assert profile.verify(receipt) == value


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_backup_source_links_are_rejected_without_touching_referent(layout, kind):
    source = layout[0] / ".kagent/intelligence/scenarios.jsonl"
    other = layout[0] / "outside.jsonl"
    source.rename(other)
    if kind == "symlink":
        source.symlink_to(other)
    elif kind == "hardlink":
        os.link(other, source)
    else:
        os.mkfifo(source)
    before = other.read_bytes()
    with pytest.raises(ValueError):
        make_plan(layout)
    assert other.read_bytes() == before and not layout[3].exists()


def test_apply_requires_approved_exact_plan_bytes(layout, tmp_path):
    p = tmp_path / "reviewed.json"
    raw = profile.encode(make_plan(layout))
    p.write_bytes(raw)
    assert profile.main(["--apply", "--plan", str(p)]) == 2
    assert profile.main(["--apply", "--plan", str(p), "--approve-plan-sha256", "0" * 64]) == 2
    assert not layout[3].exists()
    assert profile.main(["--apply", "--plan", str(p), "--approve-plan-sha256", profile.digest(raw)]) == 0


def test_backup_failure_never_publishes_launchable_profile_or_modifies_originals(layout, monkeypatch):
    value = make_plan(layout)
    before = original_bytes(layout)
    real_write = profile.private_write
    def fail_second(path, data):
        if path.name == "personal-intelligence.jsonl":
            raise OSError("synthetic full disk")
        real_write(path, data)
    monkeypatch.setattr(profile, "private_write", fail_second)
    with pytest.raises(OSError):
        profile.apply(value)
    assert original_bytes(layout) == before
    assert not (layout[3] / "profile.json").exists()
    assert not (layout[3] / "project").exists()


@pytest.mark.parametrize("dirty", ["project", "profile-home"])
def test_verify_rejects_preexisting_runtime_state(layout, dirty):
    receipt = profile.apply(make_plan(layout))
    path = layout[3] / dirty / ".kagent/memory/old.md"
    path.parent.mkdir(parents=True)
    path.write_text("old-context-canary")
    with pytest.raises(ValueError):
        profile.verify(receipt)


def test_fresh_startup_paths_legacy_fallback_history_and_policy_boundaries(layout):
    from src.cli import runtime
    from src.session import store as sessions
    from src.paths import legacy_project_data_root, project_root
    from src.engagement.state import EngagementState
    from src.permission.runtime.execution import default_execution_policy, ExecutionBlocked
    from src.skills.discovery import skill_search_dirs
    value = make_plan(layout)
    profile.apply(value)
    cwd, old_factory, old_session_path = Path.cwd(), runtime.IntelligenceStore, sessions.dir_from_path
    with profile.bound_runtime(value) as cli:
        project = layout[3] / "project"
        assert Path.cwd() == project_root() == project
        assert legacy_project_data_root() is None
        store = cli.IntelligenceStore()
        assert all(s.scope == "builtin" for s in store.list())
        assert "old-private-lab-canary" not in str(store.search("juice shop canary", 5))
        assert cli.MemoryStore().index() == ""
        assert cli.EngagementStore().load() == ""
        history = sessions.Store.new_with_id(sessions.dir_from_path(), "new-session").load()
        assert history.messages == [] and history.memory is None and history.workflow.objective is None
        dirs = cli.skill_search_dirs([])
        assert dirs == skill_search_dirs([], cwd=str(project), home=str(layout[3] / "profile-home"))
        assert not any(str(layout[1]) in path for path in dirs)
        policy = default_execution_policy(EngagementState(), project_root())
        with pytest.raises(ExecutionBlocked):
            policy.require_path(layout[0] / "artifacts/prior-report.md")
        with pytest.raises(ExecutionBlocked):
            policy.require_path(layout[1] / ".kagent/sessions/old-session.json")
    assert Path.cwd() == cwd and runtime.IntelligenceStore is old_factory
    assert sessions.dir_from_path is old_session_path


def test_current_run_learning_persists_and_retrieves_without_cross_run_leak(layout):
    value = make_plan(layout)
    profile.apply(value)
    before = original_bytes(layout)
    with profile.bound_runtime(value) as cli:
        learned = asyncio.run(cli.IntelligenceStore().learn_from_text(
            "# Lessons Learned\n- Missed checking syntheticcanaryomega input during this experiment.",
            source_session_id="new-session"))
        assert learned
        fresh_reader = cli.IntelligenceStore()
        hits = fresh_reader.search("syntheticcanaryomega input", 5)
        assert any(r["scenario"].source_session_id == "new-session" for r in hits)
        assert fresh_reader.get_stats()["project"] > 0
    second_layout = (*layout[:3], layout[3].parent / "run-2")
    second = make_plan(second_layout)
    profile.apply(second)
    with profile.bound_runtime(second) as cli:
        assert all(s.scope == "builtin" for s in cli.IntelligenceStore().list())
        assert not cli.IntelligenceStore().search("syntheticcanaryomega", 5)
    assert original_bytes(layout) == before


def test_prepare_does_not_launch_and_launcher_uses_official_bounded_new_session(layout, monkeypatch):
    from src.cli import runtime
    value = profile.plan(layout[0], layout[1], layout[2], layout[3], "http://127.0.0.1:8081", 17)
    cli_main = Mock(return_value=0)
    monkeypatch.setattr(runtime, "cli_main", cli_main)
    monkeypatch.setattr(profile.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(profile.sys.stdout, "isatty", lambda: True)
    receipt = profile.apply(value)
    cli_main.assert_not_called()
    def inspect():
        args = runtime.parse_flags(profile.sys.argv[1:])
        assert args.target_url == "http://127.0.0.1:8081"
        assert args.max_steps == 17 and not args.resume_id and not args.yolo
        assert not args.browser and not args.burp
        assert Path(args.log_path).is_relative_to(layout[3])
        assert Path(args.debug_session_path).is_relative_to(layout[3])
        return 0
    cli_main.side_effect = inspect
    assert profile.launch(receipt, 17) == 0
    with pytest.raises(ValueError):
        profile.launch(receipt, 17)
    assert cli_main.call_count == 1


def test_exception_restores_process_local_bindings(layout):
    from src.cli import runtime
    from src.session import store as sessions
    value = make_plan(layout)
    profile.apply(value)
    before = (Path.cwd(), runtime.IntelligenceStore, sessions.dir_from_path, dict(os.environ))
    with pytest.raises(RuntimeError):
        with profile.bound_runtime(value):
            raise RuntimeError("synthetic interruption")
    assert (Path.cwd(), runtime.IntelligenceStore, sessions.dir_from_path, dict(os.environ)) == before


def test_headless_launcher_requires_execution_and_yolo_opt_in_and_uses_finite_grant(layout, monkeypatch):
    from src.cli import runtime
    receipt = profile.apply(make_plan(layout))
    monkeypatch.setattr(profile.sys.stdin, "isatty", lambda: False)
    with pytest.raises(ValueError, match="execute-prompt"):
        profile.launch(receipt, headless=True)
    with pytest.raises(ValueError, match="acceptance"):
        profile.launch(receipt, headless=True, execute_prompt=True, yolo=True)
    assert not (layout[3] / "launch-started.json").exists()
    def inspect():
        args = runtime.parse_flags(profile.sys.argv[1:])
        assert args.headless and args.non_interactive and args.execute_prompt and args.yolo
        assert args.http_lab_grants == ["http://127.0.0.1:8081,autonomous,1200,500,3,3,2,131072,65536"]
        assert args.accept_unknown_http_effects
        assert Path(args.prompt_file).parent == Path(json.loads(receipt.read_text())["profile"])
        assert Path(args.headless_output).is_relative_to(layout[3])
        assert not runtime.IntelligenceStore().search("juice shop canary", 5)
        return 0
    monkeypatch.setattr(runtime, "cli_main", inspect)
    assert profile.launch(receipt, headless=True, execute_prompt=True, yolo=True,
                          accept_unknown_http_effects=True) == 0


def test_run_refuses_noninteractive_terminal_before_creating_a_marker(layout, monkeypatch):
    receipt = profile.apply(make_plan(layout))
    monkeypatch.setattr(profile.sys.stdin, "isatty", lambda: False)
    with pytest.raises(ValueError, match="interactive"):
        profile.launch(receipt, 60)
    assert not (layout[3] / "launch-started.json").exists()


@pytest.mark.parametrize("relative", ["project/old-report.md", "profile-home/notes.txt", "project/__pycache__/old-report.md"])
def test_profile_rejects_arbitrary_knowledge_files_before_launch(layout, relative):
    receipt = profile.apply(make_plan(layout))
    path = layout[3] / relative
    path.parent.mkdir(exist_ok=True)
    path.write_text("old Juice Shop knowledge")
    with pytest.raises(ValueError, match="unexpected files"):
        profile.verify(receipt)


def test_active_custom_provider_cannot_shadow_official_model_identity(layout):
    value = json.loads(layout[2].read_text())
    profile_id = "0123456789abcdef0123456789abcdef"
    value["active_custom_provider_id"] = profile_id
    value["custom_providers"] = {profile_id: {"name": "Different provider", "protocol": "openai-compatible",
        "base_url": "https://fixture.invalid/v1", "default_model": "different-model"}}
    layout[2].write_text(json.dumps(value))
    with pytest.raises(ValueError, match="official provider"):
        make_plan(layout)


@pytest.mark.parametrize("shutdown", ["ctrl+c", "parent-signal"])
async def test_actual_cli_tui_isolated_stores_logs_checkpoints_and_shutdown(
    offline_cli, layout, monkeypatch, shutdown,
):
    """Actual Textual app test pilot; fake provider, no network or Agent turn."""
    from src.llm.core.types import Message
    value = make_plan(layout)
    profile.apply(value)
    original = original_bytes(layout)
    checked = []
    async def run_app(app):
        agent = app.agent
        run = layout[3]
        project = run / "project"
        assert agent.store.path.parent == run / "profile-home/.kagent/sessions"
        assert agent.store.context_snapshot_path().parent == run / "profile-home/.kagent/context"
        assert agent.intelligence.project_path == project / ".kagent/intelligence/scenarios.jsonl"
        assert agent.intelligence.personal_path == run / "profile-home/.kagent/intelligence/scenarios.jsonl"
        assert agent.memory_store.project_dir == project / ".kagent/memory"
        assert agent.memory_store.personal_dir == run / "profile-home/.kagent/memory"
        assert agent.engagement == "" and agent.memory is None
        assert agent.tools.get("workflow").evidence_root == project
        assert agent.result_retention.store.project == project
        assert not any("old-" in (m.content or "") for m in agent.history)
        assert "old-private-lab-canary" not in agent.build_intelligence_context("juice shop canary")
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            agent.history.append(Message("user", "new-session-only-canary"))
            await agent.save()
            await agent.save_context_snapshot("offline isolated-profile test")
            app.session_debug.write("profile_test", {"marker": "new-log-only-canary"})
            if shutdown == "ctrl+c":
                await pilot.press("ctrl+c")
            else:
                app.parent_signal.set()
                await pilot.pause()
        assert agent.store.path.is_file()
        assert "old-history-canary" not in agent.store.path.read_text()
        assert agent.store.context_snapshot_path().is_file()
        assert app.snapshot_task is None or app.snapshot_task.done()
        checked.append(True)
    cli = offline_cli.cli
    monkeypatch.setattr(cli.KAgent, "run_async", run_app)
    with profile.bound_runtime(value), profile.patch.object(profile.sys, "argv", [
        "kagent", "--target", value["origin"], "--max-steps", "60",
        "--log", str(layout[3] / "logs/kagent.log"),
        "--debug-session-path", str(layout[3] / "logs/session.jsonl"),
    ]):
        assert await cli.main() == 0
    events = [json.loads(line) for line in (layout[3] / "logs/session.jsonl").read_text().splitlines()]
    assert any(row["event"] == "profile_test" for row in events)
    assert checked and original_bytes(layout) == original
    assert offline_cli.client.requests == []
