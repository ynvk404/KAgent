"""Numbered experiment resumes: fixture data only, never a live TUI/provider."""
import json
from pathlib import Path
import sys

import pytest

from scripts import experiment_profile as profile
from scripts import resume_experiment as resume
from tests.runtime.test_experiment_profile import layout, original_bytes


SESSION_ID = "bbdb1f00-531d-42bd-b896-82da30533295"


@pytest.fixture
def saved_run(layout, monkeypatch):
    repo, home, config, _ = layout
    run = repo / "experiments/scenario3/runs/lan-50"
    value = profile.plan(repo, home, config, run, "http://127.0.0.1:8081")
    receipt = profile.apply(value)
    directory = run / "profile-home/.kagent/sessions"
    directory.mkdir(parents=True)
    session = directory / f"{SESSION_ID}.json"
    session.write_text(json.dumps({
        "id": SESSION_ID,
        "messages": [{"role": "user", "content": "Saved task"}],
        "target": {"baseURL": "http://juice.fixture.invalid:8081"},
    }))
    (run / "launch-started.json").write_text("{}\n")
    (run / "logs/session.jsonl").write_text("historical events\n")
    (run / "logs/kagent.log").write_text("historical log\n")
    monkeypatch.setattr(resume, "REPO", repo)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    return value, receipt, session


@pytest.mark.parametrize("number,expected", [("50", "lan-50"), ("5", "lan-05"), ("05", "lan-05"), ("100", "lan-100")])
def test_number_maps_to_existing_experiment_convention(number, expected):
    assert resume.run_name(number) == expected


@pytest.mark.parametrize("number", ["0", "-1", "../50", "lan-50", "50/../51", "５０", "", "1" * 20])
def test_invalid_run_numbers_are_rejected(number):
    with pytest.raises(resume.ResumeError):
        resume.run_name(number)


def test_check_reads_saved_session_without_launch_or_writes(saved_run, layout, monkeypatch, capsys):
    from src.cli import runtime

    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    monkeypatch.setattr(runtime, "cli_main", lambda: pytest.fail("--check must not start KAgent"))
    before = original_bytes(layout)
    assert resume.main(["--check", "50"]) == 0
    output = capsys.readouterr().out
    assert SESSION_ID in output and "1 tin nhắn" in output
    assert "fixture-secret" not in output
    assert original_bytes(layout) == before


def test_resume_binds_existing_stores_and_current_config_without_overriding_scope(saved_run, layout, monkeypatch):
    from src.cli import runtime

    value, _, session = saved_run
    cfg = json.loads(layout[2].read_text())
    cfg["model"] = "fixture-current-model"
    layout[2].write_text(json.dumps(cfg))
    before = original_bytes(layout)
    original = (Path.cwd(), sys.argv, runtime.MemoryStore, runtime.EngagementStore)
    flags_seen = []

    def inspect():
        flags = runtime.parse_flags(sys.argv[1:])
        assert flags.resume_id == SESSION_ID
        assert flags.target_url == flags.prompt_file == ""
        assert not flags.yolo and not flags.headless and not flags.execute_prompt
        assert flags.http_lab_grants == [] and flags.max_steps == 0
        run = Path(value["run"])
        assert Path.cwd() == run / "project"
        assert runtime.require_existing_resume_session(flags.resume_id).path == session
        restored = runtime.require_existing_resume_session(flags.resume_id).load()
        assert restored.target is not None
        assert restored.target.base_url() == "http://juice.fixture.invalid:8081"
        assert runtime.MemoryStore().project_dir == run / "project/.kagent/memory"
        assert runtime.MemoryStore().personal_dir == run / "profile-home/.kagent/memory"
        assert runtime.config.config_path() == layout[2]
        assert runtime.config.load().model == "fixture-current-model"
        assert runtime.skill_search_dirs([])[0] == str(run / "project/skills")
        assert Path(flags.log_path).parent == Path(flags.debug_session_path).parent == run / "logs"
        assert Path(flags.log_path).name.startswith("kagent-resume-")
        assert Path(flags.debug_session_path).name.startswith("session-resume-")
        assert not Path(flags.log_path).exists() and not Path(flags.debug_session_path).exists()
        flags_seen.append(flags)
        return 0

    monkeypatch.setattr(runtime, "cli_main", inspect)
    assert resume.main(["50"]) == 0
    assert resume.main(["50"]) == 0
    assert flags_seen[0].log_path != flags_seen[1].log_path
    assert original_bytes(layout) == before
    assert (Path.cwd(), sys.argv, runtime.MemoryStore, runtime.EngagementStore) == original


def test_missing_number_is_prompted_and_cancellation_does_not_launch(saved_run, monkeypatch):
    from src.cli import runtime

    called = []
    monkeypatch.setattr("builtins.input", lambda _: "50")
    monkeypatch.setattr(runtime, "cli_main", lambda: called.append(True) or 0)
    assert resume.main([]) == 0 and called == [True]

    def cancel(_):
        raise EOFError

    monkeypatch.setattr("builtins.input", cancel)
    assert resume.main([]) == 130 and called == [True]


def test_non_terminal_launch_is_refused_before_reading_or_starting(saved_run, layout, monkeypatch):
    from src.cli import runtime

    before = original_bytes(layout)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(runtime, "cli_main", lambda: pytest.fail("No TTY"))
    monkeypatch.setattr(resume, "load_profile", lambda _: pytest.fail("Refuse before lookup"))
    assert resume.main(["50"]) == 2
    assert original_bytes(layout) == before


@pytest.mark.parametrize("field", ["repo", "run", "profile", "original_home", "config"])
def test_profile_cannot_redirect_resume_to_other_data(saved_run, layout, monkeypatch, field):
    from src.cli import runtime

    value, receipt, _ = saved_run
    value[field] = "../outside"
    receipt.write_text(json.dumps(value))
    before = original_bytes(layout)
    monkeypatch.setattr(runtime, "cli_main", lambda: pytest.fail("Invalid profile"))
    assert resume.main(["--check", "50"]) == 2
    assert original_bytes(layout) == before


def test_multiple_sessions_require_a_selection_and_only_resume_selected_one(saved_run, monkeypatch):
    from src.cli import runtime

    _, _, session = saved_run
    second = session.with_name("another-session.json")
    second.write_text(json.dumps({"id": second.stem, "messages": []}))
    selected = []

    def inspect():
        selected.append(runtime.parse_flags(sys.argv[1:]).resume_id)
        return 0

    monkeypatch.setattr(runtime, "cli_main", inspect)
    assert resume.main(["--check", "50"]) == 2
    assert selected == []
    monkeypatch.setattr("builtins.input", lambda _: "1")
    assert resume.main(["50"]) == 0
    assert selected == ["another-session"]
    assert resume.main(["50", "--session", SESSION_ID]) == 0
    assert selected == ["another-session", SESSION_ID]
    assert resume.main(["50", "--session", "unrelated-session"]) == 2
    assert len(selected) == 2


@pytest.mark.parametrize("failure", ["missing", "malformed", "wrong-id", "symlink"])
def test_invalid_sessions_never_start_empty_or_different_session(saved_run, layout, monkeypatch, capsys, failure):
    from src.cli import runtime

    _, _, session = saved_run
    if failure == "missing":
        session.unlink()
    elif failure == "malformed":
        session.write_text("fixture-secret invalid JSON")
    elif failure == "wrong-id":
        session.write_text(json.dumps({"id": "other", "messages": []}))
    else:
        source = session.with_suffix(".backup")
        session.rename(source)
        session.symlink_to(source)
    before = original_bytes(layout)
    monkeypatch.setattr(runtime, "cli_main", lambda: pytest.fail("Invalid session"))
    assert resume.main(["--check", "50"]) == 2
    captured = capsys.readouterr()
    assert "fixture-secret" not in captured.out + captured.err
    assert original_bytes(layout) == before


def test_failed_startup_restores_bindings_without_disclosing_exception(saved_run, layout, monkeypatch, capsys):
    from src.cli import runtime

    original = (Path.cwd(), sys.argv, runtime.MemoryStore, runtime.EngagementStore)
    before = original_bytes(layout)

    def fail():
        raise RuntimeError("fixture-secret")

    monkeypatch.setattr(runtime, "cli_main", fail)
    assert resume.main(["50"]) == 2
    assert "fixture-secret" not in capsys.readouterr().err
    assert (Path.cwd(), sys.argv, runtime.MemoryStore, runtime.EngagementStore) == original
    assert original_bytes(layout) == before
