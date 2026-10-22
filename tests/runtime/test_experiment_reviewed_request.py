"""Reviewed prompt profiles: local fixtures only; no provider, lab, or scanner I/O."""
import json
from pathlib import Path

import pytest

from scripts import experiment_profile as profile
from src.cli.prompt_file import read_prompt_file
from src.workflow.planning.goals import extract_requested_classes
from tests.runtime.test_experiment_profile import layout, original_bytes


ENGLISH = (
    b"Perform a whole-target assessment of the authorized target. "
    b"Discover endpoints and inputs, analyze them, then validate SQL Injection and XSS. "
    b"Stay within the declared origin and existing permissions and budgets. "
    b"Use minimal non-sensitive proof; do not extract credentials or bulk data.\n"
)


@pytest.fixture
def reviewed(layout, tmp_path):
    source = tmp_path / "reviewed-request.txt"
    source.write_bytes(ENGLISH)
    value = profile.plan(layout[0], layout[1], layout[2], layout[3], "http://127.0.0.1:8081", prompt_file=source)
    return source, value


def test_exact_reviewed_request_prepare_verify_and_parser_preserve_originals(layout, reviewed):
    source, value = reviewed
    before = original_bytes(layout)
    receipt = profile.apply(value)
    assert profile.verify(receipt) == value
    copied = receipt.parent / "whole-target-request.txt"
    assert copied.read_bytes() == source.read_bytes() == ENGLISH
    assert value["reviewed_request"] == {
        "source": str(source), "sha256": profile.digest(ENGLISH), "bytes": len(ENGLISH),
    }
    assert extract_requested_classes(read_prompt_file(copied)) == ["sql-injection", "cross-site-scripting"]
    assert original_bytes(layout) == before
    assert not (layout[3] / "launch-started.json").exists()


def test_dry_run_cli_pins_bytes_without_copying_prompt_into_plan(layout, reviewed, monkeypatch, capsys):
    source, _ = reviewed
    monkeypatch.setenv("kagent_CONFIG", str(layout[2]))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: layout[1]))
    assert profile.main(["--dry-run", "--repo", str(layout[0]), "--run-dir", str(layout[3]),
                         "--prompt-file", str(source)]) == 0
    output = capsys.readouterr().out
    value = json.loads(output)
    assert value["version"] == 4
    assert value["reviewed_request"]["sha256"] == profile.digest(ENGLISH)
    assert ENGLISH.decode().strip() not in output
    assert not layout[3].exists()


@pytest.mark.parametrize("fault", ["source-byte", "hash", "size", "plan-hash"])
def test_wrong_prompt_or_approval_refuses_before_creating_run(layout, reviewed, tmp_path, fault):
    source, value = reviewed
    if fault == "source-byte":
        source.write_bytes(ENGLISH[:-1] + b"!")
    elif fault == "hash":
        value["reviewed_request"]["sha256"] = "0" * 64
    elif fault == "size":
        value["reviewed_request"]["bytes"] += 1
    raw = profile.encode(value)
    plan_file = tmp_path / "plan.json"
    plan_file.write_bytes(raw)
    approved = "0" * 64 if fault == "plan-hash" else profile.digest(raw)
    assert profile.main(["--apply", "--plan", str(plan_file), "--approve-plan-sha256", approved]) == 2
    assert not layout[3].exists() and not Path(value["profile"]).exists()


@pytest.mark.parametrize("fault", ["copy-byte", "copy-lf", "source-byte", "source-missing", "hash", "size", "downgrade"])
def test_verify_refuses_prompt_or_metadata_changes(reviewed, fault):
    source, value = reviewed
    receipt = profile.apply(value)
    copied = receipt.parent / "whole-target-request.txt"
    if fault == "copy-byte":
        copied.write_bytes(ENGLISH[:-1] + b"!")
    elif fault == "copy-lf":
        copied.write_bytes(ENGLISH.replace(b"\n", b"\r\n"))
    elif fault == "source-byte":
        source.write_bytes(ENGLISH + b"\n")
    elif fault == "source-missing":
        source.unlink()
    else:
        changed = json.loads(receipt.read_text())
        if fault == "hash":
            changed["reviewed_request"]["sha256"] = "0" * 64
        elif fault == "size":
            changed["reviewed_request"]["bytes"] = True
        else:
            changed["version"] = 2
        receipt.write_bytes(profile.encode(changed))
    with pytest.raises((ValueError, OSError)):
        profile.verify(receipt)


@pytest.mark.parametrize("data", [b"", b" \n", b"bad\x1b[31m", b"\xff", b"x" * (65536 + 1)])
def test_review_reuses_cli_prompt_validation_before_writes(layout, tmp_path, data):
    source = tmp_path / "invalid.txt"
    source.write_bytes(data)
    with pytest.raises(ValueError):
        profile.plan(layout[0], layout[1], layout[2], layout[3], "http://127.0.0.1:8081", prompt_file=source)
    assert not layout[3].exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_review_rejects_linked_and_special_files(layout, tmp_path, kind):
    import os
    source, path = tmp_path / "source.txt", tmp_path / "request.txt"
    source.write_bytes(ENGLISH)
    if kind == "symlink":
        path.symlink_to(source)
    elif kind == "hardlink":
        os.link(source, path)
    else:
        os.mkfifo(path)
    with pytest.raises(ValueError):
        profile.plan(layout[0], layout[1], layout[2], layout[3], "http://127.0.0.1:8081", prompt_file=path)
    assert not layout[3].exists() and source.read_bytes() == ENGLISH


def test_prompt_changed_during_prepare_never_publishes_receipt(reviewed, monkeypatch):
    source, value = reviewed
    write = profile.private_write
    def interrupt(path, data):
        write(path, data)
        if path.name == "SKILL.md":
            source.write_bytes(ENGLISH + b"\n")
    monkeypatch.setattr(profile, "private_write", interrupt)
    with pytest.raises(ValueError, match="request"):
        profile.apply(value)
    assert not (Path(value["profile"]) / "profile.json").exists()


@pytest.mark.parametrize("mode", ["--apply", "--verify", "--launch"])
def test_runtime_prompt_override_is_refused_without_launch(layout, reviewed, mode):
    source, value = reviewed
    args = [mode] if mode == "--apply" else [mode, str(Path(value["profile"]) / "profile.json")]
    assert profile.main([*args, "--prompt-file", str(source)]) == 2
    assert not layout[3].exists()


def test_reviewed_profiles_remain_fresh_independent_and_single_use(layout, reviewed):
    from src.session import store as sessions
    source, first = reviewed
    first_receipt = profile.apply(first)
    before = original_bytes(layout)
    with pytest.raises(ValueError):
        profile.apply(first)
    second = profile.plan(layout[0], layout[1], layout[2], layout[3].with_name("run-2"), first["origin"], prompt_file=source)
    second_receipt = profile.apply(second)
    for value in (first, second):
        with profile.bound_runtime(value) as runtime:
            assert runtime.MemoryStore().index() == ""
            assert runtime.EngagementStore().load() == ""
            assert not runtime.IntelligenceStore().search("juice shop canary", 5)
            state = sessions.Store.new_with_id(sessions.dir_from_path(), "fresh-fixture").load()
            assert state.messages == [] and state.workflow.objective is None
    assert first_receipt != second_receipt and original_bytes(layout) == before
    # No session was persisted in these read-only checks.
    assert profile.verify(second_receipt) == second
    profile.private_write(Path(first["run"]) / "launch-started.json", b"{}\n")
    with pytest.raises(ValueError, match="already been launched"):
        profile.verify(first_receipt)


@pytest.mark.parametrize("raw", [b"Validate SQL Injection.\n", b"\xef\xbb\xbfValidate XSS.\r\n"])
def test_future_reviewed_requests_preserve_raw_bytes_without_hardcoded_hash(layout, tmp_path, raw):
    source = tmp_path / "future.txt"
    source.write_bytes(raw)
    value = profile.plan(layout[0], layout[1], layout[2], layout[3], "http://127.0.0.1:8081", prompt_file=source)
    receipt = profile.apply(value)
    assert (receipt.parent / "whole-target-request.txt").read_bytes() == raw
    assert profile.verify(receipt)["reviewed_request"]["sha256"] == profile.digest(raw)


def test_legacy_v2_profiles_keep_generated_request(layout):
    value = profile.plan(layout[0], layout[1], layout[2], layout[3], "http://127.0.0.1:8081", legacy_bounded=True)
    assert value["version"] == 2 and "reviewed_request" not in value
    receipt = profile.apply(value)
    assert (receipt.parent / "whole-target-request.txt").read_bytes() == profile.whole_target_request(value).encode()
    assert profile.verify(receipt) == value


def test_legacy_reviewed_launch_uses_verified_copy_and_unchanged_flags(layout, reviewed, monkeypatch):
    from src.cli import runtime
    source, _ = reviewed
    value = profile.plan(layout[0], layout[1], layout[2], layout[3], "http://127.0.0.1:8081",
                         prompt_file=source, legacy_bounded=True)
    receipt = profile.apply(value)
    called = []
    def inspect():
        flags = runtime.parse_flags(profile.sys.argv[1:])
        assert Path(flags.prompt_file).read_bytes() == source.read_bytes() == ENGLISH
        assert flags.headless and flags.non_interactive and flags.execute_prompt and flags.yolo
        assert not flags.browser and not flags.burp and not flags.resume_id
        assert flags.max_steps == 60
        assert flags.http_lab_grants == ["http://127.0.0.1:8081,autonomous,1200,500,3,3,2,131072,65536"]
        called.append(True)
        return 0
    monkeypatch.setattr(runtime, "cli_main", inspect)
    assert profile.launch(receipt, headless=True, execute_prompt=True, yolo=True,
                          accept_unknown_http_effects=True) == 0
    assert called == [True]
