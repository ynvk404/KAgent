from __future__ import annotations

import json
import os
import stat
from datetime import datetime
from pathlib import Path

import pytest

import src.session.store as session_store
from src.llm.types import FunctionCall, GeminiProvider, Message, ToolCall, ToolProvider
from src.session.store import (
    SessionLoadError,
    SessionMemory,
    Store,
    dir_from_path,
    list_dir,
    new_id,
)
from src.workflow.state import Candidate, ValidationResult, WorkflowState
from src.workflow.evidence import EvidenceArtifact
from src.engagement.state import EngagementState


class TestEngagementPersistence:
    @pytest.mark.asyncio
    async def test_exact_origin_scope_survives_round_trip(self, tmp_path):
        store = Store.new_with_id(tmp_path, "engagement-round-trip")
        engagement = EngagementState()
        engagement.initialize_target("https://App.Example:443/base")
        engagement.add_origin("https://api.example:8443/path")

        await store.save(
            [Message(role="user", content="continue")],
            engagement_state=engagement,
        )

        loaded = store.load()
        assert loaded.engagement_state == engagement
        assert loaded.engagement_state.is_in_scope("https://app.example/path")
        assert loaded.engagement_state.is_in_scope("https://api.example:8443/other")
        assert loaded.engagement_state.revision == 2

    def test_legacy_session_derives_scope_from_saved_target(self, tmp_path):
        store = Store.new_with_id(tmp_path, "legacy-target")
        store.path.write_text(
            json.dumps(
                {
                    "updated_at": "",
                    "messages": [],
                    "target": {"baseURL": "http://juice.lab:3000/app", "name": ""},
                }
            ),
            encoding="utf-8",
        )

        loaded = store.load()

        assert loaded.engagement_state.is_in_scope("http://juice.lab:3000/api")
        assert not loaded.engagement_state.is_in_scope("http://juice.lab:4000/api")


class TestWorkflowPersistence:
    @pytest.mark.asyncio
    async def test_requeued_candidate_survives_session_save_and_resume(self, tmp_path):
        store = Store.new_with_id(tmp_path, "requeued-workflow")
        workflow = WorkflowState()
        candidate, _ = workflow.add_candidate(Candidate(
            candidate_class="xss", target="https://target.test", endpoint="/search",
        ))
        workflow.add_validation_result(ValidationResult(
            candidate.id, "cross-site-scripting", "deferred",
            deferred_reason="browser unavailable",
        ))
        workflow.set_candidate_status(candidate.id, "queued")

        await store.save([Message(role="user", content="resume validation")],
                         workflow=workflow)
        resumed = store.load().workflow

        assert resumed.candidates[candidate.id].status == "queued"
        assert candidate.id in resumed.active_candidate_ids
        latest = resumed.latest_result(candidate.id)
        assert latest is not None
        assert latest.outcome == "deferred"

    @pytest.mark.asyncio
    async def test_candidate_and_result_survive_round_trip(self, tmp_path):
        store = Store.new_with_id(tmp_path, "workflow-round-trip")
        workflow = WorkflowState(current_phase="validation")
        candidate, _ = workflow.add_candidate(
            Candidate(
                candidate_class="sqli",
                method="POST",
                endpoint="/product",
                parameter="id",
                source_skill="web-input-analysis",
            )
        )
        (tmp_path / "request-7.txt").write_text(
            "Observed request and response", encoding="utf-8",
        )
        artifact = EvidenceArtifact.capture(candidate.id, "request-7.txt", tmp_path)
        workflow.add_evidence(artifact)
        workflow.add_validation_result(
            ValidationResult(
                candidate.id,
                "sql-injection",
                "confirmed",
                evidence_refs=[artifact.id],
            )
        )

        await store.save(
            [Message(role="user", content="validate")],
            workflow=workflow,
        )
        loaded = store.load().workflow

        assert loaded.to_dict() == workflow.to_dict()
        assert loaded.latest_result(candidate.id) is not None
        assert loaded.eligible_for_finding(candidate.id) is True

    def test_old_session_without_workflow_loads_empty_state(self, tmp_path):
        store = Store.new_with_id(tmp_path, "old")
        store.path.write_text(
            json.dumps({"messages": [{"role": "user", "content": "hi"}]}),
            encoding="utf-8",
        )

        assert store.load().workflow.to_dict() == WorkflowState().to_dict()

    @pytest.mark.parametrize("workflow", [None, "bad", ["bad"], {"candidates": "bad"}])
    def test_malformed_or_empty_workflow_degrades_safely(self, tmp_path, workflow):
        store = Store.new_with_id(tmp_path, "malformed-workflow")
        store.path.write_text(json.dumps({"workflow": workflow}), encoding="utf-8")

        assert store.load().workflow.candidates == {}
        assert store.load().workflow.validation_results == []

class TestEmptyPathGuards:
    @pytest.mark.asyncio
    async def test_save_is_noop_with_empty_path(self, tmp_path):
        store = Store("", "")
        await store.save([Message(role="user", content="x")], None)
        assert not any(Path(".").glob("*.tmp.*"))

    @pytest.mark.asyncio
    async def test_clear_is_noop_with_empty_path(self):
        store = Store("", "")
        await store.clear()

    @pytest.mark.asyncio
    async def test_save_context_snapshot_is_noop_with_empty_path(self):
        store = Store("", "")
        out = await store.save_context_snapshot("hello")
        assert out == ""

class TestTmpFilePermissionRace:
    @pytest.mark.asyncio
    async def test_tmp_file_is_0600_at_creation_not_only_after_rename(
        self, tmp_path, monkeypatch
    ):
        store = Store.new_with_id(tmp_path, new_id())
        observed_modes = []

        real_replace = os.replace

        def spy_replace(src, dst):
            observed_modes.append(stat.S_IMODE(os.stat(src).st_mode))
            return real_replace(src, dst)

        monkeypatch.setattr(os, "replace", spy_replace)

        memory = SessionMemory(credentials=["super-secret-token"])
        await store.save([Message(role="user", content="x")], None, memory)

        assert observed_modes, "os.replace was never called"
        assert observed_modes[0] == 0o600, (
            f"tmp file had mode {oct(observed_modes[0])} before rename; "
            "should be 0600 from creation, not only after chmod"
        )


class TestDirectoryPermissions:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("mode", [0o755, 0o777])
    async def test_save_tightens_existing_session_directory(self, tmp_path, mode):
        if os.name != "posix":
            pytest.skip("POSIX directory modes are required")
        directory = tmp_path / "sessions"
        directory.mkdir()
        directory.chmod(mode)
        if stat.S_IMODE(directory.stat().st_mode) != mode:
            pytest.skip("filesystem does not honor POSIX directory modes")

        await Store.new_with_id(directory, "session").save(
            [Message(role="user", content="private")]
        )

        assert stat.S_IMODE(directory.stat().st_mode) == 0o700

    @pytest.mark.asyncio
    async def test_snapshot_tightens_existing_context_directory(self, tmp_path):
        if os.name != "posix":
            pytest.skip("POSIX directory modes are required")
        directory = tmp_path / "context"
        directory.mkdir()
        directory.chmod(0o755)
        if stat.S_IMODE(directory.stat().st_mode) != 0o755:
            pytest.skip("filesystem does not honor POSIX directory modes")

        store = Store.new_with_id(tmp_path / "sessions", "session")
        await store.save_context_snapshot("private context")

        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert store.context_snapshot_path().read_text() == "private context\n"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("failure", [OSError, NotImplementedError])
    async def test_unsupported_directory_chmod_does_not_fail_save_or_snapshot(
        self, tmp_path, monkeypatch, failure
    ):
        def fail_chmod(_path, _mode):
            raise failure("chmod unavailable")

        monkeypatch.setattr(Path, "chmod", fail_chmod)
        store = Store.new_with_id(tmp_path / "sessions", "session")

        await store.save([Message(role="user", content="still saved")])
        await store.save_context_snapshot("still captured")

        assert store.load().messages[0].content == "still saved"
        assert store.context_snapshot_path().read_text() == "still captured\n"


class TestTempCollisionOwnership:
    @pytest.mark.asyncio
    async def test_save_preserves_temp_file_it_did_not_create(
        self, tmp_path, monkeypatch
    ):
        store = Store.new_with_id(tmp_path, "session")
        monkeypatch.setattr(session_store, "random_tmp_id", lambda: "fixed")
        temp = Path(f"{store.path}.tmp.fixed")
        temp.write_text("another writer's temp", encoding="utf-8")

        with pytest.raises(FileExistsError):
            await store.save([Message(role="user", content="x")])

        assert temp.read_text(encoding="utf-8") == "another writer's temp"

    @pytest.mark.asyncio
    async def test_snapshot_preserves_temp_file_it_did_not_create(
        self, tmp_path, monkeypatch
    ):
        store = Store.new_with_id(tmp_path / "sessions", "session")
        monkeypatch.setattr(session_store, "random_tmp_id", lambda: "fixed")
        temp = Path(f"{store.context_snapshot_path()}.tmp.fixed")
        temp.parent.mkdir(parents=True)
        temp.write_text("another writer's temp", encoding="utf-8")

        with pytest.raises(FileExistsError):
            await store.save_context_snapshot("snapshot")

        assert temp.read_text(encoding="utf-8") == "another writer's temp"


class TestMessageProviderState:
    @pytest.mark.asyncio
    async def test_preserves_raw_ask_user_tool_result_across_session_round_trip(
        self, tmp_path
    ):
        raw = json.dumps(
            {
                "answers": [
                    {
                        "question": "Which endpoint should be tested?",
                        "answer": "POST /login username",
                    }
                ]
            },
            indent=2,
        )
        store = Store.new_with_id(tmp_path, new_id())
        await store.save(
            [
                Message(
                    role="tool",
                    content=raw,
                    tool_call_id="call_ask",
                    name="ask_user",
                )
            ]
        )

        loaded = store.load().messages[0]

        assert loaded.role == "tool"
        assert loaded.content == raw
        assert loaded.tool_call_id == "call_ask"
        assert loaded.name == "ask_user"

    @pytest.mark.asyncio
    async def test_preserves_reasoning_content_across_session_round_trip(self, tmp_path):
        store = Store.new_with_id(tmp_path, new_id())
        await store.save(
            [
                Message(
                    role="assistant",
                    content="answer",
                    reasoning_content="provider state",
                )
            ]
        )

        loaded = store.load()

        assert loaded.messages[0].content == "answer"
        assert loaded.messages[0].reasoning_content == "provider state"

    @pytest.mark.asyncio
    async def test_preserves_tool_calls_and_provider_metadata(self, tmp_path):
        store = Store.new_with_id(tmp_path, new_id())
        await store.save(
            [
                Message(
                    role="assistant",
                    content="",
                    tool_calls=[
                        ToolCall(
                            id="call_1",
                            function=FunctionCall("lookup", '{"q":"x"}'),
                            provider=ToolProvider(
                                gemini=GeminiProvider("signature")
                            ),
                        )
                    ],
                )
            ]
        )

        tool_calls = store.load().messages[0].tool_calls
        assert tool_calls is not None
        tool_call = tool_calls[0]
        assert tool_call.provider is not None
        assert tool_call.provider.gemini is not None

        assert tool_call.id == "call_1"
        assert tool_call.function.name == "lookup"
        assert tool_call.function.arguments == '{"q":"x"}'
        assert tool_call.provider.gemini.thought_signature == "signature"


class TestMalformedPersistence:
    def test_drops_invalid_memory_before_compaction_can_use_it(self, tmp_path):
        store = Store.new_with_id(tmp_path, "bad-memory")
        store.path.write_text(
            json.dumps(
                {
                    "memory": {
                        "compactions": "many",
                        "objectives": "not a list",
                    }
                }
            ),
            encoding="utf-8",
        )

        assert store.load().memory is None

    def test_skips_invalid_message_and_tool_call_values(self, tmp_path):
        store = Store.new_with_id(tmp_path, "bad-message")
        store.path.write_text(
            json.dumps(
                {
                    "messages": [
                        {"role": "user", "content": ["not text"]},
                        {
                            "role": "assistant",
                            "content": "ok",
                            "tool_calls": [
                                {"id": "call", "function": "not an object"}
                            ],
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )

        messages = store.load().messages

        assert len(messages) == 1
        assert messages[0].content == "ok"
        assert messages[0].tool_calls is None

class TestCrossFormatMemoryCompat:
    @pytest.mark.asyncio
    async def test_loads_memory_written_by_ts_store_camel_case(self, tmp_path):
        store = Store.new_with_id(tmp_path, "ts-written")
        ts_style_file = {
            "updated_at": "2026-01-01T00:00:00",
            "id": "ts-written",
            "target": None,
            "memory": {
                "version": 1,
                "updatedAt": "2026-01-01T00:00:00",
                "compactions": 3,
                "lastCompactedAt": "2026-01-01T00:00:00",
                "lastSummary": "compacted once",
                "objectives": [],
                "plan": [],
                "completed": [],
                "findings": ["idor on /api/orders/1"],
                "tested": [],
                "files": [],
                "commands": [],
                "credentials": ["USER_A_TOKEN placeholder"],
                "todos": [],
            },
            "messages": [{"role": "user", "content": "hi"}],
        }
        store.path.write_text(json.dumps(ts_style_file), encoding="utf-8")

        loaded = store.load()

        assert loaded.memory is not None, (
            "memory bị drop khi load file do TS store ghi (camelCase keys)"
        )
        assert loaded.memory.compactions == 3
        assert loaded.memory.last_compacted_at == "2026-01-01T00:00:00"
        assert loaded.memory.last_summary == "compacted once"
        assert loaded.memory.credentials == ["USER_A_TOKEN placeholder"]

    @pytest.mark.asyncio
    async def test_still_loads_native_python_snake_case_memory(self, tmp_path):
        store = Store.new_with_id(tmp_path, new_id())
        memory = SessionMemory(compactions=9, last_summary="native")
        await store.save([Message(role="user", content="hi")], None, memory)
        loaded = store.load()
        assert loaded.memory is not None
        assert loaded.memory.compactions == 9
        assert loaded.memory.last_summary == "native"

class TestListDir:
    def test_returns_empty_list_for_missing_dir(self, tmp_path):
        assert list_dir(tmp_path / "does-not-exist") == []

    @pytest.mark.asyncio
    async def test_lists_newest_first_and_skips_corrupt_files(self, tmp_path):
        store_old = Store.new_with_id(tmp_path, "old-session")
        store_new = Store.new_with_id(tmp_path, "new-session")

        await store_old.save([Message(role="user", content="first one")], None)
        raw_old = json.loads(store_old.path.read_text())
        raw_old["updated_at"] = "2020-01-01T00:00:00"
        store_old.path.write_text(json.dumps(raw_old))

        await store_new.save([Message(role="user", content="second one")], None)
        raw_new = json.loads(store_new.path.read_text())
        raw_new["updated_at"] = "2026-01-01T00:00:00"
        store_new.path.write_text(json.dumps(raw_new))

        (tmp_path / "corrupt-session.json").write_text("{not valid json")

        entries = list_dir(tmp_path)
        ids = [e.id for e in entries]

        assert "corrupt-session.json" not in [Path(e.path).name for e in entries]
        assert ids.index("new-session") < ids.index("old-session")

    @pytest.mark.asyncio
    async def test_preview_strips_referenced_files_marker_and_first_line_only(
        self, tmp_path
    ):
        store = Store.new_with_id(tmp_path, new_id())
        content = "Investigate login bypass\nsecond line\n\n# Referenced files\n\napp.py"
        await store.save([Message(role="user", content=content)], None)

        entries = list_dir(tmp_path)
        assert entries[0].preview == "Investigate login bypass"

    @pytest.mark.asyncio
    async def test_preview_truncates_long_first_line_with_ellipsis(self, tmp_path):
        store = Store.new_with_id(tmp_path, new_id())
        long_line = "x" * 100
        await store.save([Message(role="user", content=long_line)], None)

        entries = list_dir(tmp_path)
        assert len(entries[0].preview) == 80
        assert entries[0].preview.endswith("…")

    @pytest.mark.asyncio
    async def test_preview_falls_back_when_no_user_messages(self, tmp_path):
        store = Store.new_with_id(tmp_path, new_id())
        await store.save([Message(role="assistant", content="hi")], None)

        entries = list_dir(tmp_path)
        assert entries[0].preview == "(no user messages)"

    def test_handles_invalid_updated_at_type(self, tmp_path):
        store = Store.new_with_id(tmp_path, "bad-timestamp")
        store.path.write_text(
            json.dumps({"updated_at": ["not a timestamp"], "messages": []}),
            encoding="utf-8",
        )

        entries = list_dir(tmp_path)

        assert entries[0].id == "bad-timestamp"

class TestLoadPropagatesCorruption:
    def test_raises_on_unparsable_session(self, tmp_path):
        store = Store.new_with_id(tmp_path, "broken")
        store.path.write_text("{not valid json", encoding="utf-8")

        with pytest.raises(SessionLoadError):
            store.load()

    def test_raises_when_session_is_not_an_object(self, tmp_path):
        store = Store.new_with_id(tmp_path, "listy")
        store.path.write_text("[]", encoding="utf-8")

        with pytest.raises(SessionLoadError):
            store.load()

    def test_returns_empty_session_when_file_is_absent(self, tmp_path):
        store = Store.new_with_id(tmp_path, "missing")
        assert store.load().messages == []
