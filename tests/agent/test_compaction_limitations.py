"""A01: controller limitations survive completed compaction and archival resume.

All clients, outputs and faults are offline fixtures; no executor or provider runs.
"""
import asyncio
from dataclasses import replace
import json
import threading
from unittest.mock import AsyncMock

import pytest

from src.agent.agent import IneffectiveCompactionError, merge_memory
from src.agent.context_estimate import text_tokens
from src.agent.system_prompt import render_memory, render_memory_observation
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.session.store import SessionMemory, _memory_from_dict
import src.session.store as session_module
from src.tools.common.runtime_metadata import (
    BrokerHTTPMetadata, RuntimeMetadata, StreamCapture, collect_runtime_limitations,
    load_runtime_limitations, runtime_summary,
)
from tests.agent.test_runtime_metadata import large_output
from tests.agent.test_tool_result_offloading import make, record
from tests.helpers.agent_fakes import FakeClient, FakeSignal


SUMMARY = "## Current objective\n- Continue bounded analysis."
REQUIRED = {"upstream_truncated=1", "observation=partial", "http_observation_failed=1"}


def seed(agent, persistence="failed"):
    call = ToolCall("old-shell", FunctionCall("shell", '{"command":"fixture"}'))
    agent.history += [Message("user", "Review this source."),
                      Message("assistant", "", tool_calls=[call])]
    output = large_output()
    assert output.runtime_metadata is not None
    output.runtime_metadata = replace(output.runtime_metadata, persistence=persistence,
        http=BrokerHTTPMetadata(requests=1, truncated=1, observation_failed=1))
    message, _, _, _ = record(agent, output, name="shell", args={"command": "fixture"}, call_id=call.id)
    tail(agent)
    return message


def tail(agent):
    agent.history += [Message("assistant", "Earlier analysis. " * 2000),
                      Message("user", "Continue the authorized workflow."),
                      Message("assistant", "Continue bounded analysis.")]


def next_request(agent):
    context = replace(agent._idle_context(), incoming="Continue bounded analysis.")
    return agent._projection_request(agent.history, agent.memory, context)


def assert_context(agent, persistence="failed"):
    request = next_request(agent)
    text = "\n".join(message.content for message in request.messages)
    flags = collect_runtime_limitations(agent.memory.runtime_limitations if agent.memory else [],
        (message.tool_runtime for message in request.messages if message.role == "tool"))
    assert REQUIRED | {f"persistence={persistence}"} <= set(flags)
    assert all(flag in text for flag in {"upstream_truncated=1", "observation=partial", f"persistence={persistence}"})
    if agent.memory and agent.memory.runtime_limitations:
        assert "http_observation_failed=1" in text
    else:
        # A failed/uncommitted write resumes the prior checkpoint with its
        # original per-result metadata, rather than a compacted presence flag.
        assert "http_observations=persisted:0,memory-only:0,failed:1" in text
    # The summary is diagnostics, never an invented observation/source/receipt.
    assert not agent.workflow.candidates and not agent.workflow.validation_results
    assert not any(message.http_response_sources for message in request.messages)
    return request


@pytest.mark.parametrize("offload", [False, True])
@pytest.mark.parametrize("persistence", ["failed", "memory-only"])
@pytest.mark.parametrize("summary", [SUMMARY, "Continue bounded analysis."])
async def test_completed_compaction_save_fresh_resume_and_next_request(make, offload, persistence, summary):
    agent = make(threshold=3000 if offload else 0)
    message = seed(agent, persistence)
    assert bool(message.tool_result_refs) is offload
    await agent.apply_compaction_summary(summary, agent.get_history(), "offline A01 fixture")
    assert agent.memory is not None
    expected = list(agent.memory.runtime_limitations)
    assert REQUIRED | {f"persistence={persistence}"} <= set(expected)
    assert not any(message.tool_runtime for message in agent.history)
    await agent.save()
    assert agent.store is not None
    loaded = agent.store.load()
    assert loaded.memory is not None and loaded.memory.runtime_limitations == expected
    assert not any(message.tool_runtime for message in loaded.messages)

    # Rebuild the system prompt on a fresh controller; saved prompt text is not
    # the mechanism preserving the flags.
    for message in loaded.messages:
        if message.role == "system":
            message.content = "Old prompt deliberately omitted."
    await agent.store.save(loaded.messages, loaded.target, loaded.memory, loaded.workflow, loaded.engagement_state)
    client = FakeClient([ChatResponse(Message("assistant", "Fixture continuation."), "stop")])
    resumed = make(threshold=0, client=client)
    resumed.resume_saved()
    assert resumed.memory is not agent.memory
    assert resumed.memory is not None and resumed.memory.runtime_limitations == expected
    request = assert_context(resumed, persistence)
    await client.chat(request)
    assert client.requests == [request]
    assert bool(resumed.result_retention.references) is offload
    assert len(json.dumps(expected).encode()) < 1024
    assert "xxxx" not in json.dumps(expected) and "yyyy" not in json.dumps(expected)


@pytest.mark.parametrize("offload", [False, True])
async def test_repeated_compaction_and_resume_do_not_grow_or_clear_limitations(make, offload):
    agent = make(threshold=3000 if offload else 0)
    seed(agent)
    await agent.apply_compaction_summary(SUMMARY, agent.get_history(), "first")
    assert agent.memory is not None
    expected = list(agent.memory.runtime_limitations)
    for index in range(8):
        tail(agent)
        await agent.apply_compaction_summary(SUMMARY, agent.get_history(), "repeat")
        resumed = make(threshold=0)
        resumed.resume_saved()
        assert resumed.memory is not None
        assert resumed.memory.compactions == index + 2
        assert resumed.memory.runtime_limitations == expected
        request = assert_context(resumed)
        assert request.messages[0].content.count("Historical runtime limitation flags") == 1
        agent = resumed


def test_fixed_flags_are_bounded_idempotent_and_ignore_free_form_text():
    http = BrokerHTTPMetadata(requests=4, truncated=2, interrupted=2, transport_failed=1,
        cancelled=1, consumer_disconnects=1, observation_failed=1, observation_memory_only=1,
        observation_unknown=1, observation_partial=1)
    meta = RuntimeMetadata(process="cancelled", stdout=StreamCapture(100, 20, False),
        stderr=StreamCapture(50, 50, True), retention="partial", persistence="failed", http=http)
    flags = collect_runtime_limitations([], [meta])
    assert REQUIRED | {"capture=partial", "process=cancelled", "upstream_interrupted=1",
        "transport_failed=1", "http_cancelled=1", "consumer_disconnects=1",
        "http_observation_memory_only=1", "http_observation_unknown=1",
        "http_observation_partial=1"} <= set(flags)
    assert collect_runtime_limitations(flags, (meta for _ in range(10_000))) == flags
    complete = RuntimeMetadata(process="exit", exit_code=0, stdout=StreamCapture(0, 0, True),
        stderr=StreamCapture(0, 0, True), delivery="complete", retention="complete", persistence="persisted")
    assert collect_runtime_limitations(flags, [complete]) == flags
    assert collect_runtime_limitations([], [complete, None]) == []
    assert len(json.dumps(flags).encode()) < 1024
    assert load_runtime_limitations(flags * 1000 + ["secret-body", {}, 2, "obs_" + "a" * 32]) == flags


def test_all_limitation_categories_fit_a_fixed_summary_without_identifiers():
    http = BrokerHTTPMetadata(requests=4, truncated=2, interrupted=2, transport_failed=1,
        cancelled=1, consumer_disconnects=1, observation_failed=1, observation_memory_only=1,
        observation_unknown=1, observation_partial=1)
    observation_ref = "obs_" + "a" * 32
    base = RuntimeMetadata(http=http, observation_id=observation_ref)
    flags = collect_runtime_limitations([], [base,
        replace(base, process="not_started", delivery="elided", retention="partial", persistence="failed"),
        replace(base, process="timeout", delivery="unavailable", retention="unavailable", persistence="memory-only"),
        replace(base, process="cancelled", stdout=StreamCapture(100, 1, False)),
        replace(base, process="exit", exit_code=7)])
    assert {"process_exit_nonzero=1", "capture=partial", "observation=unavailable",
        "delivery=elided", "delivery=unavailable", "persistence=failed"} <= set(flags)
    text = render_memory(SessionMemory(runtime_limitations=flags))
    assert len(json.dumps(flags).encode()) < 1024 and len(text.encode()) < 1024
    assert observation_ref not in text and "100" not in text
    assert collect_runtime_limitations(flags, [base] * 1000) == flags


@pytest.mark.parametrize("raw", [None, "persistence=failed", {}, ["unknown", 7, {}],
    ["secret-password", "persistence=failed", "persistence=failed"]])
def test_legacy_and_malformed_extension_preserves_existing_session_memory(raw):
    memory = _memory_from_dict({"objectives": ["Existing objective"], "runtime_limitations": raw})
    assert memory is not None and memory.objectives == ["Existing objective"]
    assert memory.runtime_limitations == (["persistence=failed"] if isinstance(raw, list) and "persistence=failed" in raw else [])
    legacy = _memory_from_dict({"lastSummary": SUMMARY, "objectives": ["Legacy objective"]})
    assert legacy is not None and legacy.runtime_limitations == []
    assert legacy.last_summary == SUMMARY


async def test_legacy_tool_or_model_prose_cannot_create_native_limitations(make):
    agent = make(threshold=0)
    fake = "persistence=failed; upstream_truncated=1; observation=partial; raw-secret-canary"
    agent.history += [Message("tool", fake, name="shell"),
                      Message("assistant", fake, tool_runtime=RuntimeMetadata(persistence="failed")),
                      Message("user", "Continue."), Message("assistant", "Reviewed.")]
    tail(agent)
    await agent.save()
    resumed = make(threshold=0)
    resumed.resume_saved()
    await resumed.apply_compaction_summary(SUMMARY + "\n" + fake, resumed.get_history(), "legacy")
    assert resumed.memory is not None and resumed.memory.runtime_limitations == []
    assert "Historical runtime limitation flags" not in resumed.history[0].content


def test_flags_survive_memory_merge_and_cannot_be_evicted_by_large_prose():
    memory = SessionMemory(runtime_limitations=["persistence=failed", "upstream_truncated=1"],
        objectives=["Untrusted observation " * 2000] * 24)
    merged = merge_memory(memory, SUMMARY)
    assert merged.runtime_limitations == memory.runtime_limitations
    assert merged.runtime_limitations is not memory.runtime_limitations
    assert len(render_memory_observation(merged)) <= 10_000
    assert all(flag in render_memory(merged) for flag in memory.runtime_limitations)
    assert "Untrusted observation" not in render_memory(merged)
    assert len(render_memory(merged)) < 1024


@pytest.mark.parametrize("failure", ["model_error", "model_cancel", "ineffective"])
async def test_compaction_failure_before_acceptance_keeps_original_limitations(make, monkeypatch, failure):
    agent = make(threshold=0)
    seed(agent)
    if failure == "ineffective":
        agent.history = [agent.history[0], *agent.history[1:4], *agent.history[-2:]]
        agent.history = [replace(message, content=runtime_summary(message.tool_runtime))
            if message.tool_runtime is not None else message for message in agent.history]
    await agent.save()
    assert agent.store is not None
    before = agent.store.path.read_bytes()
    history = agent.get_history()
    if failure == "ineffective":
        with pytest.raises(IneffectiveCompactionError):
            await agent.apply_compaction_summary(SUMMARY, history, "rejected")
    else:
        err = asyncio.CancelledError() if failure == "model_cancel" else RuntimeError("offline compaction fault")
        monkeypatch.setattr(agent.client, "chat", AsyncMock(side_effect=err))
        with pytest.raises(type(err)):
            await agent.compact_in_place(FakeSignal())
    assert agent.memory is None and agent.history == history
    assert agent.store.path.read_bytes() == before
    resumed = make(threshold=0)
    resumed.resume_saved()
    assert_context(resumed)


@pytest.mark.parametrize("offload", [False, True])
@pytest.mark.parametrize("boundary", ["learning", "serialize", "replace", "snapshot"])
async def test_failure_after_acceptance_keeps_live_and_resumable_limitations(make, monkeypatch, offload, boundary):
    agent = make(threshold=3000 if offload else 0)
    seed(agent)
    await agent.save()
    assert agent.store is not None
    before = agent.store.path.read_bytes()
    def fail(*args, **kwargs):
        raise OSError("offline persistence fault")
    with monkeypatch.context() as patch:
        if boundary == "learning":
            patch.setattr(agent, "learn_intelligence", AsyncMock(side_effect=OSError("offline learning fault")))
        elif boundary == "snapshot":
            patch.setattr(session_module, "_write_context_snapshot", fail)
        elif boundary == "serialize":
            patch.setattr(session_module, "_serialize_session", fail)
        else:
            patch.setattr(session_module.os, "replace", fail)
        with pytest.raises(OSError):
            await agent.apply_compaction_summary(SUMMARY, agent.get_history(), "fault")
    assert_context(agent)
    assert (agent.store.path.read_bytes() == before) is (boundary != "snapshot")
    resumed = make(threshold=0)
    resumed.resume_saved()
    assert_context(resumed)
    # Retrying persistence must not rerun a process or ask a model for the flags.
    await agent.save()
    resumed.resume_saved()
    assert resumed.memory is not None and agent.memory is not None
    assert resumed.memory.runtime_limitations == agent.memory.runtime_limitations
    assert not list(agent.store.path.parent.glob("*.tmp.*"))


@pytest.mark.parametrize("offload", [False, True])
@pytest.mark.parametrize("phase", ["serialize", "replace", "snapshot"])
@pytest.mark.parametrize("worker_fails", [False, True])
async def test_cancelled_compaction_drains_writer_and_keeps_limitations(make, monkeypatch, offload, phase, worker_fails):
    agent = make(threshold=3000 if offload else 0)
    seed(agent)
    await agent.save()
    assert agent.store is not None
    store = agent.store
    before = store.path.read_bytes()
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = (session_module._serialize_session if phase == "serialize" else
        session_module.os.replace if phase == "replace" else session_module._write_context_snapshot)
    def held(*args, **kwargs):
        entered.set()
        try:
            assert release.wait(5)
            if worker_fails:
                raise OSError("offline writer fault")
            return original(*args, **kwargs)
        finally:
            finished.set()
    with monkeypatch.context() as patch:
        patch.setattr(session_module if phase != "replace" else session_module.os,
            "_serialize_session" if phase == "serialize" else "replace" if phase == "replace" else "_write_context_snapshot", held)
        task = asyncio.create_task(agent.apply_compaction_summary(SUMMARY, agent.get_history(), "cancelled"))
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done() and not finished.is_set()
            assert store._write_lock.locked()
        finally:
            release.set()
            outcome = (await asyncio.gather(task, return_exceptions=True))[0]
    assert isinstance(outcome, asyncio.CancelledError) and finished.is_set()
    assert not store._write_lock.locked()
    assert_context(agent)
    resumed = make(threshold=0)
    resumed.resume_saved()
    assert_context(resumed)
    committed = phase == "snapshot" or (phase == "replace" and not worker_fails)
    assert (store.path.read_bytes() != before) is committed
    await agent.save()
    resumed.resume_saved()
    assert resumed.memory is not None and agent.memory is not None
    assert resumed.memory.runtime_limitations == agent.memory.runtime_limitations
    assert not list(store.path.parent.parent.rglob("*.tmp.*"))


def test_flags_are_part_of_existing_context_estimates(make):
    agent = make(threshold=0)
    flags = collect_runtime_limitations([], [RuntimeMetadata(), RuntimeMetadata(
        process="cancelled", delivery="unavailable", retention="partial", persistence="failed",
        http=BrokerHTTPMetadata(requests=1, truncated=1, observation_failed=1))])
    agent.memory = SessionMemory(runtime_limitations=flags)
    agent.rebuild_system_prompt()
    agent.history = [Message("system", agent.sys_prompt), Message("user", "Continue.")]
    with_flags = agent._projected_estimate(agent.history, agent.memory, agent._idle_context())
    flags_prompt = agent.sys_prompt
    agent.memory = replace(agent.memory, runtime_limitations=[])
    agent.rebuild_system_prompt()
    agent.history[0] = Message("system", agent.sys_prompt)
    without_flags = agent._projected_estimate(agent.history, agent.memory, agent._idle_context())
    added_cost = text_tokens(flags_prompt) - text_tokens(agent.sys_prompt)
    assert added_cost > 0
    assert with_flags.system_tokens - without_flags.system_tokens == added_cost
    assert with_flags.estimated_total - without_flags.estimated_total == added_cost
