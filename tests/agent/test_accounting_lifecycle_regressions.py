"""Offline production-loop regressions for interrupted deferred retention."""
import asyncio
from copy import deepcopy
import json
from typing import cast

import pytest

from src.agent.agent import AgentRunOptions
from src.llm.core.types import ChatResponse, FunctionCall, Message, ToolCall
from src.permission.permission import AlwaysAllow, AlwaysDeny, UserControlledRefusal
from src.session.store import Store
from src.tools.common.registry import Registry, InvalidToolArguments
from src.tools.execution.file import FileReadTool
from tests.agent.test_token_accounting_independent_verify import make_agent, SnapshotClient
from tests.helpers.agent_fakes import FakeSignal

CANARY = "OMITTED-MIDDLE-CANARY"
PAYLOAD = "HEAD\n" + "x" * 6000 + CANARY + "y" * 34000 + "\nTAIL"


def setup_run(tmp_path, monkeypatch, *, count=1, threshold=3000, preserve=False):
    monkeypatch.setattr("src.agent.tool_results.project_root", lambda: tmp_path)
    registry = Registry()
    tool = FileReadTool()
    if preserve:
        monkeypatch.setattr(tool, "context_reduction_policy", lambda: "preserve", raising=False)
    registry.register(tool)
    calls = []
    for i in range(count):
        path = tmp_path / f"source-{i}.txt"
        path.write_text(PAYLOAD)
        calls.append(ToolCall(f"read-{i}", FunctionCall("file_read", json.dumps({"path": str(path)}))))
    client = SnapshotClient([
        ChatResponse(Message("assistant", "", tool_calls=calls), "tool_calls"),
        ChatResponse(Message("assistant", "done"), "stop"),
    ])
    agent = make_agent(tools=registry, store=Store.new_with_id(tmp_path / "sessions", "lifecycle"), client=client)
    agent.set_auto_compact_threshold(threshold)
    return agent, registry, client


async def assert_resume_and_reread(agent, registry, tmp_path, monkeypatch, *, expected):
    saved = cast(Store, agent.store).load()
    saved_tools = [m for m in saved.messages if m.role == "tool" and m.name == "file_read"]
    assert len(saved_tools) == expected
    assert len(agent.result_retention.references) == expected
    assert not agent.result_retention.pending
    assert all(m.tool_result_refs and len(m.content) < len(PAYLOAD) for m in saved_tools)
    assert all(CANARY not in m.content for m in saved_tools)
    restored = make_agent(tools=registry, store=Store.new_with_id(tmp_path / "sessions", "lifecycle"))
    store = restored.result_retention.store
    assert store is not None
    resolve = store.resolve
    # Resume, guard, estimation and dispatch must never read a full artifact.
    monkeypatch.setattr(store, "resolve", lambda *a: pytest.fail("implicit artifact hydration"))
    restored.resume_saved()
    assert len(restored.result_retention.references) == expected
    restored.set_auto_compact_threshold(3000)
    restored.consecutive_compact_failures = 3
    events = []
    await restored.run("Continue from the recorded result", FakeSignal(), events.append, AgentRunOptions(max_steps=1))
    requests = cast(SnapshotClient, restored.client).requests
    assert len(requests) == 1
    represented = [m for m in requests[0].messages if m.role == "tool" and m.name == "file_read" and m.tool_result_refs]
    assert len(represented) == expected
    assert all(m.tool_result_refs and CANARY not in m.content for m in represented)
    monkeypatch.setattr(store, "resolve", resolve)

    class Operator(AlwaysAllow):
        def __init__(self):
            self.requests = []
        async def ask(self, request, signal=None):
            self.requests.append(request)
            return await super().ask(request, signal)

    operator = Operator()
    for ref in restored.result_retention.references.values():
        args = {"result_ref": ref.result_ref, "start_char": PAYLOAD.index(CANARY), "max_chars": len(CANARY)}
        reply = json.loads(await restored.tools.execute("read_tool_result", args, FakeSignal(), operator))
        assert reply["content"] == CANARY
        assert resolve(ref, restored.result_retention.scope["generation"])[0] == PAYLOAD
        with pytest.raises(UserControlledRefusal):
            await restored.tools.execute("read_tool_result", args, FakeSignal(), AlwaysDeny())
        other = make_agent(tools=registry, store=Store.new_with_id(tmp_path / "sessions", "other"))
        with pytest.raises(InvalidToolArguments, match="unavailable in this session/project/target generation"):
            await other.tools.execute("read_tool_result", args, FakeSignal(), operator)
    assert operator.requests and all(r.no_session_cache for r in operator.requests)
    before = deepcopy(restored.history)
    restored.target.set_base_url("https://different-target.invalid")
    with pytest.raises(InvalidToolArguments, match="unavailable in this session/project/target generation"):
        await restored.tools.execute("read_tool_result", args, FakeSignal(), operator)
    assert restored.history == before
    # Repeated resume neither creates references nor replaces artifact identities.
    again = make_agent(tools=registry, store=Store.new_with_id(tmp_path / "sessions", "lifecycle"))
    again.resume_saved()
    assert set(again.result_retention.references) == {r.result_ref for r in agent.result_retention.references.values()}


@pytest.mark.parametrize("interruption", ["normal", "abort", "cancel"])
@pytest.mark.parametrize("count", [1, 2])
async def test_saved_batch_interruption_resume_keeps_readable_refs(tmp_path, monkeypatch, interruption, count):
    agent, registry, client = setup_run(tmp_path, monkeypatch, count=count)
    signal = FakeSignal()
    saved = asyncio.Event()
    release = asyncio.Event()
    original_save = agent.save
    snapshots = []
    async def save():
        await original_save()
        if agent.history[-1].role == "tool":
            snapshots.append(cast(Store, agent.store).load())
            saved.set()
            if interruption == "abort":
                signal.aborted = True
            elif interruption == "cancel":
                await release.wait()
    monkeypatch.setattr(agent, "save", save)
    task = asyncio.create_task(agent.run("Read the local files", signal, lambda _: None, AgentRunOptions(max_steps=2)))
    await asyncio.wait_for(saved.wait(), 10)
    if interruption == "cancel":
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()  # Repeated cancellation cannot abandon a pending writer.
        await asyncio.sleep(0)
        assert not task.done() and agent.running
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 10)
    else:
        await asyncio.wait_for(task, 10)
    assert snapshots and all(m.tool_result_refs for m in snapshots[0].messages if m.role == "tool")
    assert len(client.requests) == (2 if interruption == "normal" else 1)
    assert not agent.running and not agent._tool_results_unsaved
    await assert_resume_and_reread(agent, registry, tmp_path, monkeypatch, expected=count)


async def test_cancel_between_sequential_results_saves_completed_original(tmp_path, monkeypatch):
    agent, registry, client = setup_run(tmp_path, monkeypatch, count=2)
    # Use the real sequential executor so the boundary is between result 1 and
    # permission suspension for result 2; neither executor nor registry is mocked.
    monkeypatch.setattr("src.agent.agent.STATEFUL_TOOLS", {"file_read"})
    second_permission = asyncio.Event()
    class Operator(AlwaysAllow):
        def __init__(self): self.calls = 0
        async def ask(self, request, signal=None):
            self.calls += 1
            if self.calls == 2:
                second_permission.set()
                await asyncio.Event().wait()
            return await super().ask(request, signal)
    agent.prompter = Operator()
    monkeypatch.setattr(registry.get("file_read"), "requires_permission", lambda: True)
    task = asyncio.create_task(agent.run("Read both local files", FakeSignal(), lambda _: None, AgentRunOptions(max_steps=2)))
    await asyncio.wait_for(second_permission.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 10)
    assert len(client.requests) == 1
    await assert_resume_and_reread(agent, registry, tmp_path, monkeypatch, expected=1)


@pytest.mark.parametrize("preserve,threshold", [(True, 3000), (False, 100000)])
async def test_interruption_does_not_force_retention(tmp_path, monkeypatch, preserve, threshold):
    agent, registry, _ = setup_run(tmp_path, monkeypatch, preserve=preserve, threshold=threshold)
    signal = FakeSignal()
    original_save = agent.save
    async def save():
        await original_save()
        if agent.history[-1].role == "tool": signal.aborted = True
    monkeypatch.setattr(agent, "save", save)
    await agent.run("Read local file", signal, lambda _: None)
    persisted = next(m for m in cast(Store, agent.store).load().messages if m.role == "tool")
    assert persisted.content == PAYLOAD and not persisted.tool_result_refs
    assert not agent.result_retention.references
    restored = make_agent(tools=registry, store=agent.store)
    restored.resume_saved()
    assert not restored.result_retention.pending  # Untrusted history is never backfilled.


async def test_capacity_rejection_after_execution_persists_retention_without_dispatch(tmp_path, monkeypatch):
    agent, registry, client = setup_run(tmp_path, monkeypatch)
    original = client.chat
    async def chat(req, signal=None):
        response = await original(req, signal)
        setattr(client, "input_token_limit", 100)
        return response
    monkeypatch.setattr(client, "chat", chat)
    agent.set_auto_compact_threshold(0)
    events = []
    await agent.run("Read local file", FakeSignal(), events.append, AgentRunOptions(max_steps=1))
    assert events[-1].stop_reason == "context_capacity"
    assert len(client.requests) == events[-1].total_llm_calls == 1
    assert events[-1].final_synthesis_llm_calls == 0
    assert len(agent.request_metrics.records) == 1
    await assert_resume_and_reread(agent, registry, tmp_path, monkeypatch, expected=1)


async def test_final_step_interrupted_save_uses_tools_free_request(tmp_path, monkeypatch):
    agent, registry, client = setup_run(tmp_path, monkeypatch, threshold=100000)
    # Large schemas alone cross soft pressure if incorrectly charged to synthesis.
    original_schema = cast(FileReadTool, registry.get("file_read")).schema
    monkeypatch.setattr(registry.get("file_read"), "schema", lambda: {**original_schema(), "description": "schema" * 80000})
    signal = FakeSignal()
    original_save = agent.save
    async def save():
        await original_save()
        if agent.history[-1].role == "tool": signal.aborted = True
    monkeypatch.setattr(agent, "save", save)
    await agent.run("Read local file", signal, lambda _: None, AgentRunOptions(max_steps=1))
    assert len(client.requests) == 1
    assert not agent.result_retention.references
    assert next(m for m in cast(Store, agent.store).load().messages if m.role == "tool").content == PAYLOAD


async def test_checkpoint_write_failure_keeps_original_and_retry_does_not_duplicate(tmp_path, monkeypatch):
    agent, registry, client = setup_run(tmp_path, monkeypatch)
    original = cast(Store, agent.store).save
    async def fail(*args, **kwargs):
        raise OSError("offline checkpoint write failed")
    # Initial input save may fail under the existing best-effort policy. Both
    # batch checkpoint and terminal retry fail visibly and keep trusted sources.
    monkeypatch.setattr(agent.store, "save", fail)
    with pytest.raises(OSError, match="checkpoint write failed"):
        await agent.run("Read local file", FakeSignal(), lambda _: None, AgentRunOptions(max_steps=2))
    assert not agent.running and agent._tool_results_unsaved
    assert len(client.requests) == 1 and len(agent.result_retention.references) == 1
    assert next(iter(agent.result_retention.pending.values())).original == PAYLOAD
    refs = set(agent.result_retention.references)
    async def guarded_retry(*args, **kwargs):
        assert agent.running
        with pytest.raises(RuntimeError, match="cannot switch model/provider"):
            agent.set_client(SnapshotClient([]))
        await original(*args, **kwargs)
    monkeypatch.setattr(agent.store, "save", guarded_retry)
    # Same-controller retry settles the old checkpoint before preparing new input.
    await agent.run("Continue", FakeSignal(), lambda _: None, AgentRunOptions(max_steps=1))
    assert set(agent.result_retention.references) == refs
    await assert_resume_and_reread(agent, registry, tmp_path, monkeypatch, expected=1)


async def test_cancel_before_checkpoint_commit_joins_writer(tmp_path, monkeypatch):
    agent, registry, client = setup_run(tmp_path, monkeypatch, count=2)
    entered = asyncio.Event()
    release = asyncio.Event()
    original = cast(Store, agent.store).save
    async def save(messages, *args, **kwargs):
        if any(m.role == "tool" for m in messages):
            entered.set()
            await release.wait()
        await original(messages, *args, **kwargs)
    monkeypatch.setattr(agent.store, "save", save)
    task = asyncio.create_task(agent.run("Read files", FakeSignal(), lambda _: None, AgentRunOptions(max_steps=2)))
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    # Before release only initial user input is on disk; after cancellation is
    # delivered, run must still wait for this same writer rather than start one.
    assert not any(m.role == "tool" for m in cast(Store, agent.store).load().messages)
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 10)
    assert len(client.requests) == 1
    await assert_resume_and_reread(agent, registry, tmp_path, monkeypatch, expected=2)


async def test_artifact_write_failure_is_visible_and_preserves_trusted_pending(tmp_path, monkeypatch):
    agent, registry, client = setup_run(tmp_path, monkeypatch)
    retention_store = agent.result_retention.store
    assert retention_store is not None
    original = retention_store.put
    async_errors = []
    def fail(*args, **kwargs):
        raise OSError("offline artifact write failed")
    monkeypatch.setattr(retention_store, "put", fail)
    with pytest.raises(OSError, match="artifact write failed"):
        await agent.run("Read local file", FakeSignal(), async_errors.append, AgentRunOptions(max_steps=2))
    assert any("artifact write failed" in str(e.get("err", "")) for e in async_errors)
    assert not agent.running and agent._tool_results_unsaved
    assert not agent.result_retention.references
    assert next(iter(agent.result_retention.pending.values())).original == PAYLOAD
    assert len(client.requests) == 1
    monkeypatch.setattr(retention_store, "put", original)
    await agent.run("Continue", FakeSignal(), lambda _: None, AgentRunOptions(max_steps=1))
    await assert_resume_and_reread(agent, registry, tmp_path, monkeypatch, expected=1)


async def test_manual_compact_settles_failed_checkpoint_before_summarizing(tmp_path, monkeypatch):
    agent, registry, client = setup_run(tmp_path, monkeypatch)
    original = cast(Store, agent.store).save
    async def fail(*args, **kwargs): raise OSError("offline save failure")
    monkeypatch.setattr(agent.store, "save", fail)
    with pytest.raises(OSError):
        await agent.run("Read local file", FakeSignal(), lambda _: None, AgentRunOptions(max_steps=2))
    refs = set(agent.result_retention.references)
    monkeypatch.setattr(agent.store, "save", original)
    observed = []
    original_chat = client.chat
    async def chat(req, signal=None):
        observed.append(cast(Store, agent.store).load())
        assert not agent._tool_results_unsaved
        assert not agent.result_retention.pending
        return await original_chat(req, signal)
    monkeypatch.setattr(client, "chat", chat)
    await agent.compact(FakeSignal(), lambda _: None)
    assert observed
    assert any(m.tool_result_refs for m in observed[0].messages if m.role == "tool")
    assert set(agent.result_retention.references) == refs
    restored = make_agent(tools=registry, store=agent.store)
    restored.resume_saved()
    ref = next(iter(restored.result_retention.references.values()))
    reply = json.loads(await restored.tools.execute("read_tool_result", {
        "result_ref": ref.result_ref, "start_char": PAYLOAD.index(CANARY), "max_chars": len(CANARY),
    }, FakeSignal(), restored.prompter))
    assert reply["content"] == CANARY
