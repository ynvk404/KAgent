"""Bound repeated estimates in a large guard pass without changing messages."""
import importlib

from src.llm.core.types import ChatRequest, Message
from tests.agent.test_token_accounting_independent_verify import make_agent


def test_preserved_tool_history_does_not_trigger_full_estimate_per_message(monkeypatch):
    module = importlib.import_module('src.agent.agent')
    agent = make_agent()
    agent.set_auto_compact_threshold(1000)
    monkeypatch.setattr(agent.tools, 'context_reduction_policy', lambda _: 'preserve')
    messages = [Message('system', 'fixed context')] + [
        Message('tool', 'preserved contract ' * 1000, name='load_skill') for _ in range(80)]
    original = [m.content for m in messages]
    request = ChatRequest(agent.client.model(), messages)
    actual = module.estimate_request
    calls = []
    def count(*args, **kwargs):
        calls.append(1)
        return actual(*args, **kwargs)
    monkeypatch.setattr(module, 'estimate_request', count)
    agent.guard_working_context(messages, lambda _: None, request=request)
    assert len(calls) <= 5
    assert [m.content for m in messages] == original
