"""Import boundaries and shared state after the LLM domain migration."""

import importlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest


PROVIDERS = {"anthropic", "gemini", "openai"}


@pytest.mark.parametrize(
    ("module_name", "expected_providers"),
    [
        ("src.llm", set()),
        ("src.llm.core", set()),
        ("src.llm.providers", set()),
        ("src.llm.transport", set()),
        ("src.llm.runtime", set()),
        ("src.llm.core.client", set()),
        ("src.llm.core.types", set()),
        ("src.llm.core.models", set()),
        ("src.llm.transport.http", set()),
        ("src.session.store", set()),
        ("src.cli.main", set()),
        ("src.llm.providers.anthropic", {"anthropic"}),
        ("src.llm.providers.gemini", {"gemini"}),
        ("src.llm.providers.openai", {"openai"}),
        ("src.llm.core.factory", PROVIDERS),
        ("src.llm.runtime.provider_runtime", PROVIDERS),
    ],
)
def test_fresh_import_preserves_provider_loading_boundaries(
    module_name: str, expected_providers: set[str],
) -> None:
    script = """
import importlib
import importlib.abc
import json
import sys

class NoProviderSDK(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'anthropic' or fullname.startswith('anthropic.') or fullname in (
            'google.genai', 'google.generativeai',
        ) or fullname.startswith(('google.genai.', 'google.generativeai.')):
            raise AssertionError('Unexpected optional provider SDK import: ' + fullname)

sys.meta_path.insert(0, NoProviderSDK())
importlib.import_module(sys.argv[1])
print(json.dumps(sorted(name for name in sys.modules if name.startswith('src.llm'))))
"""
    result = subprocess.run(
        [sys.executable, "-c", script, module_name],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True, text=True, check=True,
    )
    loaded = set(json.loads(result.stdout))
    assert {
        name for name in PROVIDERS if f"src.llm.providers.{name}" in loaded
    } == expected_providers
    assert "src.llm.runtime.validation_budget" not in loaded
    if module_name == "src.llm":
        assert loaded == {"src.llm"}
    elif module_name in {"src.llm.core", "src.llm.providers", "src.llm.transport", "src.llm.runtime"}:
        assert loaded == {"src.llm", module_name}


@pytest.mark.parametrize(
    ("module_name", "symbol"),
    [
        ("src.llm.core.client", "Client"),
        ("src.llm.core.types", "ChatRequest"),
        ("src.llm.core.reasoning", "ReasoningLevel"),
        ("src.llm.core.factory", "new_from_config"),
        ("src.llm.core.models", "list_models"),
        ("src.llm.providers.anthropic", "AnthropicClient"),
        ("src.llm.providers.gemini", "GeminiClient"),
        ("src.llm.providers.openai", "OpenAIClient"),
        ("src.llm.transport.errors", "BackendError"),
        ("src.llm.transport.errors", "ProviderControlError"),
        ("src.llm.transport.retry", "RetryOptions"),
        ("src.llm.runtime.metrics", "TokenUsage"),
        ("src.llm.runtime.probe", "ProbeResult"),
        ("src.llm.runtime.provider_runtime", "ProviderRuntime"),
        ("src.llm.runtime.validation_budget", "ValidationBudget"),
    ],
)
def test_symbols_are_defined_in_canonical_modules(module_name: str, symbol: str) -> None:
    assert getattr(importlib.import_module(module_name), symbol).__module__ == module_name


def test_http_factories_share_the_relocated_budget_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.llm.runtime.validation_budget import (
        ValidationBudget, ValidationBudgetExceeded, active_validation_budget,
    )
    from src.llm.transport import http

    budget = ValidationBudget(tmp_path / "budget.json", "deepseek-flash")
    mock_transport = httpx.MockTransport(lambda request: httpx.Response(200))
    monkeypatch.setattr(budget, "transport", lambda: mock_transport)
    captured: dict[str, Any] = {}
    sentinel = object()

    def fake_client(**kwargs: Any) -> object:
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(http.httpx, "AsyncClient", fake_client)
    token = active_validation_budget.set(budget)
    try:
        assert http.new_provider_async_client(12.5) is sentinel
        assert captured == {
            "timeout": 12.5, "trust_env": False, "transport": mock_transport,
        }
        with pytest.raises(ValidationBudgetExceeded, match="synchronous provider discovery"):
            http.new_provider_session()
    finally:
        active_validation_budget.reset(token)
