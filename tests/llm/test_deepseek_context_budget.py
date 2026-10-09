"""Verified first-party capacity and threshold policy without HTTP/inference."""
from typing import cast

import pytest

from src.cli.runtime import effective_auto_compact_threshold
from src.config.config import Config, add_custom_provider, resolve_custom_provider
from src.llm.core.factory import new_from_config
from src.llm.core.types import ChatRequest, Message
from src.llm.providers import DEEPSEEK_CONTEXT_LIMITS, DEEPSEEK_DEFAULT_BASE_URL
from src.llm.providers.openai import OpenAIClient
from src.llm.runtime.context_budget import ContextCapacityError, resolve_input_budget, resolve_model_input_budget
from tests.agent.test_token_accounting_independent_verify import make_agent


@pytest.mark.parametrize("model", ["", "deepseek-flash", "deepseek-v4-pro"])
def test_official_deepseek_capacity_and_default_threshold(model):
    cfg = Config(backend="deepseek", model=model, api_keys={"deepseek": "offline-fixture"})
    client = cast(OpenAIClient, new_from_config(cfg))
    assert client.name() == "deepseek"
    assert client.model() == (model or "deepseek-flash")
    assert DEEPSEEK_CONTEXT_LIMITS[client.model()] == (1048576, 393216)
    budget = resolve_input_budget(client)
    assert budget.source == "deepseek-context"
    assert budget.reserved_output_tokens == 393216
    assert budget.safety_tokens == 52429
    assert budget.input_limit == 602931
    assert effective_auto_compact_threshold(cfg) == effective_auto_compact_threshold(cfg, client) == 32000
    # The budget reserve must not add/change the adapter's output setting.
    body = client.encode_request(ChatRequest(model=client.model(), messages=[Message("user", "fixture")]), False)
    assert client.max_tokens is None
    assert "max_tokens" not in body and "max_completion_tokens" not in body


@pytest.mark.parametrize("maximum", [8192, 65536, 131072, 393216])
def test_configured_output_and_existing_safety_margin_are_reserved(maximum):
    cfg = Config(backend="deepseek", model="deepseek-flash", max_tokens=maximum,
                 api_keys={"deepseek": "offline-fixture"})
    client = cast(OpenAIClient, new_from_config(cfg))
    budget = resolve_input_budget(client)
    assert budget.reserved_output_tokens == maximum
    assert budget.safety_tokens == 52429
    assert budget.input_limit == 1048576 - maximum - 52429
    assert effective_auto_compact_threshold(cfg, client) == 32000
    assert effective_auto_compact_threshold(cfg) == 32000
    body = client.encode_request(ChatRequest(model=cfg.model, messages=[Message("user", "fixture")]), False)
    assert body["max_tokens"] == maximum


def test_live_client_output_reservation_takes_precedence_over_config():
    cfg = Config(backend="deepseek", model="deepseek-flash", max_tokens=8192)
    client = OpenAIClient(DEEPSEEK_DEFAULT_BASE_URL, "", cfg.model, "deepseek", gen_opts={"max_tokens": 131072})
    assert resolve_input_budget(client).reserved_output_tokens == 131072
    assert resolve_model_input_budget("deepseek", cfg.model, cfg.max_tokens).reserved_output_tokens == 8192


@pytest.mark.parametrize("model", ["unknown", "deepseek-chat", "deepseek-v4-flash", "deepseek-small-8k"])
def test_unverified_model_ids_do_not_inherit_capacity_from_the_name(model):
    cfg = Config(backend="deepseek", model=model)
    client = OpenAIClient(DEEPSEEK_DEFAULT_BASE_URL, "", model, "deepseek")
    assert resolve_input_budget(client).input_limit is None
    assert effective_auto_compact_threshold(cfg) == effective_auto_compact_threshold(cfg, client) == 16000


@pytest.mark.parametrize("base_url,verified", [
    (DEEPSEEK_DEFAULT_BASE_URL, True),
    (DEEPSEEK_DEFAULT_BASE_URL + "/", True),
    (DEEPSEEK_DEFAULT_BASE_URL + "/v1", True),
    (DEEPSEEK_DEFAULT_BASE_URL + "/v1/", True),
    ("https://gateway.example/v1", False),
    ("http://api.deepseek.com", False),
    ("https://api.deepseek.com.example/v1", False),
    ("https://api.deepseek.com@other.example/v1", False),
    (DEEPSEEK_DEFAULT_BASE_URL + "/other", False),
])
def test_known_capacity_is_bound_to_verified_endpoints(base_url, verified):
    cfg = Config(backend="deepseek", model="deepseek-flash", base_url=base_url)
    client = OpenAIClient(base_url, "", cfg.model, "deepseek")
    assert (resolve_input_budget(client).source == "deepseek-context") is verified
    expected = 32000 if verified else 16000
    assert effective_auto_compact_threshold(cfg) == effective_auto_compact_threshold(cfg, client) == expected


@pytest.mark.parametrize("identity", ["openai-compat", "custom DeepSeek", "openai", "openrouter"])
def test_custom_manual_and_other_backends_do_not_inherit_first_party_limits(identity):
    client = OpenAIClient(DEEPSEEK_DEFAULT_BASE_URL, "", "deepseek-flash", identity)
    cfg = Config(backend=identity, model="deepseek-flash", base_url=DEEPSEEK_DEFAULT_BASE_URL)
    assert resolve_input_budget(client).input_limit is None
    assert effective_auto_compact_threshold(cfg) == effective_auto_compact_threshold(cfg, client) == 16000


@pytest.mark.parametrize("custom", [False, True])
def test_factory_manual_and_saved_custom_deepseek_name_keep_separate_backend_identity(custom):
    cfg = Config(backend="openai-compat", model="deepseek-flash", base_url=DEEPSEEK_DEFAULT_BASE_URL)
    if custom:
        profile_id = add_custom_provider(cfg, "deepseek", DEEPSEEK_DEFAULT_BASE_URL,
                                         default_model="deepseek-flash")
        cfg, _profile = resolve_custom_provider(cfg, profile_id)
    client = new_from_config(cfg)
    assert client.name() == "openai-compat"
    assert client.model() == "deepseek-flash"
    assert resolve_input_budget(client).input_limit is None
    assert effective_auto_compact_threshold(cfg, client) == 16000


def test_provider_label_without_live_endpoint_cannot_establish_capacity(monkeypatch):
    client = OpenAIClient(DEEPSEEK_DEFAULT_BASE_URL, "", "deepseek-flash", "deepseek")
    monkeypatch.delattr(client, "base_url")
    assert resolve_input_budget(client).input_limit is None
    assert effective_auto_compact_threshold(Config(backend="deepseek"), client) == 16000


@pytest.mark.parametrize("threshold", [0, 7000, 32000, 100000])
def test_manual_threshold_overrides_are_preserved(threshold):
    cfg = Config(backend="deepseek", model="deepseek-flash", auto_compact_threshold=threshold)
    client = OpenAIClient(DEEPSEEK_DEFAULT_BASE_URL, "", cfg.model, "deepseek")
    assert effective_auto_compact_threshold(cfg) == effective_auto_compact_threshold(cfg, client) == threshold


@pytest.mark.parametrize("limit,expected", [(5000, 3750), (32000, 24000), (100000, 32000)])
def test_explicit_small_input_limit_overrides_large_model_metadata(limit, expected):
    cfg = Config(backend="deepseek", model="deepseek-flash")
    client = OpenAIClient(DEEPSEEK_DEFAULT_BASE_URL, "", cfg.model, "deepseek",
                          gen_opts={"input_token_limit": limit, "max_tokens": 8192})
    budget = resolve_input_budget(client)
    assert budget.source == "explicit-input"
    assert budget.input_limit == limit  # Already input-only: no second reservation.
    assert effective_auto_compact_threshold(cfg, client) == expected


def test_synthetic_small_model_metadata_uses_budget_policy_instead_of_forcing_32k(monkeypatch):
    # Test the supported path with a synthetic capacity; do not register an
    # invented or unverified small DeepSeek API model in production metadata.
    monkeypatch.setitem(DEEPSEEK_CONTEXT_LIMITS, "deepseek-flash", (8192, 2048))
    cfg = Config(backend="deepseek", model="deepseek-flash")
    client = OpenAIClient(DEEPSEEK_DEFAULT_BASE_URL, "", cfg.model, "deepseek")
    budget = resolve_input_budget(client)
    assert budget.reserved_output_tokens == 2048
    assert budget.safety_tokens == 410
    assert budget.input_limit == 5734
    assert effective_auto_compact_threshold(cfg) == effective_auto_compact_threshold(cfg, client) == 4300


@pytest.mark.parametrize("threshold", [0, 32000, 100000])
async def test_hard_admission_still_refuses_overflow_with_manual_threshold(threshold):
    client = OpenAIClient(DEEPSEEK_DEFAULT_BASE_URL, "", "deepseek-flash", "deepseek",
                          gen_opts={"input_token_limit": 5000})
    agent = make_agent(client=client)
    agent.set_auto_compact_threshold(threshold)
    assert agent._reduction_threshold() == (min(threshold, 5000) if threshold else 5000)
    req = ChatRequest(model=client.model(), messages=[Message("user", "x" * 24000)])
    # Admission is exercised directly: no provider dispatch is ever invoked.
    with pytest.raises(ContextCapacityError) as error:
        await agent._admit_request(req, lambda _: None)
    assert error.value.budget.input_limit == 5000
    assert req.messages[0].content == "x" * 24000
