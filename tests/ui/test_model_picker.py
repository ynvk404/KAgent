import asyncio

from src.ui.commands import model_picker
from src.llm.errors import ProviderControlError
from src.ui.core.app import ProviderChange
from src.ui.core.state import Append, Clear, SetAsk


def test_fetch_and_pick_model_reports_listing_errors(monkeypatch):
    async def run() -> None:
        dispatched: list[object] = []

        def dispatch(action: object) -> None:
            dispatched.append(action)

        def fake_list_models(*_args, **_kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(model_picker, "list_models", fake_list_models)

        await model_picker.fetch_and_pick_model(
            "groq",
            "https://example.test",
            "key",
            dispatch,
            lambda *_args, **_kwargs: None,
        )

        # 1. Loading state shown
        assert isinstance(dispatched[0], SetAsk)
        assert dispatched[0].req is not None
        assert "Fetching available models" in dispatched[0].req.question.question
        assert dispatched[0].req.question.options == []

        # 2. Loading state cleared on error
        assert isinstance(dispatched[1], SetAsk)
        assert dispatched[1].req is None

        # 3. Error reported in transcript
        assert isinstance(dispatched[2], Append)
        assert "groq list-models failed" in dispatched[2].entry.text

    asyncio.run(run())


def test_fetch_and_pick_model_dispatches_model_picker(monkeypatch):
    async def run() -> None:
        dispatched: list[object] = []
        seen_payloads: list[ProviderChange] = []

        def dispatch(action: object) -> None:
            dispatched.append(action)

        def fake_list_models(*_args, **_kwargs):
            return ["model-a", "model-b"]

        async def fake_apply_provider(payload: ProviderChange) -> None:
            seen_payloads.append(payload)

        monkeypatch.setattr(model_picker, "list_models", fake_list_models)

        await model_picker.fetch_and_pick_model(
            "ollama",
            "http://localhost:11434",
            "",
            dispatch,
            fake_apply_provider,
            {"currentModel": "model-a"},
        )

        # 1. Loading state
        assert isinstance(dispatched[0], SetAsk)
        req = dispatched[0].req
        assert dispatched[0].req is not None
        assert "Fetching available models" in dispatched[0].req.question.question

        # 2. Real model picker replaces loading state
        assert isinstance(dispatched[1], SetAsk)
        req = dispatched[1].req
        assert req is not None
        assert req.question.header == "model"
        assert req.question.options[0].label == "model-a"
        assert "● active" in (req.question.options[0].description or "")

        req.resolve("model-b")
        await asyncio.sleep(0.01)

        assert seen_payloads[0].backend == "ollama"
        assert seen_payloads[0].model == "model-b"
        assert seen_payloads[0].base_url == "http://localhost:11434"
        assert seen_payloads[0].api_key == ""
        assert isinstance(dispatched[-2], Clear)
        assert isinstance(dispatched[-1], Append)
        assert dispatched[-1].entry.kind == "system"

    asyncio.run(run())


def test_fetch_and_pick_model_preserves_active_custom_provider_id(monkeypatch):
    async def run() -> None:
        dispatched: list[object] = []
        seen_payloads: list[ProviderChange] = []

        def dispatch(action: object) -> None:
            dispatched.append(action)

        def fake_list_models(*_args, **_kwargs):
            return ["model-a", "model-b"]

        async def fake_apply_provider(payload: ProviderChange) -> None:
            seen_payloads.append(payload)

        monkeypatch.setattr(model_picker, "list_models", fake_list_models)

        await model_picker.fetch_and_pick_model(
            "openai-compat",
            "https://gateway.example/v1",
            "custom-key",
            dispatch,
            fake_apply_provider,
            current_model="model-a",
            custom_provider_id="opaque-profile-id",
        )
        request = dispatched[1].req
        request.resolve("model-b")
        await asyncio.sleep(0.01)

        assert seen_payloads[0].custom_provider_id == "opaque-profile-id"
        assert seen_payloads[0].model == "model-b"
        # Runtime resolution reads the latest profile under the mutation lock.
        assert seen_payloads[0].base_url is None
        assert seen_payloads[0].api_key is None

    asyncio.run(run())


def test_fetch_and_pick_model_loading_cancellation(monkeypatch):
    import threading

    async def run() -> None:
        dispatched: list[object] = []

        def dispatch(action: object) -> None:
            dispatched.append(action)

        ready = threading.Event()
        proceed = threading.Event()

        def fake_list_models(*_args, **_kwargs):
            ready.set()
            proceed.wait(timeout=2)
            return ["model-a", "model-b"]

        monkeypatch.setattr(model_picker, "list_models", fake_list_models)

        task = asyncio.create_task(
            model_picker.fetch_and_pick_model(
                "ollama",
                "http://localhost:11434",
                "",
                dispatch,
                lambda *_args: None,
            )
        )

        # Wait until list_models is executing in the worker thread
        await asyncio.to_thread(ready.wait, 2)

        # Loading ask was dispatched
        assert isinstance(dispatched[0], SetAsk)
        loading_req = dispatched[0].req
        assert loading_req is not None

        # Simulate user pressing Esc on loading dialog while request is in-flight
        loading_req.reject(Exception("cancelled"))

        # Unblock worker thread
        proceed.set()
        await task

        # SetAsk(None) was dispatched to close loading modal
        assert any(isinstance(a, SetAsk) and a.req is None for a in dispatched)
        # Model picker was NOT shown
        assert not any(
            isinstance(a, SetAsk) and a.req is not None and a.req.question.options != []
            for a in dispatched
        )

    asyncio.run(run())


def test_discovery_failure_offers_manual_model_id_and_uses_it(monkeypatch):
    async def run() -> None:
        dispatched: list[object] = []
        prompts: list[str] = []
        applied: list[ProviderChange] = []

        def fake_list_models(*_args, **_kwargs):
            raise ProviderControlError(
                "unsupported-endpoint",
                "provider does not support the models endpoint (HTTP 404)",
            )

        async def prompt(reason: str) -> str:
            prompts.append(reason)
            return "custom-model"

        async def apply(change: ProviderChange) -> None:
            applied.append(change)

        monkeypatch.setattr(model_picker, "list_models", fake_list_models)
        await model_picker.fetch_and_pick_model(
            "openai-compat",
            "https://provider.invalid/v1",
            "secret",
            dispatched.append,
            apply,
            manual_model_prompt=prompt,
            custom_provider_id="profile-id",
        )

        assert prompts == ["provider does not support the models endpoint (HTTP 404)"]
        picker_action = next(
            action
            for action in dispatched
            if isinstance(action, SetAsk)
            and action.req is not None
            and action.req.question.options
        )
        assert picker_action.req is not None
        assert picker_action.req.question.options[0].label == "custom-model"
        picker_action.req.resolve("custom-model")
        await asyncio.sleep(0)
        assert applied[0].model == "custom-model"
        assert applied[0].custom_provider_id == "profile-id"

    asyncio.run(run())


def test_discovery_auth_failure_does_not_offer_manual_fallback(monkeypatch):
    async def run() -> None:
        dispatched: list[object] = []
        prompts: list[str] = []

        def fake_list_models(*_args, **_kwargs):
            raise ProviderControlError("authentication", "provider authentication failed (HTTP 401)")

        async def prompt(reason: str) -> str:
            prompts.append(reason)
            return "custom-model"

        monkeypatch.setattr(model_picker, "list_models", fake_list_models)
        await model_picker.fetch_and_pick_model(
            "openai-compat",
            "https://provider.invalid/v1",
            "secret",
            dispatched.append,
            lambda *_args: None,
            manual_model_prompt=prompt,
        )

        assert prompts == []
        error = next(action for action in dispatched if isinstance(action, Append))
        assert error.entry.kind == "error"
        assert "authentication failed" in error.entry.text
        assert "secret" not in error.entry.text

    asyncio.run(run())
