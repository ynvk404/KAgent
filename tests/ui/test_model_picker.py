import asyncio

from src.ui.commands import model_picker
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
