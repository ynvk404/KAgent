import asyncio

from src.ui.commands import model_picker
from src.ui.core.state import Append, SetAsk


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

        assert isinstance(dispatched[0], Append)
        assert "groq list-models failed" in dispatched[0].entry.text

    asyncio.run(run())


def test_fetch_and_pick_model_dispatches_model_picker(monkeypatch):
    async def run() -> None:
        dispatched: list[object] = []
        seen_payloads: list[dict[str, object]] = []

        def dispatch(action: object) -> None:
            dispatched.append(action)

        def fake_list_models(*_args, **_kwargs):
            return ["model-a", "model-b"]

        async def fake_apply_provider(payload: dict[str, object]) -> None:
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

        assert isinstance(dispatched[0], SetAsk)
        req = dispatched[0].req
        assert req is not None
        assert req.question.header == "model"
        assert req.question.options[0].label == "model-a"

        req.resolve("model-b")
        await asyncio.sleep(0.01)

        assert seen_payloads[0]["model"] == "model-b"
        assert isinstance(dispatched[-1], Append)
        assert dispatched[-1].entry.kind == "system"

    asyncio.run(run())
