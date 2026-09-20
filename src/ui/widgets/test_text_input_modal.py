from typing import cast
from unittest.mock import Mock

from src.ui.widgets.text_input_modal import (
    TextInputModal,
    TextInputRequest,
)


def make_req() -> TextInputRequest:
    return TextInputRequest(
        header="API Key",
        question="Enter API key",
        placeholder="sk-...",
        resolve=Mock(),
        reject=Mock(),
    )


def test_enter_resolve():
    req = make_req()
    modal = TextInputModal(req)

    modal.handle_key("a")
    modal.handle_key("b")
    modal.handle_key("enter")

    cast(Mock, req.resolve).assert_called_once_with("ab")


def test_enter_trim_value():
    req = make_req()
    modal = TextInputModal(req)

    modal.handle_key(" ")
    modal.handle_key("a")
    modal.handle_key(" ")

    modal.handle_key("enter")

    cast(Mock, req.resolve).assert_called_once_with("a")


def test_backspace():
    req = make_req()
    modal = TextInputModal(req)

    modal.handle_key("a")
    modal.handle_key("b")
    modal.handle_key("backspace")

    assert modal.value == "a"


def test_delete():
    req = make_req()
    modal = TextInputModal(req)

    modal.handle_key("a")
    modal.handle_key("delete")

    assert modal.value == ""


def test_uses_raw_text_for_named_punctuation_keys():
    req = make_req()
    modal = TextInputModal(req)

    modal.handle_key("full_stop", ".")
    modal.handle_key("quotation_mark", "_")

    assert modal.value == "._"


def test_escape_reject():
    req = make_req()
    modal = TextInputModal(req)

    modal.handle_key("esc")

    cast(Mock, req.reject).assert_called_once()


def test_escape_long():
    req = make_req()
    modal = TextInputModal(req)

    modal.handle_key("escape")

    cast(Mock, req.reject).assert_called_once()


def test_render_placeholder():
    req = make_req()
    modal = TextInputModal(req)

    frame = "\n".join(modal.render())

    assert "[API Key]" in frame
    assert "Enter API key" in frame
    assert "Answer:\n> sk-...▌" in frame


def test_render_empty_input_has_visible_focused_answer_field():
    req = make_req()
    req.placeholder = None
    modal = TextInputModal(req)

    frame = "\n".join(modal.render())

    assert "Answer:\n> ▌" in frame


def test_render_plain_value():
    req = make_req()
    modal = TextInputModal(req)

    for c in "sk-live-key":
        modal.handle_key(c)

    frame = "\n".join(modal.render())

    assert "Answer:\n> sk-live-key▌" in frame
    assert "*******-key" not in frame


def test_render_masked_value_does_not_expose_secret():
    req = make_req()
    req.masked = True
    modal = TextInputModal(req)

    for c in "sk-live-key":
        modal.handle_key(c)

    frame = "\n".join(modal.render())

    assert "sk-live-key" not in frame
    assert f"> {'•' * len('sk-live-key')}▌" in frame
