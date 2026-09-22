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
    assert "Answer:\n❯ sk-...▌" in frame


def test_render_empty_input_has_visible_focused_answer_field():
    req = make_req()
    req.placeholder = None
    modal = TextInputModal(req)

    frame = "\n".join(modal.render())

    assert "Answer:\n❯ ▌" in frame


def test_render_plain_value():
    req = make_req()
    modal = TextInputModal(req)

    for c in "sk-live-key":
        modal.handle_key(c)

    frame = "\n".join(modal.render())

    assert "Answer:\n❯ sk-live-key▌" in frame
    assert "*******-key" not in frame


def test_render_masked_value_does_not_expose_secret():
    req = make_req()
    req.masked = True
    modal = TextInputModal(req)

    for c in "sk-live-key":
        modal.handle_key(c)

    frame = "\n".join(modal.render())

    assert "sk-live-key" not in frame
    assert f"❯ {'•' * len('sk-live-key')}▌" in frame


def test_cursor_navigation_and_midstring_url_editing():
    req = make_req()
    req.initial_value = "http://localhost:8000"
    modal = TextInputModal(req)

    assert modal.value == "http://localhost:8000"
    assert modal.cursor == len("http://localhost:8000")

    # Move cursor left to between '80' and '00'
    for _ in range(2):
        modal.handle_key("left")
    assert modal.cursor == len("http://localhost:80")

    # Insert '8' at cursor -> http://localhost:80800
    modal.handle_key("8")
    assert modal.value == "http://localhost:80800"
    assert modal.cursor == len("http://localhost:808")

    # Forward delete to remove next '0' -> http://localhost:8080
    modal.handle_key("delete")
    assert modal.value == "http://localhost:8080"
    assert modal.cursor == len("http://localhost:808")

    # Move to Home and insert an 's' to make https
    modal.handle_key("home")
    assert modal.cursor == 0
    for _ in range(4):
        modal.handle_key("right")
    assert modal.cursor == 4
    modal.handle_key("s")
    assert modal.value == "https://localhost:8080"
    assert modal.cursor == 5

    # Move to end
    modal.handle_key("end")
    assert modal.cursor == len(modal.value)
    modal.handle_key("/")
    assert modal.value == "https://localhost:8080/"


def test_midstring_backspace():
    req = make_req()
    modal = TextInputModal(req)
    for c in "abcd":
        modal.handle_key(c)
    assert modal.value == "abcd"

    modal.handle_key("left")
    modal.handle_key("left")
    assert modal.cursor == 2

    # Backspace deletes 'b' before cursor
    modal.handle_key("backspace")
    assert modal.value == "acd"
    assert modal.cursor == 1


def test_midstring_cursor_render():
    req = make_req()
    req.initial_value = "hello"
    modal = TextInputModal(req)
    modal.handle_key("home")
    modal.handle_key("right")
    assert modal.cursor == 1

    frame = "\n".join(modal.render())
    assert "Answer:\n❯ h▌ello" in frame
