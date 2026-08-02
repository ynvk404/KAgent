from unittest.mock import Mock

from ui.widgets.secret_input_modal import (
    SecretInputModal,
    SecretInputRequest,
    mask_secret,
)


# ==========================================================
# Helper
# ==========================================================

def make_req() -> SecretInputRequest:
    return SecretInputRequest(
        header="API Key",
        question="Enter secret value",
        placeholder="input hidden",
        resolve=Mock(),
        reject=Mock(),
    )


# ==========================================================
# mask_secret
# ==========================================================

def test_mask_secret_empty():
    assert mask_secret("") == ""


def test_mask_secret_short():
    assert mask_secret("abc") == "***"


def test_mask_secret_exact_four():
    assert mask_secret("abcd") == "****"


def test_mask_secret_long():
    assert mask_secret("password123") == "*******d123"


# ==========================================================
# Input handling
# ==========================================================

def test_enter_resolve():

    req = make_req()
    modal = SecretInputModal(req)

    modal.handle_key("a")
    modal.handle_key("b")
    modal.handle_key("enter")

    req.resolve.assert_called_once_with("ab")


def test_enter_trim_value():

    req = make_req()
    modal = SecretInputModal(req)

    modal.handle_key(" ")
    modal.handle_key("a")
    modal.handle_key(" ")

    modal.handle_key("enter")

    req.resolve.assert_called_once_with("a")


def test_backspace():

    req = make_req()
    modal = SecretInputModal(req)

    modal.handle_key("a")
    modal.handle_key("b")
    modal.handle_key("backspace")

    assert modal.value == "a"


def test_delete():

    req = make_req()
    modal = SecretInputModal(req)

    modal.handle_key("a")
    modal.handle_key("delete")

    assert modal.value == ""


def test_escape_reject():

    req = make_req()
    modal = SecretInputModal(req)

    modal.handle_key("esc")

    req.reject.assert_called_once()


def test_escape_long():

    req = make_req()
    modal = SecretInputModal(req)

    modal.handle_key("escape")

    req.reject.assert_called_once()


# ==========================================================
# Render
# ==========================================================

def test_render_placeholder():

    req = make_req()
    modal = SecretInputModal(req)

    lines = modal.render()

    frame = "\n".join(lines)

    assert "[API Key]" in frame
    assert "Enter secret value" in frame
    assert "input hidden" in frame


def test_render_masked_value():

    req = make_req()
    modal = SecretInputModal(req)

    for c in "password123":
        modal.handle_key(c)

    lines = modal.render()

    frame = "\n".join(lines)

    assert "*******d123" in frame
    assert "password123" not in frame