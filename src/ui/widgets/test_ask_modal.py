from __future__ import annotations

from unittest.mock import Mock

from src.ui.widgets.ask_modal import AskModal
from src.ui.bridges.ask_bridge import AskRequest
from src.ask.ask import Option, Question


def make_req(**overrides) -> AskRequest:
    data = {
        "question": Question(
            header="Target",
            question="Choose target",
            options=[
                Option(
                    label="Local",
                    description="localhost",
                ),
                Option(
                    label="Remote",
                    description="remote host",
                ),
                Option(
                    label="Cloud",
                ),
            ],
        ),
        "resolve": Mock(),
        "reject": Mock(),
    }

    data.update(overrides)

    return AskRequest(**data)


def test_render_shows_question_and_options():

    modal = AskModal(
        make_req()
    )

    frame = "\n".join(
        modal.render()
    )

    assert "[Target]" in frame
    assert "Choose target" in frame
    assert "› Local" in frame
    assert "Remote" in frame
    assert "Cloud" in frame


def test_down_arrow_changes_selection():

    modal = AskModal(
        make_req()
    )

    modal.handle_key("down")

    frame = "\n".join(
        modal.render()
    )

    assert "› Remote" in frame
    assert "  Local" in frame



def test_up_arrow_wraps():

    modal = AskModal(
        make_req()
    )

    modal.handle_key("up")

    frame = "\n".join(
        modal.render()
    )

    assert "› Cloud" in frame


def test_enter_resolves_selected_option():

    resolve = Mock()

    modal = AskModal(
        make_req(
            resolve=resolve
        )
    )

    modal.handle_key("enter")

    resolve.assert_called_once_with(
        "Local"
    )


def test_number_shortcut_selects_option():

    resolve = Mock()

    modal = AskModal(
        make_req(
            resolve=resolve
        )
    )

    modal.handle_key("2")

    modal.handle_key("enter")

    resolve.assert_called_once_with(
        "Remote"
    )


def test_escape_rejects():

    reject = Mock()

    modal = AskModal(
        make_req(
            reject=reject
        )
    )

    modal.handle_key("escape")

    reject.assert_called_once()

    error = reject.call_args.args[0]

    assert isinstance(
        error,
        Exception,
    )

    assert str(error) == "cancelled"