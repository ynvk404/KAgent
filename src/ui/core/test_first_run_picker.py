from src.ui.core.first_run_picker import (
    FirstRunPicker,
    FirstRunPickerRequest,
    ToolingProfile,
    OPTIONS,
)


def make_picker():
    picked = []
    cancelled = []
    exited = []

    req = FirstRunPickerRequest(
        on_pick=lambda profile: picked.append(profile),
        on_cancel=lambda: cancelled.append(True),
        exit_app=lambda: exited.append(True),
    )

    picker = FirstRunPicker(req)

    return picker, picked, cancelled, exited


# ==========================================================
# Render
# ==========================================================

def test_render_shows_options():

    picker, _, _, _ = make_picker()

    text = "\n".join(picker.render())

    assert "pentestagent first-run setup" in text
    assert OPTIONS[0].label in text
    assert OPTIONS[1].label in text
    assert "Enter pick" in text


# ==========================================================
# Navigation
# ==========================================================

def test_down_changes_selection():

    picker, _, _, _ = make_picker()

    picker.handle_key("down")

    assert picker.idx == 1


def test_up_wraps():

    picker, _, _, _ = make_picker()

    picker.handle_key("up")

    assert picker.idx == len(OPTIONS) - 1


# ==========================================================
# Selection
# ==========================================================

def test_enter_picks_minimal():

    picker, picked, _, _ = make_picker()

    picker.handle_key("enter")

    assert picked == [ToolingProfile.MINIMAL]


def test_enter_after_down_picks_full():

    picker, picked, _, _ = make_picker()

    picker.handle_key("down")
    picker.handle_key("enter")

    assert picked == [ToolingProfile.FULL]


# ==========================================================
# Cancel
# ==========================================================

def test_escape_calls_cancel_and_exit():

    picker, _, cancelled, exited = make_picker()

    picker.handle_key("escape")

    assert cancelled == [True]
    assert exited == [True]


def test_ctrl_c_calls_cancel_and_exit():

    picker, _, cancelled, exited = make_picker()

    picker.handle_key("ctrl+c")

    assert cancelled == [True]
    assert exited == [True]