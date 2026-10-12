"""ITab lifecycle regression tests; Java/Burp stand-ins do not prove visibility."""

from unittest.mock import Mock

import pytest

from tests.integration.test_kagent_burp import (
    BurpExtender, _components, _message, extender, extension_module,
)


def test_registered_tab_returns_one_populated_component(extender):
    caption, panel = extender.callbacks.tab_components[0]
    assert caption == "KAgent"
    assert isinstance(panel, extension_module.JPanel)
    assert len(panel.children) == 2
    assert extender.getUiComponent() is panel
    assert extender.getUiComponent() is panel
    assert extender.log_area in list(_components(panel))


@pytest.mark.parametrize("checkbox,tool,other_tool", [
    ("auto_proxy_box", "TOOL_PROXY", "TOOL_REPEATER"),
    ("auto_repeater_box", "TOOL_REPEATER", "TOOL_PROXY"),
])
def test_enabling_auto_capture_takes_effect_without_save(extender, checkbox, tool, other_tool):
    extender._post_json = Mock()
    message = _message()
    extender.processHttpMessage(getattr(extender.callbacks, tool), False, message)
    extender._post_json.assert_not_called()

    getattr(extender, checkbox).setSelected(True)
    extender.processHttpMessage(getattr(extender.callbacks, other_tool), False, message)
    extender._post_json.assert_not_called()
    extender.processHttpMessage(getattr(extender.callbacks, tool), False, message)
    extender._post_json.assert_called_once()
    assert extender._post_json.call_args.args[0] == "/ingest"


@pytest.mark.parametrize("checkbox,tool", [
    ("auto_proxy_box", "TOOL_PROXY"),
    ("auto_repeater_box", "TOOL_REPEATER"),
])
def test_unchecking_saved_auto_capture_stops_before_payload_without_save(extender, checkbox, tool):
    box = getattr(extender, checkbox)
    box.setSelected(True)
    extender._save_settings(None)
    extender._post_json = Mock()
    extender._message_to_ingest_payload = Mock(wraps=extender._message_to_ingest_payload)

    box.setSelected(False)
    extender.processHttpMessage(getattr(extender.callbacks, tool), False, _message())

    extender._post_json.assert_not_called()
    extender._message_to_ingest_payload.assert_not_called()
    assert not extender.auto_send_proxy and not extender.auto_send_repeater
    assert not extender.auto_sent_keys


def test_auto_capture_toggle_does_not_save_pending_connection_edits(extender):
    extender.url_field.setText("http://127.0.0.1:9999")
    extender.token_field.setText("pending-token")
    extender.auto_proxy_box.setSelected(True)
    extender.auto_repeater_box.setSelected(True)

    assert extender.auto_send_proxy and extender.auto_send_repeater
    assert extender.base_url == extension_module.DEFAULT_BASE_URL
    assert extender.token == ""


def test_repeated_getter_keeps_registered_controls_and_activity_log(extender):
    panel = extender.callbacks.tab_components[0][1]
    visible_url, visible_token = extender.url_field, extender.token_field
    visible_proxy, visible_log = extender.auto_proxy_box, extender.log_area
    visible_url.setText("http://127.0.0.1:9999")
    visible_token.setText("fixture-token")
    visible_proxy.setSelected(True)
    visible_log.setText("existing activity\n")

    extender.getUiComponent()
    save_button = next(c for c in _components(panel)
                       if isinstance(c, extension_module.JButton) and c.text == "Save")
    save_button.actionPerformed(None)

    assert extender.url_field is visible_url
    assert extender.token_field is visible_token
    assert extender.auto_proxy_box is visible_proxy
    assert extender.log_area is visible_log
    assert extender.base_url == "http://127.0.0.1:9999"
    assert extender.token == "fixture-token"
    assert extender.auto_send_proxy
    assert visible_log.getText() == "existing activity\nbridge settings saved\n"


@pytest.mark.parametrize("already_on_edt", [False, True])
def test_build_and_registration_complete_on_edt(extender, monkeypatch, already_on_edt):
    swing = extension_module.SwingUtilities
    monkeypatch.setattr(swing, "on_edt", already_on_edt)
    dispatch = Mock(wraps=swing.invokeAndWait)
    monkeypatch.setattr(swing, "invokeAndWait", dispatch)
    instance = BurpExtender()
    callbacks = extender.callbacks
    callbacks.registrations.clear()
    callbacks.tab_components.clear()
    build = instance._build_ui
    add_tab = callbacks.addSuiteTab
    events = []

    def checked_build():
        assert swing.isEventDispatchThread()
        events.append("build")
        return build()

    def checked_add_tab(tab):
        assert swing.isEventDispatchThread()
        assert tab.stdout is not None
        events.append("register")
        add_tab(tab)

    monkeypatch.setattr(instance, "_build_ui", checked_build)
    monkeypatch.setattr(callbacks, "addSuiteTab", checked_add_tab)
    instance.registerExtenderCallbacks(callbacks)

    assert events == ["build", "register"]
    assert dispatch.call_count == int(not already_on_edt)
    assert callbacks.tab_components == [("KAgent", instance.getUiComponent())]
    assert [kind for kind, _ in callbacks.registrations].count("tab") == 1
    # Subsequent getters do no Swing work, even off the EDT.
    monkeypatch.setattr(swing, "on_edt", False)
    instance.getUiComponent()
    assert events == ["build", "register"]


def test_ui_failure_does_not_register_tab_or_report_success(extender, monkeypatch):
    instance = BurpExtender()
    callbacks = extender.callbacks
    callbacks.registrations.clear()
    callbacks.tab_components.clear()
    monkeypatch.setattr(instance, "_build_ui", Mock(side_effect=RuntimeError("UI failed")))

    with pytest.raises(RuntimeError, match="UI failed"):
        instance.registerExtenderCallbacks(callbacks)

    assert not callbacks.tab_components
    assert "tab" not in [kind for kind, _ in callbacks.registrations]
    instance.stdout.println.assert_not_called()


def test_reload_uses_distinct_ui_without_replacing_previous_widgets(extender):
    previous_panel, previous_log = extender.getUiComponent(), extender.log_area
    reloaded = BurpExtender()
    reloaded.registerExtenderCallbacks(extender.callbacks)
    assert reloaded.getUiComponent() is not previous_panel
    assert reloaded.log_area is not previous_log
    assert extender.getUiComponent() is previous_panel
    assert extender.log_area is previous_log
    # Actual removal of unloaded tabs is Burp's lifecycle, not simulated here.
