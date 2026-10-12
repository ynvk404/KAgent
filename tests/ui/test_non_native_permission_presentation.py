"""Option A: production proposals keep their authority and complete previews."""
from copy import deepcopy
import asyncio
from dataclasses import fields
from unittest.mock import Mock, AsyncMock

import pytest

from src.permission.permission import Decision, PermissionRequest
from src.permission.permission import PermissionReviewCancelled, YoloPrompter
from src.ui.bridges.perm_bridge import BridgedPermissionRequest, BridgedPrompter
from src.ui.widgets.permission_modal import PermissionModal
from src.ui.commands.result_review import review_result
from src.tools.common.registry import Registry
from src.tools.execution.file import (FileReadTool, FileWriteTool, FileEditTool, FileWriteToolAlias,
                                      FileEditToolAlias, gate_sensitive_path)
from src.tools.mcp.integration import MCPTool
from src.config.config import MCPServerConfig, PluginConfig
from src.tools.execution.plugin import CommandPluginTool
from src.tools.common.browser_capture import BrowserCaptureClearTool
from src.browser.store import CaptureStore
from src.coverage.store import CoverageStore
from src.tools.workflow.coverage import CoverageTool
from tests.security.test_action_approval import Session
from tests.tools.test_discovery_tools import make_content_tool, make_service_tool
from tests.agent.test_tool_result_offloading import make, record, reference
from src.tools.http.private_host import gate_private_request, parse_http_url
from src.target.target import Target
from src.ui.core.app import KAgent
from src.ui.core.state import SetPerm
from tests.ui.test_app import make_app
from tests.ui.test_permission_review import _content_text
from tests.ui.test_permission_modal import make_req, rendered
from tests.security.test_captured_http_replay import replay
from tests.security.test_execution_policy import runtime
from tests.security.test_operator_review import command, setup_review
from tests.security.test_browser_local import rig, ORIGIN as BROWSER_ORIGIN
from tests.security.test_browser_yolo import call, yolo


@pytest.mark.parametrize("group,name,args", [
    ("read", "snapshot", {}),
    ("navigate", "navigate", {"url": BROWSER_ORIGIN + "/fixture"}),
    ("interaction", "click", {"ref": "s1e1", "element": "fixture"}),
])
async def test_browser_real_proposal_has_one_complete_scope_and_warning(rig, group, name, args):
    prompter = yolo(rig)
    if group == "interaction":
        await call(rig, prompter)
    checked = []

    async def review(request, signal=None):
        original = deepcopy(request)
        before = deepcopy(rig.binding.grant)
        modal = PermissionModal(bridged(request))
        frame = rendered(modal, width=300)
        normalized = " ".join(frame.split())
        scope = " ".join(request.session_scope_display.split())
        assert normalized.count(scope) == 1
        assert "Tool:" not in frame
        assert f"a trust Browser {group}" in frame
        assert '"executor"' in frame and '"args"' in frame
        assert request.detail.partition("\n\n")[0] in frame
        assert '"tool": "browser_' + name + '"' in frame
        assert "Session lifetime; no call quota" in frame
        assert "does not authenticate tab/profile" in frame and "all Chrome traffic" in frame
        assert "browser_snapshot" in scope
        if group != "read":
            assert "browser_navigate" in scope
        if group == "interaction":
            assert "browser_click" in scope and "browser_type" in scope
            assert frame.count("Click/type may submit forms") == 1
        assert request == original and rig.binding.grant == before
        rig.operator.asks.append(request)
        checked.append(group)
        return Decision.ALLOW_ONCE

    rig.operator.ask = review
    await call(rig, prompter, name, args)
    assert checked == [group] and rig.binding.grant is None


@pytest.mark.parametrize("enabled,name", [(False, "snapshot"), (True, "press_key")])
async def test_browser_once_and_unsupported_actions_keep_full_json_without_trust(rig, enabled, name):
    prompter = yolo(rig, enabled)
    checked = []

    async def review(request, signal=None):
        modal = PermissionModal(bridged(request))
        frame = rendered(modal, width=300)
        assert " · a trust " not in frame
        assert '"server": "browser"' in frame and '"tool": "browser_' + name + '"' in frame
        assert "UNKNOWN_ARGUMENT_TAIL" in frame
        checked.append(name)
        rig.operator.asks.append(request)
        return Decision.ALLOW_ONCE

    rig.operator.ask = review
    await call(rig, prompter, name, {"key": "Enter", "fixture": "UNKNOWN_ARGUMENT_TAIL"})
    assert checked == [name] and rig.binding.grant is None


def test_unknown_browser_trailer_is_not_removed_or_reclassified():
    detail = '{"args":{"text":"FULL_ARGUMENT_TAIL"}}\n\nCUSTOM_BROWSER_TRAILER'
    req = make_req(tool="mcp_browser_browser_click", summary="mcp: browser/browser_click",
                   detail=detail, offer_browser_grant="interaction", force_operator=True,
                   no_session_cache=True, session_scope_display="custom scope")
    frame = rendered(PermissionModal(req), width=200)
    assert detail in frame and "CUSTOM_BROWSER_TRAILER" in frame


async def test_browser_separate_grant_review_keeps_producer_scope_and_decision(rig):
    checked = []

    async def review(request, signal=None):
        rig.operator.asks.append(request)
        if request.tool != "browser_lab_grant":
            return Decision.GRANT_LAB
        original = deepcopy(request)
        modal = PermissionModal(bridged(request))
        frame = rendered(modal, width=300)
        scope = request.summary.removeprefix("Activate ")
        assert frame.count(scope) == 1 and "Tool:" not in frame
        assert "Session lifetime; no call quota" in frame and "does not authenticate tab/profile" in frame
        assert "y approve grant" in frame and " · a " not in frame
        assert request == original and rig.binding.grant is None
        checked.append(request)
        return Decision.ALLOW_ONCE

    rig.operator.ask = review
    await call(rig, yolo(rig))
    assert len(checked) == 1 and rig.binding.grant.group == "read"


@pytest.mark.parametrize("verb", ["read", "search", "read retained result"])
async def test_sensitive_gate_producer_keeps_resolved_and_original_path(tmp_path, verb):
    secret = tmp_path / ".env"
    secret.write_text("password=fixture-secret")
    alias = tmp_path / "alias.txt"
    alias.symlink_to(secret)
    checked = []

    class Operator:
        async def ask(self, request, signal=None):
            original = deepcopy(request)
            frame = rendered(PermissionModal(bridged(request)), width=300)
            assert "Tool: file" not in frame and "Sensitive-path access may expose secrets." in frame
            assert str(secret) in frame and "Original: " + str(alias) in frame
            assert verb.capitalize() + " sensitive file" in frame
            assert "fixture-secret" not in frame and " · a " not in frame
            assert request == original
            checked.append(request)
            return Decision.ALLOW_ONCE

    assert await gate_sensitive_path(Operator(), str(alias), verb, None) == str(secret)
    assert len(checked) == 1


@pytest.mark.parametrize("tool_type,verb", [(FileWriteTool, "writes"), (FileEditTool, "edits")])
async def test_file_registry_proposal_keeps_once_resolved_scope_and_complete_content(tmp_path, monkeypatch, tool_type, verb):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "notes.txt"
    old = "OLD_HEAD\n+ metadata-like line\nOLD_TAIL"
    new = "NEW_HEAD\npath: payload value\nNEW_TAIL"
    if tool_type is FileEditTool:
        path.write_text(old)
    args = {"path": "notes.txt", "content": new} if tool_type is FileWriteTool else {
        "path": "notes.txt", "old_string": old, "new_string": new, "replace_all": True}
    original_args = deepcopy(args)
    registry = Registry()
    tool = tool_type()
    registry.register(tool)
    checked = []

    class Operator:
        async def ask(self, request, signal=None):
            original = deepcopy(request)
            frame = rendered(PermissionModal(bridged(request)), width=300)
            assert f"Allow once: {verb} to {path}" in frame
            assert " · a " not in frame and "NEW_TAIL" in frame
            assert new in frame
            if tool_type is FileEditTool:
                assert old in frame and "replace_all: True" in frame
                assert path.read_text() == old
            else:
                assert not path.exists()
            assert request == original
            checked.append(request)
            return Decision.ALLOW_ONCE

    await registry.execute(tool.name(), args, None, Operator())
    assert len(checked) == 1 and args == original_args and path.read_text() == new


async def test_general_mcp_producer_keeps_executor_and_frozen_arguments_without_duplicate_header():
    session = Session()
    tool = MCPTool(session, "mcp_fixture_operation", "operation", "fixture", {})
    tool._server = MCPServerConfig(name="fixture-server", command="python", args=["-m", "fixture-server"])
    registry = Registry()
    registry.register(tool)
    args = {"resource": "fixture.txt", "password": "fixture-secret", "nested": {"tail": "FULL_ARGUMENT_TAIL"}}
    original_args = deepcopy(args)
    checked = []

    class Operator:
        async def ask(self, request, signal=None):
            original = deepcopy(request)
            modal = PermissionModal(bridged(request))
            frame = rendered(modal, width=300)
            assert "Tool:" not in frame and "mcp: fixture-server/operation" in frame
            assert '"command": "python"' in frame and '"fixture-server"' in frame
            assert request.detail in frame and "FULL_ARGUMENT_TAIL" in frame
            assert "fixture-secret" not in frame and " · a " not in frame
            assert request == original and not session.calls
            checked.append(request)
            return Decision.ALLOW_ONCE

    await registry.execute(tool.name(), args, None, Operator())
    assert len(checked) == 1 and args == original_args and session.calls[0][1] == original_args


async def test_plugin_producer_keeps_joined_executor_and_json_stdin(monkeypatch):
    run = AsyncMock(return_value="fixture")
    monkeypatch.setattr("src.tools.execution.plugin.run_plugin", run)
    tool = CommandPluginTool(PluginConfig(name="fixture_plugin", command="python", args=["argument with spaces"]))
    registry = Registry()
    registry.register(tool)
    args = {"stdin": "FULL_STDIN_TAIL", "password": "fixture-secret"}
    original_args = deepcopy(args)

    class Operator:
        async def ask(self, request, signal=None):
            original = deepcopy(request)
            frame = rendered(PermissionModal(bridged(request)), width=300)
            assert "Tool:" not in frame and "plugin: fixture_plugin" in frame
            assert "python argument with spaces" in frame and "FULL_STDIN_TAIL" in frame
            assert "fixture-secret" not in frame and " · a " not in frame
            assert request == original
            run.assert_not_called()
            return Decision.ALLOW_ONCE

    await registry.execute(tool.name(), args, None, Operator())
    assert run.call_args.args[:3] == ("python", ["argument with spaces"], original_args)
    assert args == original_args


@pytest.mark.parametrize("kind", ["content", "service"])
async def test_discovery_producer_scope_preserves_all_bounds_without_repetition(monkeypatch, kind):
    tool = make_content_tool() if kind == "content" else make_service_tool()
    run = AsyncMock(return_value="fixture")
    monkeypatch.setattr(tool, "run", run)
    args = {"paths": ["admin", "health"], "max_requests": 8, "rate_limit": 2, "mode": "native"} if kind == "content" else {
        "ports": [8080], "mode": "socket"}
    original_args = deepcopy(args)
    registry = Registry()
    registry.register(tool)

    class Operator:
        async def ask(self, request, signal=None):
            original = deepcopy(request)
            frame = rendered(PermissionModal(bridged(request)), width=300)
            assert "Tool:" not in frame
            assert " ".join(frame.split()).count(" ".join(request.session_scope_display.split())) == 1
            assert "http://target.test:8080" in frame
            if kind == "content":
                assert "2 paths" in frame and "<= 8 requests" in frame
                assert "recursion: disabled" in frame and "redirects: not followed" in frame
                assert "maximum requests:" not in frame and "base path:" not in frame
            else:
                assert "ports 8080" in frame and "TCP only" in frame and "active origin:" in frame
                assert "network scan timeout:" not in frame
            assert request == original
            run.assert_not_called()
            return Decision.ALLOW_ONCE

    await registry.execute(tool.name(), args, None, Operator())
    assert run.call_args.args[0] == original_args and args == original_args


async def test_clear_proposals_describe_full_store_effects_before_execution(tmp_path):
    coverage = CoverageStore(str(tmp_path / "coverage.json"))
    await coverage.mark(endpoint="/one", param="q", vulnClass="xss", status="failed")
    await coverage.mark(endpoint="/two", param="q", vulnClass="xss", status="failed")
    capture = CaptureStore()
    capture.ingest({"kind": "burp", "id": "fixture", "method": "GET", "url": "https://fixture.test/one"})
    tools = [CoverageTool(coverage), BrowserCaptureClearTool(capture)]
    registry = Registry()
    for tool in tools:
        registry.register(tool)

    class Operator:
        async def ask(self, request, signal=None):
            original = deepcopy(request)
            frame = rendered(PermissionModal(bridged(request)), width=300)
            if request.tool == "coverage":
                assert "Clear all coverage records" in frame
                assert await coverage.get(endpoint="/two", param="q", vulnClass="xss") is not None
                assert '"action": "clear"' in frame
            else:
                assert "Clear browser capture memory" in frame and "Forwarding continues" in frame
                assert capture.list_requests()
            assert request == original and " · a " not in frame
            return Decision.ALLOW_ONCE

    await registry.execute("coverage", {"action": "clear"}, None, Operator())
    await registry.execute("browser_capture_clear", {}, None, Operator())
    assert await coverage.get(endpoint="/one", param="q", vulnClass="xss") is None
    assert await coverage.get(endpoint="/two", param="q", vulnClass="xss") is None
    assert not capture.list_requests()


@pytest.mark.parametrize("tool,summary,detail", [
    ("mcp_fixture", "mcp: fixture/operation", '{"args":{"tail":"UNKNOWN_TAIL"}}'),
    ("mcp_fixture", "mcp: fixture/operation", '{"server": "fixture", INVALID_JSON UNKNOWN_TAIL'),
    ("content_discovery", "content discovery: fixture", "CUSTOM_BOUNDARY UNKNOWN_TAIL"),
    ("service_discovery", "service discovery: fixture", "PRIVATE_ADDRESS_REASON UNKNOWN_TAIL"),
    ("file", "read sensitive file: fixture", "path: fixture\nUNKNOWN_WARNING_TAIL"),
])
def test_unknown_non_native_formats_keep_complete_sanitized_preview(tool, summary, detail):
    request = make_req(tool=tool, summary=summary, detail=detail, no_session_cache=True)
    assert detail in rendered(PermissionModal(request), width=300)


def test_deep_custom_json_is_preserved_by_metadata_adapter():
    detail = '{"args":{"nested":' + '[' * 1500 + '"DEEP_ARGUMENT_TAIL"' + ']' * 1500 + '}}'
    req = make_req(tool="mcp_fixture", summary="mcp: fixture/operation", detail=detail)
    # Exercise the new adapter independently of the existing recursive
    # redactor, whose deep-input limit is outside this presentation change.
    assert PermissionModal(req)._other_presentation(detail, False) == (req.summary, detail, False)
    req.resolve.assert_not_called()


@pytest.mark.parametrize("tool_type,verb", [(FileWriteTool, "writes"), (FileWriteToolAlias, "writes"),
                                         (FileEditTool, "edits"), (FileEditToolAlias, "edits")])
async def test_file_artifact_root_production_scope_distinguishes_write_and_edit(tmp_path, monkeypatch, tool_type, verb):
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "artifacts"
    monkeypatch.setattr("src.tools.execution.file.project_root", lambda: tmp_path)
    monkeypatch.setattr("src.tools.execution.file.project_artifact_root", lambda: root)
    path = root / "report.txt"
    old, new = "OLD_ARTIFACT", "NEW_ARTIFACT_TAIL"
    editing = issubclass(tool_type, FileEditTool)
    if editing:
        root.mkdir()
        path.write_text(old)
    args = {"path": "artifacts/report.txt", "old_string": old, "new_string": new} if editing else {
        "path": "artifacts/report.txt", "content": new}
    tool = tool_type()
    registry = Registry()
    registry.register(tool)

    class Operator:
        async def ask(self, request, signal=None):
            original = deepcopy(request)
            modal = PermissionModal(bridged(request))
            frame = rendered(modal, width=300)
            assert f"Session trust: {verb} under {root}" in frame
            assert "a trust artifact root" in frame and "NEW_ARTIFACT_TAIL" in frame
            modal.handle_key("a")
            modal.req.resolve.assert_called_once_with(Decision.ALLOW_SESSION)
            assert request == original
            return Decision.ALLOW_SESSION

    await registry.execute(tool.name(), args, None, Operator())
    assert path.read_text() == new


async def test_retained_range_producer_preserves_reference_history_and_bounds(make):
    checked = []

    class Operator:
        async def ask(self, request, signal=None):
            original = deepcopy(request)
            before = deepcopy(agent.history)
            frame = rendered(PermissionModal(bridged(request)), width=300)
            assert "Read retained tool result range" in frame and "Tool:" not in frame
            assert '"result_ref"' in frame and '"start_char": 12500' in frame and '"max_chars": 100' in frame
            assert " · a " not in frame
            assert request == original and agent.history == before
            checked.append(request)
            return Decision.ALLOW_ONCE

    agent = make(prompter=Operator())
    record(agent)
    ref = reference(agent)
    args = {"result_ref": ref.result_ref, "start_char": 12500, "max_chars": 100}
    history = deepcopy(agent.history)
    response = await agent.tools.execute("read_tool_result", args, None, agent.prompter)
    assert response and len(checked) == 1 and agent.history == history


async def test_web_fetch_private_host_gate_keeps_exact_scope_and_reason(monkeypatch):
    monkeypatch.setattr("src.tools.http.private_host.private_host_reason", AsyncMock(return_value="DNS resolves to loopback IPv4"))
    url = "http://fixture.lab:8080/private"
    target = Target("http://fixture.lab:8080")
    checked = []

    class Operator:
        async def ask(self, request, signal=None):
            original = deepcopy(request)
            frame = rendered(PermissionModal(bridged(request)), width=300)
            assert url in frame and "DNS resolves to loopback IPv4" in frame
            assert "HTTP requests to http://fixture.lab:8080" in frame
            assert "Approve only if this host is intentionally in scope" in frame
            assert request == original
            checked.append(request)
            return Decision.ALLOW_ONCE

    await gate_private_request(Operator(), parse_http_url(url), None, "web_fetch", target=target)
    assert len(checked) == 1


def mounted_permission_app(monkeypatch):
    monkeypatch.setattr(KAgent, "on_mount", lambda self: None)
    app = make_app()
    app._sync_overlay = KAgent._sync_overlay.__get__(app, KAgent)
    shown = []
    visible = asyncio.Event()

    def publish(request):
        app.dispatch(SetPerm(request))
        app._sync_overlay()
        if request is not None:
            shown.append(request)
            visible.set()

    return app, BridgedPrompter(publish), shown, visible


@pytest.mark.parametrize("size", [(40, 18), (80, 24)])
@pytest.mark.parametrize("key", ["y", "n", "escape"])
async def test_mounted_real_capture_review_keyboard_never_sends_before_approval(replay, monkeypatch, size, key):
    app, bridge, shown, visible = mounted_permission_app(monkeypatch)
    _, args = replay.baseline({"Authorization": "Bearer fixture-secret"})
    originals = []

    async def review(request):
        originals.append(deepcopy(request))
        decision = await bridge.ask(request)
        replay.control.deny = decision == Decision.DENY

    replay.control.review = review
    async with app.run_test(size=size) as pilot:
        task = asyncio.create_task(replay.send(args))
        try:
            await asyncio.wait_for(visible.wait(), 3)
            await pilot.pause()
            frame = _content_text(app)
            assert "bounded reuse" in frame and "baseline:" in frame
            assert "fixture-secret" not in frame and "authorize capture use" in frame
            assert app.overlay_static.region.bottom <= size[1]
            assert app.overlay_content_static.max_scroll_x == 0
            await pilot.press("v", "end", "home")
            await pilot.pause()
            assert not replay.control.sent and not task.done()
            assert replay.control.questions[0] == originals[0]
            await pilot.press(key)
            if key == "escape":
                with pytest.raises(PermissionReviewCancelled):
                    await asyncio.wait_for(task, 3)
            else:
                await asyncio.wait_for(task, 3)
            count = len(replay.control.sent)
            assert count == (1 if key == "y" else 0)
            assert len(replay.tool.permissions._capture_grants) == count
            shown[0].resolve(Decision.ALLOW_ONCE)
            assert len(replay.control.sent) == count
            assert not bridge._session_allowed and app.state.pending_perm is None
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("size", [(40, 18), (80, 24)])
@pytest.mark.parametrize("group,name", [("read", "snapshot"), ("navigate", "navigate"), ("interaction", "type")])
async def test_mounted_real_browser_grant_keeps_scope_arguments_and_trust_mapping(rig, monkeypatch, size, group, name):
    if group == "interaction":
        await call(rig, yolo(rig))
    app, bridge, shown, visible = mounted_permission_app(monkeypatch)
    prompter = YoloPrompter(bridge, True)
    prompter.bind_execution_policy(rig.policy)
    tail = "x\n" * 200 + "MOUNTED_ARGUMENT_TAIL"
    args = {"url": BROWSER_ORIGIN + "/fixture", "fixture": tail} if group == "navigate" else {
        "ref": "s1e1", "element": "fixture", "text": tail} if group == "interaction" else {"fixture": tail}
    original_args = deepcopy(args)
    count = len(rig.calls)
    async with app.run_test(size=size) as pilot:
        task = asyncio.create_task(call(rig, prompter, name, args))
        try:
            await asyncio.wait_for(visible.wait(), 3)
            await pilot.pause()
            full = _content_text(app)
            assert "MOUNTED_ARGUMENT_TAIL" in full and "no call quota" in full
            assert "browser_snapshot" in full
            if group != "read":
                assert "browser_navigate" in full
            assert app.overlay_static.region.bottom <= size[1]
            assert app.overlay_content_static.max_scroll_x == 0
            await pilot.press("end")
            await pilot.pause()
            for _ in range(20):
                if "MOUNTED_ARGUMENT_TAIL" in _content_text(app, visible_only=True):
                    break
                await pilot.press("up")
                await pilot.pause()
            assert "MOUNTED_ARGUMENT_TAIL" in _content_text(app, visible_only=True)
            assert len(rig.calls) == count and rig.binding.grant is None
            await pilot.press("a")
            await asyncio.wait_for(task, 3)
            grant = getattr(rig.binding, "grant")
            assert grant is not None and grant.group == group and grant.remaining is None
            assert not bridge._session_allowed  # Browser grant is not bridge cache authority.
            assert args == original_args and len(rig.calls) == count + 1
            shown[0].resolve(Decision.ALLOW_SESSION)
            assert len(rig.calls) == count + 1
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


def bridged(request: PermissionRequest) -> BridgedPermissionRequest:
    return BridgedPermissionRequest(**{field.name: getattr(request, field.name) for field in fields(PermissionRequest)},
                                    resolve=Mock(), reject=Mock())


async def test_capture_use_wording_comes_from_real_authorization_proposal(replay):
    _, args = replay.baseline({"Authorization": "Bearer fixture-secret"}, identity="fixture-user")
    seen = []

    async def review(request):
        original = deepcopy(request)
        before_grants = deepcopy(replay.tool.permissions._capture_grants)
        modal = PermissionModal(bridged(request))
        frame = rendered(modal, width=200)
        assert "y authorize capture use" in frame and "current invocation only" not in frame
        assert "bounded reuse" in frame and "immutable capture" in frame
        assert "baseline:" in frame and "POST " in frame and '"keep"' in frame
        assert "No redirects or shared HTTP context import" in frame
        assert "configured lifetime:" in frame and "expires in" not in frame
        assert "remaining lifetime" not in frame and "fixture-secret" not in frame
        assert request == original and replay.tool.permissions._capture_grants == before_grants
        assert not replay.control.sent
        modal.handle_key("a")
        modal.req.resolve.assert_not_called()
        modal.handle_key("y")
        modal.req.resolve.assert_called_once_with(Decision.ALLOW_ONCE)
        seen.append(request)

    replay.control.review = review
    await replay.send(args)
    await replay.send(args | {"mutation_value": "next"})
    assert len(seen) == 1 and len(replay.control.sent) == 2
    assert len(replay.tool.permissions._capture_grants) == 1


@pytest.mark.parametrize("decision", [Decision.ALLOW_ONCE, Decision.DENY])
async def test_conclusion_review_uses_real_proof_and_decline_semantics(runtime, tmp_path, decision):
    _, _, policy, operator, _, _, _ = runtime
    app, state, candidate, _, _, output = await setup_review(runtime, tmp_path)
    prior = deepcopy(state.to_dict())
    checked = []

    async def review(request, signal=None):
        original = deepcopy(request)
        modal = PermissionModal(bridged(request))
        frame = rendered(modal, width=200)
        assert "y approve conclusion" in frame and "n decline review" in frame
        assert "current invocation only" not in frame and "no execution rights" in frame
        assert "Exact result:" in frame and "Evidence:" in frame and "Impact:" in frame
        assert "Designated private fixture resource" in frame
        assert request == original and state.to_dict() == prior
        app.agent.save.assert_not_called()
        modal.handle_key("n" if decision == Decision.DENY else "y")
        modal.req.resolve.assert_called_once_with(decision)
        operator.requests.append(request)
        checked.append(decision)
        return decision

    operator.ask = review
    await review_result(app, command(candidate))
    assert checked == [decision]
    if decision == Decision.DENY:
        assert state.to_dict() == prior and output[-1].entry.kind == "error"
        app.agent.save.assert_not_called()
    else:
        result = state.latest_result(candidate.id)
        assert result is not None and result.outcome == "confirmed"
        assert output[-1].entry.kind == "system"


@pytest.mark.parametrize("tool", ["http_capture_credentials", "review_result"])
def test_special_name_with_unknown_producer_format_keeps_generic_preview(tool):
    req = make_req(tool=tool, summary="Custom action", detail="UNKNOWN_PREVIEW_TAIL")
    modal = PermissionModal(req)
    frame = rendered(modal)
    assert "UNKNOWN_PREVIEW_TAIL" in frame and "y allow once" in frame
    assert "authorize capture use" not in frame and "approve conclusion" not in frame
