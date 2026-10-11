"""C1 regressions: real dispatch, isolated files, and offline transports."""
from copy import deepcopy
import json
import stat
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from src.coverage.store import CoverageStore
from src.engagement.state import EngagementState
from src.permission.permission import Decision, YoloPrompter
from src.permission.runtime.execution import ExecutionPolicy
from src.target.target import Target
from src.tools.common.ask import AskUserTool
from src.tools.common.outcome import ToolOutput
from src.tools.common.registry import InvalidToolArguments, Registry
from src.tools.execution.file import (
    FileWriteTool, FileWriteToolAlias, FileEditTool, FileEditToolAlias,
)
from src.tools.http.http_tool import HTTPTool
from src.tools.workflow.coverage import CoverageTool, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from tests.tools.test_discovery_tools import make_content_tool, make_service_tool

MISSING = object()


def dispatch(tool, tmp_path, monkeypatch, engagement=None):
    state = engagement or EngagementState()
    policy = ExecutionPolicy(state, tmp_path)
    operator = Mock()
    operator.ask = AsyncMock(return_value=Decision.ALLOW_ONCE)
    prompter = YoloPrompter(operator)
    prompter.bind_execution_policy(policy)
    prepare = Mock(wraps=policy.prepare)
    monkeypatch.setattr(policy, "prepare", prepare)
    registry = Registry()
    registry.register(tool)
    return registry, prompter, operator, policy, prepare


def assert_no_review(operator, policy, prepare):
    operator.ask.assert_not_called()
    prepare.assert_not_called()
    assert not policy._receipts and not policy._pending
    assert not policy.input_questions
    assert policy.used == policy.active == 0
    assert not policy.engagement.http_permissions._receipts
    assert not policy.engagement.http_permissions._pending
    assert not policy.engagement.http_permissions._capture_grants


@pytest.mark.parametrize("args", [None, [], False, "not an object"])
async def test_registry_non_object_arguments_fail_before_policy(args, tmp_path, monkeypatch):
    tool = FileWriteTool()
    registry, p, operator, policy, prepare = dispatch(tool, tmp_path, monkeypatch)
    with pytest.raises(InvalidToolArguments, match="arguments must be an object"):
        await registry.execute(tool.name(), args, None, p)
    assert_no_review(operator, policy, prepare)


@pytest.mark.parametrize("factory", [FileWriteTool, FileWriteToolAlias])
@pytest.mark.parametrize("content", [MISSING, None, {}, True, 3, []])
@pytest.mark.parametrize("exists", [False, True])
async def test_invalid_write_never_creates_or_truncates(factory, content, exists, tmp_path, monkeypatch):
    path = tmp_path / "existing.txt" if exists else tmp_path / "new-parent" / "new.txt"
    original = b"original\r\nUTF-8: \xe2\x98\x83"
    if exists:
        path.write_bytes(original)
    tool = factory()
    args = {"path": str(path)}
    if content is not MISSING:
        args["content"] = content
    registry, p, operator, policy, prepare = dispatch(tool, tmp_path, monkeypatch)
    with pytest.raises(InvalidToolArguments, match="content.*string"):
        await registry.execute(tool.name(), args, None, p)
    assert path.read_bytes() == original if exists else not path.parent.exists()
    assert_no_review(operator, policy, prepare)


@pytest.mark.parametrize("factory", [FileEditTool, FileEditToolAlias])
@pytest.mark.parametrize("replacement", [MISSING, None, 7, False, {}])
async def test_invalid_edit_preserves_original_bytes(factory, replacement, tmp_path, monkeypatch):
    path = tmp_path / "existing.txt"
    original = b"keep MATCH keep\r\n"
    path.write_bytes(original)
    tool = factory()
    args = {"path": str(path), "old_string": "MATCH"}
    if replacement is not MISSING:
        args["new_string"] = replacement
    registry, p, operator, policy, prepare = dispatch(tool, tmp_path, monkeypatch)
    with pytest.raises(InvalidToolArguments, match="new_string.*string"):
        await registry.execute(tool.name(), args, None, p)
    assert path.read_bytes() == original
    assert_no_review(operator, policy, prepare)


@pytest.mark.parametrize("factory,args,field", [
    (FileWriteTool, {"path": {}, "content": "x"}, "path"),
    (FileEditTool, {"path": "", "old_string": "x", "new_string": ""}, "path"),
    (FileEditTool, {"path": "x", "old_string": None, "new_string": ""}, "old_string"),
    (FileEditTool, {"path": "x", "old_string": "", "new_string": ""}, "old_string"),
    (FileEditToolAlias, {"path": "x", "old_string": "x", "new_string": "", "replace_all": 1}, "replace_all"),
])
async def test_other_mutation_fields_fail_before_resource_resolution(factory, args, field, tmp_path, monkeypatch):
    tool = factory()
    registry, p, operator, policy, prepare = dispatch(tool, tmp_path, monkeypatch)
    with pytest.raises(InvalidToolArguments, match=field):
        await registry.execute(tool.name(), args, None, p)
    assert_no_review(operator, policy, prepare)


@pytest.mark.parametrize("factory", [FileWriteTool, FileWriteToolAlias])
async def test_authorized_empty_write_and_existing_modes(factory, tmp_path, monkeypatch):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    path = private / "file.txt"
    path.write_text("before")
    path.chmod(0o600)
    tool = factory()
    registry, p, operator, policy, _ = dispatch(tool, tmp_path, monkeypatch)
    await registry.execute(tool.name(), {"path": str(path), "content": ""}, None, p)
    assert path.read_bytes() == b""
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(private.stat().st_mode) == 0o700
    new_path = tmp_path / "new" / "file.txt"
    await registry.execute(tool.name(), {"path": str(new_path), "content": ""}, None, p)
    assert new_path.read_bytes() == b""
    assert stat.S_IMODE(new_path.stat().st_mode) == 0o644
    assert operator.ask.await_count == 2
    assert not policy._receipts


@pytest.mark.parametrize("factory", [FileEditTool, FileEditToolAlias])
@pytest.mark.parametrize("replace_all", [False, True])
async def test_empty_edit_deletes_only_with_valid_authorization(factory, replace_all, tmp_path, monkeypatch):
    path = tmp_path / "edit.txt"
    path.write_text("x keep x" if replace_all else "x keep")
    path.chmod(0o600)
    tool = factory()
    registry, p, operator, _, _ = dispatch(tool, tmp_path, monkeypatch)
    args = {"path": str(path), "old_string": "x", "new_string": "", "replace_all": replace_all}

    async def approve(_request, _signal):
        args["new_string"] = "caller changed this during review"
        return Decision.ALLOW_ONCE

    operator.ask.side_effect = approve
    await registry.execute(tool.name(), args, None, p)
    assert path.read_text() == (" keep " if replace_all else " keep")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert operator.ask.await_count == 1


@pytest.mark.parametrize("factory,key", [(FileWriteTool, "content"), (FileEditTool, "new_string")])
async def test_direct_file_adapter_also_rejects_missing_mutation(factory, key, tmp_path):
    path = tmp_path / "direct.txt"
    path.write_bytes(b"x\r\n")
    p = Mock(ask=AsyncMock())
    with pytest.raises(ValueError, match=key):
        await factory().run({"path": str(path), "old_string": "x"}, None, p)
    assert path.read_bytes() == b"x\r\n"
    p.ask.assert_not_called()


HTTP_BAD_FIELDS = [
    {"method": 7}, {"method": None}, {"method": True}, {"method": {}},
    {"method": ""}, {"method": "GET\r\nX: bad"},
    {"body": {}}, {"body": None}, {"body": True}, {"body": 3},
    {"headers": "bad"}, {"headers": None}, {"headers": []},
    {"headers": {"X-Probe": 7}}, {"headers": {"X-Probe": None}},
    {"headers": {"X-Probe": True}}, {"headers": {7: "value"}},
]


@pytest.mark.parametrize("fields", HTTP_BAD_FIELDS)
@pytest.mark.parametrize("direct", [False, True])
async def test_http_bad_fields_never_prepare_authority_or_send(fields, direct, tmp_path, monkeypatch):
    target = Target("http://127.0.0.1:3000")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    tool = HTTPTool(target, engagement)
    registry, p, operator, policy, prepare = dispatch(tool, tmp_path, monkeypatch, engagement)
    authorize = AsyncMock()
    send = AsyncMock()
    monkeypatch.setattr(tool.permissions, "authorize", authorize)
    monkeypatch.setattr(httpx.AsyncClient, "send", send)
    args = {"phase": "recon", "url": "/probe", **fields}
    before = deepcopy(args)
    with pytest.raises(ValueError, match="method|body|headers"):
        if direct:
            await tool.run(args, None, p)
        else:
            await registry.execute("http", args, None, p)
    assert args == before
    assert_no_review(operator, policy, prepare)
    authorize.assert_not_called()
    send.assert_not_called()


def test_invalid_http_summary_is_display_only_and_preserves_input(monkeypatch):
    target = Target("http://target.test:8080")
    engagement = EngagementState()
    engagement.initialize_target(target.base_url())
    tool = HTTPTool(target, engagement)
    prepare = Mock(side_effect=AssertionError("invalid preview must not prepare a request"))
    monkeypatch.setattr(tool, "_prepare_with_diff", prepare)
    args = {"phase": "recon", "url": "http://target.test:8080/", "headers": "bad"}
    before = deepcopy(args)
    preview = tool.summarize(args)
    assert "invalid arguments" in preview["summary"] and "headers" in preview["detail"]
    assert "not prepared" in preview["detail"]
    assert args == before
    prepare.assert_not_called()


@pytest.mark.parametrize("method", [MISSING, "pOsT"])
async def test_http_valid_request_bytes_match_the_review(method, tmp_path, monkeypatch):
    engagement = EngagementState()
    target = Target("http://127.0.0.1:3000")
    engagement.initialize_target(target.base_url())
    tool = HTTPTool(target, engagement)
    registry, p, operator, _, _ = dispatch(tool, tmp_path, monkeypatch, engagement)
    sent = []
    original_client = httpx.AsyncClient

    def handler(request):
        sent.append(request)
        return httpx.Response(200, content=b"offline response", request=request)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original_client(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr("src.tools.http.http_tool.gate_private_request", AsyncMock(return_value=""))
    body = "Tiếng Việt\r\n\x1b[31m{'probe':true}"
    args = {"phase": "recon", "url": "/probe", "body": body, "headers": {"X-Probe": "exact-value"}}
    if method is not MISSING:
        args["method"] = method

    async def approve(request, _signal):
        assert "exact-value" in request.detail
        args["body"] = "changed during review"
        args["headers"]["X-Probe"] = "changed"
        return Decision.ALLOW_ONCE

    operator.ask.side_effect = approve
    result = await registry.execute("http", args, None, p)
    assert isinstance(result, ToolOutput)
    assert result.http_status == 200 and len(sent) == 1
    assert sent[0].method == ("GET" if method is MISSING else "POST")
    assert sent[0].content == body.encode("utf-8")
    assert (b"X-Probe", b"exact-value") in sent[0].headers.raw
    assert operator.ask.await_count == 1


@pytest.mark.parametrize("bad_question", [
    {"question": "Choose", "header": 7},
    {"question": "Choose", "header": None},
    {"question": "Choose", "options": [{"label": str(i)} for i in range(5)]},
    {"question": "Choose", "choices": [str(i) for i in range(5)]},
    {"question": "Choose", "options": None},
    {"question": "Choose", "options": [{"label": "a", "description": 3}, {"label": "b"}]},
    {"question": False},
])
async def test_ask_validates_entire_batch_before_presenting(bad_question, tmp_path, monkeypatch):
    ask = Mock(ask=AsyncMock(return_value="answer"))
    tool = AskUserTool(ask)
    registry, p, operator, policy, prepare = dispatch(tool, tmp_path, monkeypatch)
    args = {"questions": [{"question": "Valid first question"}, bad_question]}
    with pytest.raises(InvalidToolArguments, match=r"questions\[1\]"):
        await registry.execute(tool.name(), args, None, p)
    with pytest.raises(ValueError):
        await tool.run(args, None, p)
    ask.ask.assert_not_called()
    assert_no_review(operator, policy, prepare)


async def test_ask_question_limit_and_legacy_ui_augmentation(tmp_path, monkeypatch):
    ask = Mock(ask=AsyncMock(return_value="answer"))
    tool = AskUserTool(ask)
    registry, p, operator, policy, prepare = dispatch(tool, tmp_path, monkeypatch)
    with pytest.raises(InvalidToolArguments, match="at most 4 questions"):
        await registry.execute(tool.name(), {"questions": [{"question": "q"}] * 5}, None, p)
    assert_no_review(operator, policy, prepare)
    choices = ["a", "b", "c", "d"]
    for wire in ({"choices": choices}, {"options": [{"label": c} for c in choices]}):
        args = {"questions": [{"question": "Which target are you authorized to test?", **wire}]}
        before = deepcopy(args)
        await registry.execute(tool.name(), args, None, p)
        assert len(ask.ask.call_args.args[0].options) == 5
        assert args == before


@pytest.mark.parametrize("limit", [None, True, False, 0, -1, 1.5, "2", {}, float("inf"), float("nan")])
async def test_coverage_invalid_limit_fails_before_store_access(limit, tmp_path, monkeypatch):
    store = CoverageStore(str(tmp_path / "coverage.json"))
    tool = CoverageTool(store)
    registry, p, operator, policy, prepare = dispatch(tool, tmp_path, monkeypatch)
    with pytest.raises(InvalidToolArguments, match="limit must be a positive integer"):
        await registry.execute(tool.name(), {"action": "list", "limit": limit}, None, p)
    assert not store.loaded and not (tmp_path / "coverage.json").exists()
    assert_no_review(operator, policy, prepare)


@pytest.mark.parametrize("limit,expected", [(MISSING, DEFAULT_PAGE_SIZE), (1, 1), (1.0, 1),
    (MAX_PAGE_SIZE, MAX_PAGE_SIZE), (MAX_PAGE_SIZE + 1, MAX_PAGE_SIZE), (10 ** 400, MAX_PAGE_SIZE)])
async def test_coverage_positive_integer_boundaries_and_clamping(limit, expected, tmp_path, monkeypatch):
    tool = CoverageTool(CoverageStore(str(tmp_path / "coverage.json")))
    registry, p, _, _, _ = dispatch(tool, tmp_path, monkeypatch)
    args = {"action": "list"}
    if limit is not MISSING:
        args["limit"] = limit
    result = json.loads(await registry.execute(tool.name(), args, None, p))
    assert result["ok"] and result["limit"] == expected
    schema = tool.schema()["properties"]["limit"]
    assert schema["type"] == "integer" and schema["minimum"] == 1


@pytest.mark.parametrize("cursor", [None, 0, True, "-1", "1.0", "", "1" * 13, "²"])
async def test_coverage_cursor_types_fail_early(cursor, tmp_path, monkeypatch):
    tool = CoverageTool(CoverageStore(str(tmp_path / "coverage.json")))
    registry, p, operator, policy, prepare = dispatch(tool, tmp_path, monkeypatch)
    with pytest.raises(InvalidToolArguments, match="cursor"):
        await registry.execute(tool.name(), {"action": "list", "cursor": cursor}, None, p)
    assert_no_review(operator, policy, prepare)


@pytest.mark.parametrize("factory", [make_content_tool, make_service_tool])
async def test_discovery_published_bounds_are_enforced_before_reviews(factory, tmp_path, monkeypatch):
    tool = factory()
    schema = tool.schema()["properties"]
    registry, p, operator, policy, prepare = dispatch(tool, tmp_path, monkeypatch, tool.engagement)
    for field in ("max_requests", "rate_limit", "timeout_seconds"):
        if field not in schema:
            continue
        bounds = schema[field]
        for value in (bounds["minimum"], bounds["maximum"]):
            tool.validate_args({field: value})
        for value in (bounds["minimum"] - 1, bounds["maximum"] + 1, True, 5.5):
            with pytest.raises(InvalidToolArguments, match=field):
                await registry.execute(tool.name(), {field: value}, None, p)
    for field in ("paths", "ports"):
        if field not in schema:
            continue
        assert schema[field]["minItems"] == 1
        over_limit = ["health" if field == "paths" else 8080] * (schema[field]["maxItems"] + 1)
        for value in ([], over_limit):
            with pytest.raises(InvalidToolArguments, match=field):
                await registry.execute(tool.name(), {field: value}, None, p)
    assert_no_review(operator, policy, prepare)
