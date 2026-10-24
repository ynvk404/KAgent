"""All active native tool declarations through offline provider encoders."""
from copy import deepcopy
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator

from src.findings.store import Store as FindingStore
from src.llm.core.types import ChatRequest, Message
from src.llm.providers import anthropic, gemini
from src.llm.providers.openai import OpenAIClient
from src.tools.common.ask import AskUserTool
from src.tools.common.permission_status import PermissionStatusTool
from src.tools.discovery.content import ContentDiscoveryTool
from src.tools.discovery.service import ServiceDiscoveryTool
from src.tools.execution.file import FileReadTool, FileReadToolAlias, FileWriteToolAlias, FileEditTool, FileEditToolAlias
from src.tools.execution.search import GlobTool, GrepTool
from src.tools.execution.shell import ShellTool, BashTool
from src.tools.http.web import WebFetchTool, WebSearchTool
from src.tools.skills.payloads import ReadPayloadsTool
from src.tools.skills.skill_file import ReadSkillFileTool
from src.tools.workflow.action_view import ActionView
from src.tools.workflow.coverage import CoverageTool
from src.tools.workflow.finding import ConfirmFindingTool
from tests.helpers.burp_selection import make_runtime


@pytest.mark.parametrize("provider", ["openai-compat", "deepseek", "anthropic", "gemini"])
@pytest.mark.parametrize("mode", ["direct", "whole_target"])
def test_all_native_tool_contracts_survive_provider_projection(tmp_path, provider, mode):
    rt = make_runtime(tmp_path)
    registry = rt.agent.tools
    for tool in (FileReadTool(), FileReadToolAlias(), FileWriteToolAlias(), FileEditTool(), FileEditToolAlias(),
                 ShellTool(), BashTool(), GlobTool(), GrepTool(),
                 ContentDiscoveryTool(rt.target, rt.engagement, workflow=rt.workflow),
                 ServiceDiscoveryTool(rt.target, rt.engagement, workflow=rt.workflow),
                 WebFetchTool(rt.engagement, rt.target), WebSearchTool(),
                 AskUserTool(cast(Any, None)), PermissionStatusTool(),
                 ReadPayloadsTool(rt.skills), ReadSkillFileTool(rt.skills),
                 CoverageTool(rt.coverage), ConfirmFindingTool(FindingStore(tmp_path / "findings"), workflow=rt.workflow)):
        registry.register(tool)
    original = cast(list[dict[str, Any]], registry.as_llm_tools())
    before = deepcopy(original)
    # Every locally generated declaration must be a valid JSON Schema.
    for spec in original:
        Draft202012Validator.check_schema(spec["function"]["parameters"])
    projected = ActionView.for_objective(mode).project_tools(original)
    request = ChatRequest("offline-fixture", [Message("user", "continue")], tools=cast(Any, projected))
    if provider in {"openai-compat", "deepseek"}:
        body = OpenAIClient("https://fixture.invalid", "synthetic", "offline-fixture").encode_request(request, False)
        encoded = {item["function"]["name"]: item["function"] for item in body["tools"]}
    elif provider == "anthropic":
        body = anthropic.encode_request(request, request.model)
        encoded = {item["name"]: {**item, "parameters": item["input_schema"]} for item in body["tools"]}
    else:
        body = gemini.encode_request(request)
        encoded = {item["name"]: item for item in body["tools"][0]["functionDeclarations"]}
    assert original == before
    assert set(encoded) == set(registry.names())
    assert len(encoded) >= 30  # aliases, capture tools, all three controller readers
    for spec in cast(list[dict[str, Any]], projected):
        local = spec["function"]
        remote = encoded[local["name"]]
        assert remote["description"] == local["description"]
        schema = remote["parameters"]
        if provider != "gemini":
            assert schema == local["parameters"]
        else:
            assert schema == gemini.normalize_schema(local["parameters"])
    props = encoded["workflow"]["parameters"]["properties"]
    assert props["discovery_source_id"]["pattern"] == "^ds_[0-9a-f]{64}$"
    assert props["endpoint_id"]["pattern"] == "^ep_[0-9a-f]{64}$"
    assert props["source_bounds"]["properties"]["max_bytes"]["maximum"] == 16 * 1024**2
    assert "headers" in encoded["http"]["parameters"]["properties"]["candidate_id"]["description"]
    # Gemini deliberately drops additionalProperties; local runtime remains the gate.
    if provider == "gemini":
        assert "additionalProperties" not in props["source_bounds"]
    else:
        assert props["source_bounds"]["additionalProperties"] is False
