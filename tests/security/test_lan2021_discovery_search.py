"""Bounded literal lookup avoids scanning vendor prefixes or fetching again."""
import json
from copy import deepcopy

import pytest

from tests.helpers.discovery_calls import execute
from tests.skills.test_inline_openapi_guidance import retained_initializer


@pytest.mark.parametrize("needle,matched", [("/api/catalog", True), ("unseen-route", False)])
async def test_literal_lookup_reads_retained_call_site_without_http_or_ownership(tmp_path, monkeypatch, needle, matched):
    body = "/* vendor */" * 600 + 'const base=config.api; client.get(base+"/api/catalog",{params:{filter:value}});'
    rt, source, requests = await retained_initializer(tmp_path, monkeypatch, body, cap=16384)
    before = deepcopy(rt.workflow.to_dict())
    result = await execute(rt, "read_discovery_source", {"discovery_source_id": source.id,
        "start_char": 0, "max_chars": 2000, "find_text": needle})
    header, content = result.result.split("\n", 1)
    metadata = json.loads(header)
    assert len(result.result) <= 2000 and metadata["literal_match"] is matched
    if matched:
        assert 'client.get(base+"/api/catalog"' in content and "filter:value" in content
        assert metadata["start_char"] > 6000
    else:
        assert content == "" and metadata["next_start_char"] is None
    assert rt.workflow.to_dict() == before and len(requests) == 1
    assert not rt.workflow.candidates and not rt.workflow.attempts and not rt.workflow.evidence
    rt.policy.revoke("http")
    denied = await execute(rt, "read_discovery_source", {"discovery_source_id": source.id,
        "start_char": 0, "max_chars": 2000, "find_text": needle}, success=False)
    assert denied.status != "success" and len(requests) == 1
