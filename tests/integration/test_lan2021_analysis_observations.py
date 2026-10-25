"""Declared analysis comparisons check request identity, never SQL semantics."""
import json
from copy import deepcopy

import pytest

from tests.helpers.discovery_calls import execute
from tests.integration.test_input_http_source import offline, source_runtime  # noqa: F401


@pytest.mark.parametrize("fault", ["method", "path", "missing"])
async def test_analysis_observation_mismatch_rejects_candidate_atomically(tmp_path, fault):
    rt, source = await source_runtime(tmp_path)
    before = deepcopy(rt.workflow.to_dict())
    result = await execute(rt, "workflow", {"action": "record_candidate", "candidate_class": "sqli",
        "method": "POST" if fault == "method" else "GET",
        "endpoint": "/other" if fault == "path" else "/search", "parameter": "q", "location": "query",
        "observation_ids": ["obs_" + "f" * 32 if fault == "missing" else source.retained_ref],
        "signals": ["Bounded analysis hypothesis; no confirmation."]}, success=False)
    expected = {"method": "method does not match", "path": "path does not match", "missing": "source_ref unavailable"}
    assert result.status == "error" and expected[fault] in result.result
    assert rt.workflow.to_dict() == before


async def test_analysis_facts_are_authoritative_and_grant_no_terminal_ownership(tmp_path):
    rt, source = await source_runtime(tmp_path)
    observation = rt.policy.observations._items[source.retained_ref]
    output = json.loads((await execute(rt, "workflow", {"action": "record_candidate",
        "candidate_class": "sqli", "method": "GET", "endpoint": "/search", "parameter": "q",
        "location": "query", "observation_ids": [source.retained_ref],
        "signals": ["Hypothesis from existing context, not a confirmed finding."]})).result)
    fact = output["analysis_observations"][0]
    assert fact["observation_id"] == observation.id
    assert fact["method"] == "GET" and fact["status"] == 200
    assert fact["response_media_type"] == "text/plain" and fact["request_url"] == observation.url
    assert fact["terminal_evidence"] is False
    assert observation.candidate_id is observation.attempt_id is None
    assert not rt.workflow.attempts and not rt.workflow.validation_results and not rt.workflow.evidence


@pytest.mark.parametrize("declared", ["application/json; charset=utf-8", "application/x-www-form-urlencoded"])
async def test_request_media_is_checked_independently_of_response_media(tmp_path, declared):
    rt, _ = await source_runtime(tmp_path)
    await execute(rt, "http", {"method": "POST", "url": "/search",
        "headers": {"Content-Type": "application/json; charset=UTF-8"},
        "body": '{"q":"fixture"}', "phase": "recon"})
    item = next(row for row in rt.policy.observations._items.values() if row.method == "POST")
    before = deepcopy(rt.workflow.to_dict())
    output = await execute(rt, "workflow", {"action": "record_candidate", "candidate_class": "sqli",
        "method": "POST", "endpoint": "/search", "parameter": "q", "location": "json",
        "content_type": declared, "observation_ids": [item.id]}, success=False)
    if declared.startswith("application/json"):
        fact = json.loads(output.result)["analysis_observations"][0]
        assert fact["request_media_type"] == "application/json"
        assert fact["response_media_type"] == "text/plain"
        assert item.candidate_id is item.attempt_id is None
    else:
        assert output.status == "error" and "media type does not match" in output.result
        assert rt.workflow.to_dict() == before
