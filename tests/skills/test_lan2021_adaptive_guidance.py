"""Delivered instructions and cost bounds, not a claim of LLM compliance."""
import re

import pytest

from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry


async def guidance(name):
    registry = Registry()
    registry.load_dir("skills")
    return " ".join((await LoadSkillTool(registry).run({"name": name})).replace("`", "").lower().split())


async def test_source_menu_uses_information_value_and_cost_without_mandatory_branches():
    text = await guidance("web-enumeration")
    for pattern in (r"source menu.{0,150}not.{0,80}(?:checklist|required order)",
                    r"expected.{0,80}information.{0,150}cost", r"next.{0,60}discovery question",
                    r"find_text.{0,180}(?:retained|literal)"):
        assert re.search(pattern, text)


async def test_schema_and_call_site_completeness_do_not_require_scalar_sink():
    text = await guidance("web-enumeration")
    assert re.search(r"arrays.{0,140}(?:not|never).{0,100}(?:scalar|sink)", text)
    assert re.search(r"vendor.{0,160}(?:not|never).{0,100}(?:entire|whole)", text)
    assert re.search(r"api.base.{0,100}(?:unresolved|unknown)", text)


@pytest.mark.parametrize("name", ["web-input-analysis", "sql-injection"])
async def test_comparison_and_implementation_claims_require_exact_evidence(name):
    text = await guidance(name)
    assert re.search(r"method.{0,120}(?:mismatch|different).{0,160}(?:baseline|comparison)", text)
    assert re.search(r"(?:parser|middleware).{0,100}order.{0,150}(?:unknown|not|unverified)", text)


async def test_dependency_question_preserves_keep_blocked_and_previous_answers():
    text = await guidance("web-input-analysis")
    assert "input_ids" in text and "keep blocked" in text and "do not re-ask" in text


async def test_other_expert_skill_uses_shared_per_input_admission():
    text = await guidance("cross-site-scripting")
    assert "canonical analysis handoff" in text and "linked analyzed input" in text
    assert "independent blocked inputs" in text and "incomplete" in text
