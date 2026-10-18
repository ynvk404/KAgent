"""Target selection follows operator instructions, not supplied example text."""
from copy import deepcopy

import pytest

from src.agent.agent import Agent, AgentOptions
from src.permission.permission import AlwaysAllow
from src.skills.registry import Registry as Skills
from src.target.target import Target
from src.tools.common.registry import Registry
from tests.helpers.agent_fakes import FakeClient, FakeSignal, collect


def make_agent(url=""):
    return Agent(AgentOptions(FakeClient([]), Registry(), Skills(), AlwaysAllow(),
                              None, Target(url)))


@pytest.mark.parametrize("existing", ["", "https://active.test"])
@pytest.mark.parametrize("user_msg", [
    "Explain this text:\n> Scan https://quoted.invalid",
    "Please explain:\n```text\nScan https://quoted.invalid\n```",
    "Explain this example:\n~~~\nScan https://quoted.invalid\n~~~",
    "Explain this command: `Scan https://quoted.invalid`",
    'Explain the sentence "Scan https://quoted.invalid".',
    "Explain how to scan https://quoted.invalid",
    "Describe a security assessment of https://quoted.invalid",
    "Do not scan https://quoted.invalid",
    "Scan the current target.\n> Reference: https://quoted.invalid",
    "Explain this text:\n    Scan https://quoted.invalid",
    "Explain this quoted paragraph:\n> Example instruction:\nScan https://quoted.invalid",
])
def test_example_or_informational_url_cannot_select_target(existing, user_msg):
    agent = make_agent(existing)
    if existing:
        from src.workflow.state import Candidate
        agent._initialize_request_objective("Perform a whole-target assessment", True)
        assert agent.workflow.objective is not None
        agent.workflow.add_candidate(Candidate(
            candidate_class="sql-injection", target=existing, endpoint="/search",
            objective_id=agent.workflow.objective.id,
        ))
    before = deepcopy((agent.target.to_dict(), agent.target.revision,
                       agent.engagement_state.to_dict(), agent.workflow.to_dict(),
                       agent.workflow.committed_revision, agent.history))
    assert agent.initialize_target_from_user_request(user_msg) is False
    assert (agent.target.to_dict(), agent.target.revision,
            agent.engagement_state.to_dict(), agent.workflow.to_dict(),
            agent.workflow.committed_revision, agent.history) == before


@pytest.mark.parametrize("existing", ["", "https://active.test"])
@pytest.mark.parametrize("user_msg,mode", [
    ("Scan https://selected.test", "direct"),
    ("Please test GET https://selected.test/search parameter q for SQL injection", "direct"),
    ("Perform a whole-target assessment of https://selected.test", "whole_target"),
    ("Perform a web security assessment of https://selected.test. Start with reconnaissance.", "whole_target"),
    ("Explain the example below. Then scan https://selected.test\n> Scan https://quoted.invalid", "direct"),
    ("Scan `https://selected.test`", "direct"),
    ('Please scan "https://selected.test"', "direct"),
    ("Set target to https://selected.test", "direct"),
    ("Switch the target to https://selected.test", "direct"),
    ("Scan https://selected.test\n```\nScan https://quoted.invalid\n```", "direct"),
    ("Scan the following target:\nhttps://selected.test", "direct"),
    ("Explain this quote:\n> Example:\nScan https://quoted.invalid\n\nThen scan https://selected.test", "direct"),
])
def test_explicit_instruction_selects_or_switches_target(existing, user_msg, mode):
    agent = make_agent(existing)
    assert agent.initialize_target_from_user_request(user_msg) is True
    agent._initialize_request_objective(user_msg, True)
    assert agent.target.base_url() == "https://selected.test"
    assert agent.workflow.objective is not None
    assert agent.workflow.objective.mode == mode
    assert agent.workflow.objective.target_origin == "https://selected.test"
    assert [origin.as_url() for origin in agent.engagement_state.allowed_origins] == ["https://selected.test"]


@pytest.mark.parametrize("user_msg", [
    "Scan https://one.test and https://two.test",
    "Scan the current target. Explain https://quoted.invalid",
    "Explain https://quoted.invalid; scan the current target",
])
def test_ambiguous_or_unrelated_url_does_not_switch_target(user_msg):
    agent = make_agent("https://active.test")
    assert agent.initialize_target_from_user_request(user_msg) is False
    assert agent.target.base_url() == "https://active.test"


async def test_explanation_with_quoted_scan_keeps_target_at_real_run_boundary():
    from src.llm.core.types import ChatResponse, Message
    agent = make_agent("https://active.test")
    agent.client = FakeClient([ChatResponse(Message("assistant", "It is a scan example."), "stop")])
    await agent.run("Explain this text:\n> Scan https://quoted.invalid", FakeSignal(), collect()["sink"])
    assert agent.target.base_url() == "https://active.test"
    assert agent.workflow.objective is not None and agent.workflow.objective.mode == "direct"


def test_same_origin_request_does_not_reset_active_workflow():
    agent = make_agent("https://selected.test")
    agent._initialize_request_objective("Perform a whole-target assessment", True)
    before = deepcopy(agent.workflow.to_dict())
    assert agent.initialize_target_from_user_request("Scan https://selected.test/search") is False
    assert agent.workflow.to_dict() == before
