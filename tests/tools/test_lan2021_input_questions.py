"""Dependency identity deduplicates questions without granting exclusions."""
import json

import pytest

from src.skills.registry import Registry
from src.tools.common.ask import AskUserTool
from src.workflow.state import AttackSurfaceInput, WorkflowObjective, WorkflowState
from tests.security.test_execution_policy import ORIGIN
from tests.security.test_execution_policy import runtime as execution_runtime

runtime = execution_runtime


class Operator:
    def __init__(self):
        self.questions = []

    async def ask(self, q, signal=None):
        self.questions.append(q)
        return "Keep blocked"


def dependency(runtime):
    _, prompter, policy, _, _, _, target = runtime
    state = WorkflowState(objective=WorkflowObjective("questions", "whole_target", ORIGIN))
    item, _ = state.add_attack_surface_input(AttackSurfaceInput("questions", ORIGIN,
        method="POST", endpoint="/private/order", parameter="lines", location="json"))
    state.set_input_disposition(item.id, "blocked", reason="Credential missing; untested.")
    policy.bind_validation_context(state, Registry(), target)
    return prompter, policy, state, item


async def test_reworded_dependency_question_preserves_original_answer_and_state(runtime):
    prompter, policy, state, item = dependency(runtime)
    operator = Operator()
    tool = AskUserTool(operator)
    before = state.to_dict()
    rights = dict(policy.engagement.http_permissions.grants)
    first = {"question": "Missing credential: provide it or keep blocked?", "input_ids": [item.id]}
    second = {"question": "Exclude the input to unblock validation?", "input_ids": [item.id]}
    a = json.loads(await tool.run({"questions": [first]}, None, prompter))
    policy.revision += 1  # Permission mode/review changes are not new input intent.
    b = json.loads(await tool.run({"questions": [second]}, None, prompter))
    assert len(operator.questions) == 1
    assert a == b and b["answers"][0]["question"] == first["question"]
    assert state.to_dict() == before and item.disposition == "blocked"
    assert policy.engagement.http_permissions.grants == rights
    policy.retry()  # Explicit operator retry is allowed to reconsider the question.
    await tool.run({"questions": [second]}, None, prompter)
    assert len(operator.questions) == 2


async def test_unknown_dependency_in_batch_rejects_before_any_question(runtime):
    prompter, _, _, item = dependency(runtime)
    operator = Operator()
    with pytest.raises(ValueError, match="input"):
        await AskUserTool(operator).run({"questions": [
            {"question": "First", "input_ids": [item.id]},
            {"question": "Wrong", "input_ids": ["input_unknown"]},
        ]}, None, prompter)
    assert not operator.questions
