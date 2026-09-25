from __future__ import annotations

import json

import pytest

from src.ask.ask import (
    AskPrompter,
    Question,
)
from src.permission.permission import AlwaysAllow
from src.tools.ask import AskUserTool

class CaptureAskPrompter(AskPrompter):
    def __init__(self):
        self.questions: list[Question] = []

    async def ask(
        self,
        q: Question,
        signal=None,
    ) -> str:
        self.questions.append(q)

        return (
            q.options[0].label
            if q.options
            else ""
        )


def test_schema_advertises_options_for_each_question():
    tool = AskUserTool(CaptureAskPrompter())
    schema = tool.schema()
    question = schema["properties"]["questions"]["items"]
    options_description = question["properties"]["options"]["description"]

    assert question["required"] == ["question"]
    assert question["properties"]["options"]["minItems"] == 2
    assert "choices" not in question["properties"]
    assert "finite choices" in options_description
    assert "arbitrary user-supplied values" in options_description
    assert "free text" in options_description


def test_ask_user_preserves_user_control_answers_in_working_context():
    tool = AskUserTool(CaptureAskPrompter())

    assert tool.context_reduction_policy() == "preserve"


def test_description_explains_when_to_omit_or_use_options():
    description = AskUserTool(CaptureAskPrompter()).description()

    assert "Omit options for arbitrary user-supplied values" in description
    assert "finite known choices" in description
    assert "materially change the next step" in description
    assert "choices that all lead to free text" in description


def test_description_distinguishes_blocking_tool_questions_from_conversation():
    description = AskUserTool(CaptureAskPrompter()).description()

    assert "blocks same-turn work" in description
    assert "target, endpoint/method" in description
    assert "credentials/session/token/OTP" in description
    assert "normal assistant text" in description
    assert "does not approve actions or replace a runtime permission prompt" in description


@pytest.mark.asyncio
async def test_accepts_open_ended_question_without_options():
    class FreeTextPrompter(CaptureAskPrompter):
        async def ask(self, q: Question, signal=None) -> str:
            self.questions.append(q)
            return "coverage state"

    prompter = FreeTextPrompter()
    result = await AskUserTool(prompter).run(
        {"questions": [{"question": "What should be reset?"}]},
        None,
        AlwaysAllow(),
    )

    assert prompter.questions[0].options == []
    assert json.loads(result)["answers"][0]["answer"] == "coverage state"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "options, error",
    [
        ([], "at least 2 options required"),
        ([{"label": "Only choice"}], "at least 2 options required"),
        (["not an option object", {"label": "Choice"}], r"options\[0\] invalid"),
        ([{"description": "missing label"}, {"label": "Choice"}], "label required"),
    ],
)
async def test_rejects_invalid_structured_options(options, error):
    with pytest.raises(Exception, match=error):
        await AskUserTool(CaptureAskPrompter()).run(
            {"questions": [{"question": "Choose", "options": options}]},
            None,
            AlwaysAllow(),
        )


@pytest.mark.asyncio
async def test_accepts_legacy_choices_payload_from_openai_compatible_models():
    prompter = CaptureAskPrompter()
    tool = AskUserTool(prompter)

    result = await tool.run(
        {
            "questions": [
                {
                    "question": "Do you want to reset the testing session?",
                    "choices": ["Yes", "No"],
                }
            ]
        },
        None,
        AlwaysAllow(),
    )

    assert [option.label for option in prompter.questions[0].options] == [
        "Yes",
        "No",
    ]
    assert json.loads(result) == {
        "answers": [
            {
                "question": "Do you want to reset the testing session?",
                "answer": "Yes",
            }
        ]
    }

@pytest.mark.asyncio
async def test_adds_authorized_testing_to_authorization_scope_questions():
    prompter = CaptureAskPrompter()
    tool = AskUserTool(prompter)

    out = await tool.run(
        {
            "questions": [
                {
                    "header": "Scope",
                    "question":
                        "Which target are you authorized to test?",
                    "options": [
                        {
                            "label":
                                "Just curious / explore"
                        },
                        {
                            "label":
                                "Web vuln hunt"
                        },
                    ],
                }
            ]
        },
        None,
        AlwaysAllow(),
    )

    assert [
        o.label
        for o in prompter.questions[0].options
    ] == [
        "Authorized testing",
        "Just curious / explore",
        "Web vuln hunt",
    ]

    assert json.loads(out) == {
        "answers": [
            {
                "question":
                    "Which target are you authorized to test?",
                "answer":
                    "Authorized testing",
            }
        ]
    }

@pytest.mark.asyncio
async def test_does_not_duplicate_authorized_testing_when_already_present():
    prompter = CaptureAskPrompter()
    tool = AskUserTool(prompter)

    await tool.run(
        {
            "questions": [
                {
                    "question":
                        "Which target are you authorized to test?",
                    "options": [
                        {
                            "label":
                                "Authorized testing"
                        },
                        {
                            "label":
                                "Just curious / explore"
                        },
                    ],
                }
            ]
        },
        None,
        AlwaysAllow(),
    )

    assert [
        o.label
        for o in prompter.questions[0].options
    ] == [
        "Authorized testing",
        "Just curious / explore",
    ]

@pytest.mark.asyncio
async def test_does_not_add_authorized_testing_to_unrelated_questions():
    prompter = CaptureAskPrompter()
    tool = AskUserTool(prompter)

    await tool.run(
        {
            "questions": [
                {
                    "question":
                        "Do you have authenticated credentials to use?",
                    "options": [
                        {
                            "label":
                                "Unauthenticated only"
                        },
                        {
                            "label":
                                "I have credentials"
                        },
                    ],
                }
            ]
        },
        None,
        AlwaysAllow(),
    )

    assert [
        o.label
        for o in prompter.questions[0].options
    ] == [
        "Unauthenticated only",
        "I have credentials",
    ]
