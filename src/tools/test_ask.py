"""
Test AskUserTool

Port từ:
kagent/src/tools/ask.test.ts
"""

from __future__ import annotations

import json

import pytest

from src.ask.ask import (
    AskPrompter,
    Question,
)

from src.permission.permission import AlwaysAllow

from src.tools.ask import AskUserTool



# ==========================================================
# Fake AskPrompter
# ==========================================================

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



# ==========================================================
# Tests
# ==========================================================


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