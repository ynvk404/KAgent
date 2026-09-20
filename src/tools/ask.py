from __future__ import annotations

import json

from src.ask.ask import (
    AskPrompter,
    Option,
    Question,
)
from src.permission.permission import Prompter
from .types import Tool

AUTHORIZED_TESTING_OPTION = Option(
    label="Authorized testing",
    description="I have permission to test this target.",
)

class AskUserTool(Tool):
    def __init__(
        self,
        prompter: AskPrompter,
    ):
        self.prompter = prompter

    def name(self) -> str:
        return "ask_user"

    def description(self) -> str:
        return (
            "Ask the user a question, optionally with multiple-choice options, "
            "to disambiguate or get a decision. Prefer this tool when missing "
            "user-supplied information blocks a concrete workflow and execution "
            "should continue in the same turn, such as a target URL, endpoint, "
            "HTTP method, target identity, finite selection, workflow branch, "
            "required credential/session/token/OTP, or explicit scope or "
            "authorization checkpoint. Use normal assistant text for open-ended "
            "discussion or clarification that does not need same-turn continuation. "
            "This tool collects user intent, context, or inputs; it does not replace "
            "a runtime permission prompt for a proposed tool action. Omit options "
            "when collecting "
            "an arbitrary user-supplied value that cannot be enumerated in "
            "advance. Use options only for a genuinely finite set of known "
            "choices that materially changes the next step; do not add an "
            "option question when every choice merely leads to a free-text "
            "question. When the requested action or object is ambiguous, ask "
            "neutrally about the missing object or scope; do not invent one."
        )

    def schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "questions": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 4,
                    "items": {
                        "type": "object",
                        "properties": {
                            "header": {
                                "type": "string",
                                "description": "Optional short label for the question.",
                            },
                            "question": {
                                "type": "string",
                                "description": "The question to show the user.",
                            },
                            "options": {
                                "type": "array",
                                "minItems": 2,
                                "maxItems": 4,
                                "description": (
                                    "Two to four finite, known choices that "
                                    "materially change the next step. Omit "
                                    "options for arbitrary user-supplied "
                                    "values; ask for those directly as free "
                                    "text. Use this field, not choices."
                                ),
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "label": {
                                            "type": "string",
                                            "description": "Short text shown for this choice.",
                                        },
                                        "description": {
                                            "type": "string",
                                            "description": "Optional explanation of this choice.",
                                        },
                                    },
                                    "required": ["label"],
                                },
                            },
                        },
                        "required": ["question"],
                    },
                }
            },
            "required": [
                "questions"
            ],
        }

    def requires_permission(self) -> bool:
        return False

    def context_reduction_policy(self) -> str:
        # Answers carry user intent needed by the remainder of the same turn.
        return "preserve"

    def summarize(
        self,
        args: dict,
    ) -> dict:
        return {
            "summary":
                "ask_user: multiple-choice question",
            "detail":
                json.dumps(
                    args,
                    indent=2
                )
        }

    async def run(
        self,
        args: dict,
        signal,
        prompter: Prompter,
    ) -> str:
        raw = args.get("questions")

        if not isinstance(raw, list) or not raw:
            raise Exception(
                "questions is required"
            )

        answers = []

        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                raise Exception(
                    f"questions[{i}] invalid"
                )

            qtext = item.get(
                "question",
                ""
            )

            if not isinstance(qtext, str) or not qtext:
                raise Exception(
                    f"questions[{i}] question required"
                )

            header = item.get(
                "header"
            )

            options = []

            raw_options = item.get("options")
            legacy_choices = raw_options is None and "choices" in item

            # Earlier providers saw an underspecified schema and sometimes
            # emitted `choices: ["Yes", "No"]`.  Keep that wire shape
            # compatible while advertising and internally using `options`.
            if legacy_choices:
                raw_options = item.get("choices", [])

            if raw_options is None:
                question = Question(
                    question=qtext,
                    options=[],
                    header=header,
                )
            else:
                if not isinstance(raw_options, list):
                    raise Exception(f"questions[{i}] options must be an array")

                for option_index, opt in enumerate(raw_options):
                    if legacy_choices and isinstance(opt, str):
                        label = opt
                        description = None
                    elif isinstance(opt, dict):
                        label = opt.get("label", "")
                        description = opt.get("description")
                    else:
                        raise Exception(
                            f"questions[{i}] options[{option_index}] invalid"
                        )

                    if not isinstance(label, str) or not label:
                        raise Exception(
                            f"questions[{i}] options[{option_index}] label required"
                        )

                    if description is not None and not isinstance(description, str):
                        raise Exception(
                            f"questions[{i}] options[{option_index}] description invalid"
                        )

                    options.append(
                        Option(
                            label=label,
                            description=description,
                        )
                    )

                add_authorized_testing_option(
                    qtext,
                    header,
                    options,
                )

                if len(options) < 2:
                    raise Exception(
                        f"questions[{i}] at least 2 options required"
                    )

                question = Question(
                    question=qtext,
                    options=options,
                    header=header,
                )

            choice = await self.prompter.ask(
                question,
                signal
            )

            answers.append(
                {
                    "question": qtext,
                    "answer": choice
                }
            )

        return json.dumps(
            {
                "answers": answers
            },
            indent=2
        )

def add_authorized_testing_option(
    question: str,
    header: str | None,
    opts: list[Option],
):
    if not is_authorization_scope_question(
        question,
        header
    ):
        return

    if any(
        o.label.lower()
        ==
        AUTHORIZED_TESTING_OPTION.label.lower()
        for o in opts
    ):
        return

    opts.insert(
        0,
        AUTHORIZED_TESTING_OPTION
    )

def is_authorization_scope_question(
    question: str,
    header: str | None,
):
    text = (
        f"{header or ''} {question}"
    ).lower()

    return (
        "authorized to test" in text
        or
        "permission to test" in text
        or
        (
            "scope" in text
            and
            "target" in text
        )
        or
        (
            "authorized" in text
            and
            "target" in text
        )
    )
