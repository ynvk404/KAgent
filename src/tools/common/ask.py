from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from src.permission.permission import Prompter
from src.tools.common.types import Tool


@dataclass
class Option:
    label: str
    description: Optional[str] = None


@dataclass
class Question:
    question: str
    options: list[Option] = field(default_factory=list)
    header: Optional[str] = None


class AskPrompter(Protocol):

    async def ask(self, q: Question, signal: Any = None) -> str:
        ...


class FirstOptionPrompter:

    async def ask(self, q: Question, signal: Any = None) -> str:
        if not q.options:
            raise RuntimeError("ask: no options")
        return q.options[0].label


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
            "Ask up to four questions when missing input blocks same-turn work "
            "(target, endpoint/method, identity, workflow branch, "
            "credentials/session/token/OTP, or scope/authorization). Use normal "
            "assistant text for open-ended discussion. This gathers user input; "
            "it does not approve actions or replace a runtime permission prompt. "
            "Omit options for arbitrary user-supplied values. Use 2–4 finite "
            "known choices only when they materially change the next step; do not "
            "offer choices that all lead to free text. Ask neutrally about a "
            "missing object or scope; do not invent one."
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
                                    "Use options, not choices: 2–4 finite choices "
                                    "that change the next step. Omit for arbitrary "
                                    "user-supplied values; ask in free text."
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

    def validate_args(self, args: dict[str, Any]) -> None:
        self._questions(args)

    def _questions(self, args: dict[str, Any]) -> list[Question]:
        raw = args.get("questions")

        if not isinstance(raw, list) or not raw:
            raise ValueError(
                "questions is required"
            )

        if len(raw) > 4:
            raise ValueError("questions must contain at most 4 questions")
        questions = []

        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                raise ValueError(
                    f"questions[{i}] invalid"
                )

            qtext = item.get(
                "question",
                ""
            )

            if not isinstance(qtext, str) or not qtext:
                raise ValueError(
                    f"questions[{i}] question required"
                )

            header = item.get(
                "header"
            )
            if "header" in item and not isinstance(header, str):
                raise ValueError(f"questions[{i}] header must be a string")

            options = []

            raw_options = item.get("options")
            legacy_choices = raw_options is None and "choices" in item

            # Earlier providers saw an underspecified schema and sometimes
            # emitted `choices: ["Yes", "No"]`.  Keep that wire shape
            # compatible while advertising and internally using `options`.
            if legacy_choices:
                raw_options = item.get("choices", [])
            if raw_options is None and ("options" in item or legacy_choices):
                raise ValueError(f"questions[{i}] options must be an array")

            if raw_options is None:
                question = Question(
                    question=qtext,
                    options=[],
                    header=header,
                )
            else:
                if not isinstance(raw_options, list):
                    raise ValueError(f"questions[{i}] options must be an array")
                # Bounds apply to submitted choices, before trusted UI
                # augmentation can add the authorization-testing option.
                if len(raw_options) < 2:
                    raise ValueError(f"questions[{i}] at least 2 options required")
                if len(raw_options) > 4:
                    raise ValueError(f"questions[{i}] at most 4 options allowed")

                for option_index, opt in enumerate(raw_options):
                    if legacy_choices and isinstance(opt, str):
                        label = opt
                        description = None
                    elif isinstance(opt, dict):
                        label = opt.get("label", "")
                        description = opt.get("description")
                    else:
                        raise ValueError(
                            f"questions[{i}] options[{option_index}] invalid"
                        )

                    if not isinstance(label, str) or not label:
                        raise ValueError(
                            f"questions[{i}] options[{option_index}] label required"
                        )

                    if description is not None and not isinstance(description, str):
                        raise ValueError(
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

                question = Question(
                    question=qtext,
                    options=options,
                    header=header,
                )

            questions.append(question)
        return questions

    async def run(
        self,
        args: dict,
        signal,
        prompter: Prompter,
    ) -> str:
        # Parse the entire batch before presenting anything or recording a
        # pending question. A bad later question must not partially ask it.
        questions = self._questions(args)
        answers = []
        for item, question in zip(args["questions"], questions):
            from src.permission.runtime.execution import policy_for, ExecutionBlocked
            policy = policy_for(prompter)
            key = hashlib.sha256(json.dumps([policy.stamp() if policy else None, item],
                                           sort_keys=True, default=str).encode()).hexdigest()
            if policy is not None and key in policy.input_questions:
                choice = policy.input_questions[key]
                if choice is None:
                    raise ExecutionBlocked("pending: equivalent input question pending/cancelled; operator retry required")
            else:
                if policy is not None:
                    if len(policy.input_questions) >= 128:
                        raise ExecutionBlocked("blocked: input-question-capacity; operator retry required")
                    policy.input_questions[key] = None
                choice = await self.prompter.ask(question, signal)
                if policy is not None:
                    policy.input_questions[key] = choice

            answers.append(
                {
                    "question": question.question,
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
