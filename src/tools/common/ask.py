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
    input_ids: tuple[str, ...] = ()
    dependency_kind: str | None = None
    dependency_basis: str | None = None


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
                            "input_ids": {
                                "type": "array", "maxItems": 32, "uniqueItems": True,
                                "items": {"type": "string"},
                                "description": "Exact current blocked Workflow input IDs for this dependency question. Rewording does not ask it again; answers do not commit exclusions or grant permission.",
                            },
                            'dependency_kind': {'type': 'string', 'enum': ['access', 'request_context', 'scope'],
                                'description': 'Required with input_ids. access asks about an evidenced access prerequisite; request_context asks for unknown request/schema information; scope asks for an independent assessment coverage decision. Never relabel an assumed authentication dependency as a scope decision.'},
                            'dependency_basis': {'type': 'string', 'minLength': 1, 'maxLength': 600,
                                'description': 'Required with input_ids. State the concrete observed/documented/operator-supplied basis and why operator involvement is needed. A field name, GET error or missing account alone does not establish an access prerequisite.'},
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

                if not item.get("input_ids"):
                    add_authorized_testing_option(qtext, header, options)

                question = Question(
                    question=qtext,
                    options=options,
                    header=header,
                )

            ids = item.get("input_ids", [])
            if (not isinstance(ids, list) or len(ids) > 32
                    or any(not isinstance(value, str) or not value or len(value) > 80 for value in ids)
                    or len(set(ids)) != len(ids)):
                raise ValueError("input_ids must be unique bounded Workflow input IDs")
            question.input_ids = tuple(sorted(ids))
            if ids:
                kind, basis = item.get('dependency_kind'), item.get('dependency_basis')
                if kind not in {'access', 'request_context', 'scope'} or not isinstance(basis, str) or not 1 <= len(basis.strip()) <= 600:
                    raise ValueError('input_ids require dependency_kind (access/request_context/scope) and a concrete dependency_basis; do not infer authentication from a field name or GET error')
                question.dependency_kind, question.dependency_basis = kind, basis.strip()
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
        from src.permission.runtime.execution import policy_for, ExecutionBlocked
        policy = policy_for(prompter)
        # Validate the whole batch before showing its first question. Dependency
        # identity binds an answer to existing inputs, never to an inferred scope.
        identities = []
        for item, question in zip(args["questions"], questions):
            identity: Any = item
            if question.input_ids:
                boundary = policy.generic_validation if policy else None
                state = boundary.state if boundary else None
                objective = state.objective if state else None
                rows = {row.id: row for row in state.objective_inputs()} if state else {}
                if (objective is None or objective.mode != "whole_target"
                        or any(iid not in rows or rows[iid].disposition != "blocked" for iid in question.input_ids)):
                    raise ValueError("input_ids require exact current blocked objective inputs")
                assert state is not None
                identity = [objective.id, objective.target_origin,
                            [(iid, rows[iid].disposition_reason) for iid in question.input_ids]]
                from src.workflow.discovery.input_view import input_provenance
                from src.ui.render.sanitize import sanitize_text
                from urllib.parse import urlsplit
                affected = []
                for iid in question.input_ids:
                    row = rows[iid]
                    affected.append(sanitize_text(f'{row.method or "unknown method"} '
                        f'{urlsplit(row.endpoint or "").path or "/"} · input {row.parameter or "unknown"} '
                        f'({row.location or "unknown location"})'))
                basis = list(dict.fromkeys(sanitize_text(rows[iid].disposition_reason or 'Dependency unspecified.')
                                            for iid in question.input_ids))
                uncertainty = any(input_provenance(state, rows[iid])['kind'] == 'unverified'
                                  for iid in question.input_ids)
                if question.dependency_kind == 'access' and uncertainty:
                    raise ValueError('input provenance is unverified; establish the actual request and access prerequisite before asking for credentials or exclusion. Use request_context for unknown method/body/schema, or scope only for an independent operator coverage decision.')
                question.question = ('Affected inputs: ' + '; '.join(affected) + '\n'
                    'Operator involvement: ' + sanitize_text(question.dependency_basis or '') + '\n'
                    'Agent-reported dependency: ' + '; '.join(basis) + '\n'
                    + ('Input provenance is unverified; authentication requirements are unknown. '
                       'Establish request context before assuming credentials are necessary.\n' if uncertainty else
                       'Source references do not verify authentication enforcement.\n')
                    + question.question + '\nExclude removes only the inputs listed above from this assessment; '
                    'they remain untested. Keeping them blocked preserves the unresolved work. '
                    'The answer does not grant execution permission.')
            identities.append(identity)
        answers = []
        for identity, question in zip(identities, questions):
            context = (policy.session_id or policy.engagement.http_permissions.session_id
                       if policy and question.input_ids else policy.stamp() if policy else None)
            key = hashlib.sha256(json.dumps([context, identity],
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
                    policy.input_question_texts[key] = question.question
                choice = await self.prompter.ask(question, signal)
                if policy is not None:
                    policy.input_questions[key] = choice

            answers.append(
                {
                    "question": policy.input_question_texts.get(key, question.question) if policy else question.question,
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
