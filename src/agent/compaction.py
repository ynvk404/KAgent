"""Data transforms used by Agent session compaction."""

import re
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Optional

from src.llm.core.types import Message
from src.session.store import SessionMemory
from src.workflow.state import WorkflowState


@dataclass
class SessionMemoryParsed:
    objectives: list[str] = field(default_factory=list)
    plan: list[str] = field(default_factory=list)
    completed: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    tested: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    credentials: list[str] = field(default_factory=list)
    todos: list[str] = field(default_factory=list)


def recent_useful_turn(
    messages: list[Message],
    *,
    compact_message: Callable[[Message], Message],
    recent_message_char_limit: int,
) -> list[Message]:
    """Keep the latest raw user request and final answer, not bulky tool payloads."""
    user_index = next(
        (index for index in range(len(messages) - 1, -1, -1) if messages[index].role == "user"),
        None,
    )
    if user_index is None:
        return []

    recent = [compact_message(messages[user_index])]
    final_answer = next(
        (
            message
            for message in reversed(messages[user_index + 1 :])
            if message.role == "assistant" and message.content and not message.tool_calls
        ),
        None,
    )
    if final_answer is not None:
        # A clipped assistant answer cannot safely replay its original
        # provider-private continuation state. The summary already carries
        # the answer; omit this history step rather than send altered content
        # without the state required by DeepSeek or Gemini.
        has_provider_state = (
            final_answer.reasoning_content is not None
            or final_answer.gemini_parts is not None
        )
        if not (has_provider_state and len(final_answer.content) > recent_message_char_limit):
            recent.append(compact_message(final_answer))
    return recent


def compact_recent_message(
    message: Message,
    recent_message_char_limit: int,
    *,
    replace_message: Callable[..., Any] = replace,
) -> Message:
    content = message.content or ""
    if len(content) <= recent_message_char_limit:
        return replace_message(message)
    marker_template = "\n[... {omitted} characters summarized during compaction ...]\n"
    retained = recent_message_char_limit
    for _ in range(10):
        marker = marker_template.format(omitted=len(content) - retained)
        next_retained = max(0, recent_message_char_limit - len(marker))
        if next_retained >= retained:
            break
        retained = next_retained
    marker = marker_template.format(omitted=len(content) - retained)
    head = retained // 2
    tail = retained - head
    bounded = (
        content[:head]
        + marker
        + content[-tail:]
    )
    return replace_message(
        message, content=bounded, reasoning_content=None, tool_calls=None,
        gemini_parts=None, provider_state_provider=None, provider_state_model=None,
    )


def remove_workflow_duplicates(
    memory: SessionMemory,
    workflow: WorkflowState,
    *,
    replace_memory: Callable[..., Any] = replace,
) -> SessionMemory:
    """Do not mirror Candidate-linked facts into prose session memory."""
    candidate_ids = tuple(workflow.candidates)
    if not candidate_ids:
        return memory

    def keep(items: list[str]) -> list[str]:
        return [item for item in items if not any(value in item for value in candidate_ids)]

    return replace_memory(
        memory,
        objectives=keep(memory.objectives),
        plan=keep(memory.plan),
        completed=keep(memory.completed),
        findings=keep(memory.findings),
        tested=keep(memory.tested),
        files=keep(memory.files),
        commands=keep(memory.commands),
        credentials=keep(memory.credentials),
        todos=keep(memory.todos),
    )


def format_history_for_compaction(
    messages: list[Message],
    *,
    redact_payload: Callable[[str], str],
) -> str:
    lines: list[str] = []

    for message in messages:
        if not message.content and (not message.tool_calls or len(message.tool_calls) == 0):
            continue

        if message.name:
            lines.append(f"\n[{message.role}:{message.name}]")
        else:
            lines.append(f"\n[{message.role}]")

        if message.content:
            lines.append(redact_payload(message.content))

        if message.tool_calls:
            for tool_call in message.tool_calls:
                lines.append(
                    f"tool_call {tool_call.id} "
                    f"{tool_call.function.name} "
                    f"{redact_payload(tool_call.function.arguments)}"
                )

    return "\n".join(lines)


def bounded_history_for_compaction(
    messages: list[Message],
    *,
    input_char_limit: int,
    format_history: Callable[[list[Message]], str],
) -> str:
    full = format_history(messages)

    if len(full) <= input_char_limit:
        return full

    tail = full[-input_char_limit:]

    boundary = tail.find("\n[")

    if boundary > 0:
        trimmed = tail[boundary:]
    else:
        trimmed = tail

    return "\n".join(
        [
            (
                "[system]\n"
                "Older conversation text was omitted because "
                f"the compaction input exceeded "
                f"{input_char_limit} characters. "
                "Preserve continuity from persistent memory "
                "and the newest visible context below."
            ),
            trimmed,
        ]
    )


def merge_list(
    prev: Optional[list[str]],
    next_items: list[str],
    cap: int = 24,
) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []

    for item in (prev or []) + next_items:

        clean = " ".join(item.split()).strip()

        if not clean:
            continue

        key = clean.lower()

        if key in seen:
            continue

        seen.add(key)

        if len(clean) > 240:
            clean = clean[:239] + "…"

        out.append(clean)

    if cap is not None:
        return out[-cap:]

    return out


def parse_compaction_summary(
    summary: str,
    *,
    split_sections: Callable[[str], dict[str, list[str]]],
    get_section_items: Callable[[dict[str, list[str]], list[str]], list[str]],
    parsed_memory_type: Callable[..., SessionMemoryParsed] = SessionMemoryParsed,
) -> SessionMemoryParsed:
    sections = split_sections(summary)

    files_and_commands = get_section_items(
        sections,
        [
            "files and commands",
        ],
    )

    return parsed_memory_type(
        objectives=get_section_items(
            sections,
            [
                "current objective",
                "target and scope",
            ],
        ),

        plan=get_section_items(
            sections,
            [
                "plan",
            ],
        ),

        completed=get_section_items(
            sections,
            [
                "completed tasks",
            ],
        ),

        findings=get_section_items(
            sections,
            [
                "findings and evidence",
            ],
        ),

        tested=get_section_items(
            sections,
            [
                "tested surface",
                "decisions and assumptions",
            ],
        ),

        files=[
            item
            for item in files_and_commands
            if re.search(
                r"(?:^|[\s/])[\w.-]+\.\w+|/|\\",
                item,
            )
        ],

        commands=[
            item
            for item in files_and_commands
            if re.search(
                r"`[^`]+`|\b(?:curl|npm|git|rg|python|node|ffuf|nuclei|sqlmap|httpx)\b",
                item,
            )
        ],

        credentials=get_section_items(
            sections,
            [
                "credentials and placeholders",
            ],
        ),

        todos=get_section_items(
            sections,
            [
                "open todos",
                "next best actions",
            ],
        ),
    )


def section_items(
    sections: dict[str, list[str]],
    names: list[str],
    *,
    heading_normalizer: Callable[[str], str],
) -> list[str]:
    out: list[str] = []

    for name in map(heading_normalizer, names):

        for line in sections.get(name, []):

            item = re.sub(
                r"^\s*(?:[-*]|\d+[.)])\s+",
                "",
                line,
            ).strip()

            if not item:
                continue

            if re.match(
                r"^none\b|^n/a$",
                item,
                re.IGNORECASE,
            ):
                continue

            out.append(item)

    return out


def normalize_heading(s: str) -> str:
    return re.sub(
        r"[:#]",
        "",
        s.lower(),
    ).strip()


def split_markdown_sections(
    text: str,
    *,
    heading_normalizer: Callable[[str], str],
) -> dict[str, list[str]]:
    sections = {}
    current = "summary"

    for raw in text.replace("\r\n", "\n").split("\n"):

        heading = re.match(
            r"^#{1,3}\s+(.+?)\s*$",
            raw
        )

        if heading and heading.group(1):
            current = heading_normalizer(
                heading.group(1)
            )

            if current not in sections:
                sections[current] = []

            continue

        if current not in sections:
            sections[current] = []

        sections[current].append(raw)

    return sections
