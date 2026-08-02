from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any, Awaitable, Callable

from src.agent.agent import Agent
from src.skills.template import render_skill_template
from src.ui.core.state import Append, SetSkillsPicker, TranscriptEntry


def handle_skills_command(
    agent: Agent,
    rest: list[str],
    dispatch: Callable[[Any], None],
    persist_disabled_skills: Callable[[list[str]], Awaitable[None]] | None,
    on_skill_created: Callable[[str], None] | None,
) -> None:
    all_skills = agent.skills.list()
    if not all_skills:
        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="system",
                    text="/skills: no skills are loaded",
                )
            )
        )
        return

    if not rest:
        dispatch(SetSkillsPicker(open=True))
        return

    if rest[0] == "new":
        name = (rest[1] if len(rest) > 1 else "").strip()
        if not re.fullmatch(r"[a-z0-9-]+", name):
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text="usage: /skills new <name>  (lowercase, letters/digits/hyphens)",
                    )
                )
            )
            return

        skills_root = Path.cwd() / ".pentestagent" / "skills"
        skill_dir = skills_root / name
        skill_file = skill_dir / "SKILL.md"
        if skill_file.exists():
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text=f"/skills new: a skill already exists at {skill_file}",
                    )
                )
            )
            return

        try:
            skill_dir.mkdir(parents=True, exist_ok=True)
            skill_file.write_text(render_skill_template(name), encoding="utf-8")
            agent.skills.load_dir(skills_root)
            agent.rebuild_from_skills()
            on_skill_created(str(skills_root)) if on_skill_created else None
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=(
                            f'created skill "{name}" at {skill_file}\n'
                            f"edit it (hot-reloads on save), then invoke with /{name}."
                        ),
                    )
                )
            )
        except Exception as err:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text=f"/skills new: {err}",
                    )
                )
            )
        return

    if rest[0] in {"enable", "disable"}:
        verb = rest[0]
        name = " ".join(rest[1:]).strip()
    else:
        verb = "toggle"
        name = " ".join(rest).strip()

    if not name:
        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="error",
                    text="usage: /skills <name>  ·  /skills enable|disable <name>",
                )
            )
        )
        return

    if not agent.skills.has(name):
        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="error",
                    text=(
                        f'/skills: unknown skill "{name}". Run /skills to list available skills.'
                    ),
                )
            )
        )
        return

    target_enabled = (
        True
        if verb == "enable"
        else False
        if verb == "disable"
        else agent.skills.is_disabled(name)
    )

    async def _apply() -> None:
        try:
            changed = await agent.set_skill_enabled(name, target_enabled)
        except Exception as err:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text=f"/skills: {err}",
                    )
                )
            )
            return

        if not changed:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=(
                            f"/skills: {name} already "
                            f"{'enabled' if target_enabled else 'disabled'}"
                        ),
                    )
                )
            )
            return

        if persist_disabled_skills is not None:
            try:
                await persist_disabled_skills(agent.skills.disabled_names())
            except Exception as err:
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="error",
                            text=(
                                f"/skills: state changed but could not persist: {err}"
                            ),
                        )
                    )
                )
                return

        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="system",
                    text=f"/skills: {name} {'enabled' if target_enabled else 'disabled'}",
                )
            )
        )

    asyncio.create_task(_apply())
