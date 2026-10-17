from __future__ import annotations

from typing import Callable, Awaitable
from src.skills.transactions import skill_changes

from rich.cells import cell_len
from rich.text import Text

from src.ui.commands.menu_window import compute_menu_window

SKILLS_MODAL_VISIBLE_CAP = 8


PersistDisabledSkills = Callable[[list[str]], Awaitable[None]]


class SkillsModal:

    def __init__(
        self,
        agent,
        on_close: Callable[[], None],
        persist_disabled_skills: PersistDisabledSkills | None = None,
        on_loaded: Callable[[str], None] | None = None,
        width: int = 80,
    ):
        self.agent = agent
        self.on_close = on_close
        self.persist_disabled_skills = persist_disabled_skills
        self.on_loaded = on_loaded
        self.width = width
        self.closed = False

        self.idx = 0
        self.busy_name: str | None = None
        self.error: str | None = None
        self.item_lines: dict[int, int] = {}

    def skills(self):
        return self.agent.skills.list()


    def current_skill(self):
        skills = self.skills()

        if not skills:
            return None

        safe_idx = min(
            self.idx,
            len(skills) - 1,
        )

        return skills[safe_idx]

    async def load(self) -> None:
        current = self.current_skill()
        if current is None or self.busy_name or self.closed:
            return

        self.busy_name = current.name
        self.error = None
        try:
            async with skill_changes(self.agent):
                # Reopening the picker before the next prompt must not inject the
                # same playbook again. Keep disabled/in-flight checks on the Agent.
                already_pending = (
                    current.name in getattr(self.agent, "pending_skills", set())
                    and not self.agent.skills.is_disabled(current.name)
                    and not getattr(self.agent, "running", False)
                )
                name = current.name if already_pending else await self.agent.inject_skill(current.name)
        except Exception as err:
            self.error = str(err)
        else:
            if self.closed:
                return
            self.closed = True
            if self.on_loaded:
                self.on_loaded(name)
            self.on_close()
        finally:
            self.busy_name = None

    async def toggle(self):

        current = self.current_skill()

        if not current:
            return

        if self.busy_name or self.closed:
            return


        target_enabled = (
            self.agent.skills
            .is_disabled(current.name)
        )


        self.busy_name = current.name
        self.error = None


        try:
            async with skill_changes(self.agent):

                changed = await self.agent.set_skill_enabled(
                    current.name,
                    target_enabled,
                )


                if (
                    changed
                    and self.persist_disabled_skills
                ):
                    await self.persist_disabled_skills(
                        self.agent.skills.disabled_names()
                    )


        except Exception as err:

            self.error = str(err)


        finally:

            self.busy_name = None



    async def toggle_all(
        self,
        enabled: bool,
    ):

        if self.busy_name or self.closed:
            return


        self.busy_name = "*"
        self.error = None


        try:
            async with skill_changes(self.agent):

                for skill in self.skills():

                    disabled = (
                        self.agent.skills
                        .is_disabled(skill.name)
                    )


                    if disabled == (not enabled):
                        continue


                    await self.agent.set_skill_enabled(
                        skill.name,
                        enabled,
                    )


                if self.persist_disabled_skills:

                    await self.persist_disabled_skills(
                        self.agent.skills.disabled_names()
                    )


        except Exception as err:

            self.error = str(err)


        finally:

            self.busy_name = None


    def handle_key(
        self,
        key: str,
    ):

        if key in ("escape", "esc", "q"):
            if not self.closed:
                self.closed = True
                self.on_close()
            return
        if self.busy_name or self.closed:
            return
        skills = self.skills()
        total = len(skills)

        if total == 0:
            return


        if key in ("up", "arrowup", "shift+tab"):

            self.idx = (
                self.idx - 1
            ) % total

            return


        if key in ("down", "arrowdown", "tab"):

            self.idx = (
                self.idx + 1
            ) % total

            return


        if key == "enter":
            return self.load()

        if key == "space":

            return self.toggle()


        if key == "a":

            return self.toggle_all(True)


        if key == "d":

            return self.toggle_all(False)


        if key.isdigit():

            n = int(key) - 1

            if n < total:
                self.idx = n

    def render(self) -> list[str]:

        skills = self.skills()
        self.item_lines = {}


        if not skills:

            return [
                "[skills]",
                "No skills are loaded.",
                "",
                "Esc · q to close",
            ]


        if self.idx >= len(skills):

            self.idx = len(skills) - 1


        enabled_count = sum(
            not self.agent.skills.is_disabled(s.name)
            for s in skills
        )


        lines: list[str] = []


        lines.append(
            f"{enabled_count}/{len(skills)} enabled"
        )

        lines.append(
            "Select a skill to use or toggle"
        )

        lines.append("")

        window = compute_menu_window(
            len(skills),
            self.idx,
            cap=SKILLS_MODAL_VISIBLE_CAP,
        )

        if window.hidden_above > 0:
            lines.append(f"  ↑ {window.hidden_above} more")

        for i in range(window.start, window.end):
            skill = skills[i]
            selected = i == self.idx

            disabled = (
                self.agent.skills
                .is_disabled(skill.name)
            )


            busy = (
                self.busy_name == skill.name
                or self.busy_name == "*"
            )


            if busy:
                state = "[…] "
            elif disabled:
                state = "[off]"
            else:
                state = "[on] "


            cursor = (
                "› "
                if selected
                else "  "
            )


            self.item_lines[len(lines)] = i
            label = f"{cursor}{state} {skill.name}"
            # Description metadata may contain paragraphs (up to 1024 chars).
            # Only presentation is shortened; the registry/body stay intact.
            summary_width = min(64, self.width - cell_len(label) - 3)
            if summary_width > 3:
                summary = truncate(" ".join(skill.description.split()), summary_width)
                label += f" — {summary}"
            lines.append(truncate(label, self.width))

        if window.hidden_below > 0:
            lines.append(f"  ↓ {window.hidden_below} more")

        if self.error:

            lines.extend([
                "",
                f"error: {self.error}",
            ])


        lines.extend([
            "",
            "↑↓/Tab select · Space toggle",
            "Enter use · a enable all · d disable all",
            "Esc/q close",
        ])


        return lines

def truncate(
    text: str,
    n: int,
) -> str:

    value = Text(text)
    value.truncate(max(0, n), overflow="ellipsis")
    return value.plain
