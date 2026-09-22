from __future__ import annotations

from typing import Callable, Awaitable

from src.ui.commands.menu_window import compute_menu_window

SKILLS_MODAL_VISIBLE_CAP = 8


PersistDisabledSkills = Callable[[list[str]], Awaitable[None]]


class SkillsModal:

    def __init__(
        self,
        agent,
        on_close: Callable[[], None],
        persist_disabled_skills: PersistDisabledSkills | None = None,
    ):
        self.agent = agent
        self.on_close = on_close
        self.persist_disabled_skills = persist_disabled_skills

        self.idx = 0
        self.busy_name: str | None = None
        self.error: str | None = None

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

    async def toggle(self):

        current = self.current_skill()

        if not current:
            return

        if self.busy_name:
            return


        target_enabled = (
            self.agent.skills
            .is_disabled(current.name)
        )


        self.busy_name = current.name
        self.error = None


        try:

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

        if self.busy_name:
            return


        self.busy_name = "*"
        self.error = None


        try:

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

        if self.busy_name:
            return


        skills = self.skills()
        total = len(skills)


        if key in ("escape", "esc", "q"):
            self.on_close()
            return


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


        if key in ("enter", "space"):

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
            "Toggle skills available to the agent"
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


            lines.append(
                f"{cursor}"
                f"{state} "
                f"{skill.name}"
                f" — {truncate(skill.description, 60)}"
            )

        if window.hidden_below > 0:
            lines.append(f"  ↓ {window.hidden_below} more")

        if self.error:

            lines.extend([
                "",
                f"error: {self.error}",
            ])


        lines.extend([
            "",
            (
                "↑↓/Tab select · Space/Enter toggle · "
                "a enable all · d disable all · "
                "Esc/q close"
            )
        ])


        return lines

def truncate(
    text: str,
    n: int,
) -> str:

    if len(text) <= n:
        return text

    return text[:n - 1] + "…"
