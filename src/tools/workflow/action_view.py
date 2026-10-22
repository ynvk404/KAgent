"""Transient objective projection, never an execution permission gate."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from .workflow_tool import ACTIONS, ACTION_INPUTS, ACTION_REQUIRED


WHOLE_TARGET_ACTIONS = frozenset({
    "select_source", "get_source", "get_endpoint", "set_source_disposition",
    "record_input", "set_input_disposition", "link_input_candidate",
    "record_phase_coverage", "review_no_candidate",
})


@dataclass(frozen=True)
class ActionView:
    available: tuple[str, ...]
    excluded: tuple[str, ...]

    @classmethod
    def for_objective(cls, mode: str | None) -> ActionView:
        excluded = WHOLE_TARGET_ACTIONS if mode in {"direct", "candidate_validation"} else frozenset()
        return cls(tuple(action for action in ACTIONS if action not in excluded),
                   tuple(action for action in ACTIONS if action in excluded))

    def project_tools(self, tools: list[Any] | None) -> list[Any] | None:
        projected = deepcopy(tools)
        for spec in projected or ():
            function = spec["function"] if isinstance(spec, dict) else spec.function
            name = function["name"] if isinstance(function, dict) else function.name
            if name != "workflow":
                continue
            schema = function["parameters"] if isinstance(function, dict) else function.parameters
            properties = schema["properties"]
            properties["action"]["enum"] = list(self.available)
            properties["action"]["description"] = (
                "Action fields (* required); omit others.\n" + "\n".join(
                    action + "(" + ",".join(
                        key + ("*" if key in ACTION_REQUIRED.get(action, ()) else "")
                        for key in ACTION_INPUTS[action] if key in properties) + ")"
                    for action in self.available))
        return projected
