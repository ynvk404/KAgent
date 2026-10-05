"""Validate runtime dictionary and typed tool specs before provider encoding."""
from __future__ import annotations

from typing import Any

from .types import ToolFunction, ToolSpec


def normalize_tool_spec(value: Any) -> ToolSpec:
    if isinstance(value, ToolSpec):
        kind, function = value.type, value.function
    elif isinstance(value, dict):
        kind, function = value.get("type"), value.get("function")
    else:
        raise ValueError("invalid tool specification: expected ToolSpec or dictionary")
    if kind != "function":
        raise ValueError("invalid tool specification: type must be function")
    if isinstance(function, ToolFunction):
        name, description, parameters = function.name, function.description, function.parameters
    elif isinstance(function, dict):
        name = function.get("name")
        description = function.get("description", "")
        parameters = function.get("parameters")
    else:
        raise ValueError("invalid tool specification: function must be an object")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("invalid tool specification: function name must be nonempty")
    if not isinstance(description, str) or not isinstance(parameters, dict):
        raise ValueError("invalid tool specification: description must be text and parameters an object")
    return ToolSpec(ToolFunction(name, description, parameters))
