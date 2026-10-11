"""Optional execution metadata carried alongside existing tool text."""

from __future__ import annotations

from typing import Literal

ToolStatus = Literal["success", "observation", "error", "cancelled", "pending"]
ErrorKind = Literal[
    "permission_denied", "scope_denied", "timeout", "network", "tls",
    "invalid_args", "cancelled", "tool_exception",
    "permission_pending", "permission_timeout", "permission_stale", "policy_block",
    "workflow_state", "reference_unavailable",
]


class ToolOutput(str):
    """A string result with metadata; existing consumers still see text."""

    status: ToolStatus
    error_kind: ErrorKind | None
    http_status: int | None
    truncated: bool

    def __new__(
        cls,
        text: str,
        *,
        status: ToolStatus = "success",
        error_kind: ErrorKind | None = None,
        http_status: int | None = None,
        truncated: bool = False,
    ) -> "ToolOutput":
        value = super().__new__(cls, text)
        value.status = status
        value.error_kind = error_kind
        value.http_status = http_status
        value.truncated = truncated
        return value
