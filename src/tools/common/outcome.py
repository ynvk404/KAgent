"""Optional execution metadata carried alongside existing tool text."""

from __future__ import annotations

from typing import Literal

ToolStatus = Literal["success", "observation", "error", "cancelled", "pending"]
ErrorKind = Literal[
    "permission_denied", "scope_denied", "timeout", "network", "tls",
    "invalid_args", "cancelled", "tool_exception",
    "permission_pending", "permission_timeout", "permission_stale", "policy_block",
    "workflow_state", "reference_unavailable", "input_unavailable",
]


class ToolOutput(str):
    """A string result with metadata; existing consumers still see text."""

    status: ToolStatus
    error_kind: ErrorKind | None
    http_status: int | None
    truncated: bool
    # Native runtime metadata, never deserialized from a tool/MCP payload.
    http_sources: tuple[tuple[str, str], ...]
    http_session: str | None
    http_stamp: tuple | None
    http_body_ranges: tuple[tuple[int, int], ...]

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
        value.http_sources = ()
        value.http_session = None
        value.http_stamp = None
        value.http_body_ranges = ()
        return value
