"""Optional execution metadata carried alongside existing tool text."""

from __future__ import annotations

from typing import Literal, TYPE_CHECKING

from src.tools.common.runtime_metadata import RuntimeMetadata

if TYPE_CHECKING:
    from src.tools.execution.scanner_runner import ScannerResult
    from src.tools.discovery.content import NativeDiscoveryResult

ToolStatus = Literal["success", "observation", "error", "cancelled", "pending"]
ErrorKind = Literal[
    "permission_denied", "scope_denied", "timeout", "network", "tls",
    "invalid_args", "cancelled", "tool_exception",
    "permission_pending", "permission_timeout", "permission_stale", "policy_block",
    "workflow_state", "reference_unavailable", "input_unavailable",
]


class ToolOutput(str):
    """A string result with metadata; existing consumers still see text."""

    runtime_metadata: RuntimeMetadata | None
    status: ToolStatus
    error_kind: ErrorKind | None
    http_status: int | None
    truncated: bool
    # Native runtime metadata, never deserialized from a tool/MCP payload.
    http_sources: tuple[tuple[str, str], ...]
    http_session: str | None
    http_stamp: tuple | None
    http_body_ranges: tuple[tuple[int, int], ...]
    scanner_result: ScannerResult | None
    native_discovery: NativeDiscoveryResult | None

    def __new__(
        cls,
        text: str,
        *,
        status: ToolStatus = "success",
        error_kind: ErrorKind | None = None,
        http_status: int | None = None,
        truncated: bool = False,
        runtime_metadata: RuntimeMetadata | None = None,
    ) -> "ToolOutput":
        value = super().__new__(cls, text)
        value.runtime_metadata = runtime_metadata
        value.status = status
        value.error_kind = error_kind
        value.http_status = http_status
        value.truncated = truncated
        value.http_sources = ()
        value.http_session = None
        value.http_stamp = None
        value.http_body_ranges = ()
        value.scanner_result = None
        value.native_discovery = None
        return value
