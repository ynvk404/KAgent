"""Optional execution metadata carried alongside existing tool text."""

from __future__ import annotations

from typing import Literal, TYPE_CHECKING, TypeVar
from dataclasses import dataclass

from src.tools.common.runtime_metadata import RuntimeMetadata

if TYPE_CHECKING:
    from src.tools.discovery.content import NativeDiscoveryResult

ToolStatus = Literal["success", "observation", "error", "cancelled", "pending"]
ErrorKind = Literal[
    "permission_denied", "scope_denied", "timeout", "network", "tls",
    "invalid_args", "cancelled", "tool_exception",
    "permission_pending", "permission_timeout", "permission_stale", "policy_block",
    "workflow_state", "reference_unavailable", "input_unavailable",
]


PresentationImpact = Literal["operation", "intervention", "session", "persistence"]
_Error = TypeVar("_Error", bound=Exception)


def annotate_error(error: _Error, impact: PresentationImpact) -> _Error:
    """Transient native UI annotation; preserve exception identity and semantics."""
    setattr(error, "presentation_impact", impact)
    return error


@dataclass(frozen=True, slots=True)
class RecoveryReceipt:
    """Native transient presentation evidence; never model input or session state."""
    resource: str
    completed: bool = False
    retry_safe: bool = False


class ToolOutput(str):
    """A string result with metadata; existing consumers still see text."""

    recovery_receipt: RecoveryReceipt | None
    presentation_impact: PresentationImpact | None
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
        presentation_impact: PresentationImpact | None = None,
    ) -> "ToolOutput":
        value = super().__new__(cls, text)
        value.presentation_impact = presentation_impact
        value.recovery_receipt = None
        value.runtime_metadata = runtime_metadata
        value.status = status
        value.error_kind = error_kind
        value.http_status = http_status
        value.truncated = truncated
        value.http_sources = ()
        value.http_session = None
        value.http_stamp = None
        value.http_body_ranges = ()
        value.native_discovery = None
        return value
