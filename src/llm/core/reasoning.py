"""Provider-neutral reasoning intent and capability resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ReasoningLevel(str, Enum):
    OFF = "off"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ReasoningPurpose(str, Enum):
    AGENT_TURN = "agent_turn"
    COMPACTION = "compaction"
    FINAL_SYNTHESIS = "final_synthesis"


@dataclass(frozen=True)
class ReasoningCapabilities:
    supported: frozenset[ReasoningLevel]
    aliases: dict[ReasoningLevel, ReasoningLevel] = field(default_factory=dict)
    fallbacks: dict[ReasoningLevel, ReasoningLevel] = field(default_factory=dict)


@dataclass(frozen=True)
class ReasoningResolution:
    requested: ReasoningLevel
    effective: ReasoningLevel | None
    relation: str  # exact, alias, fallback, or legacy


def requested_level(purpose: ReasoningPurpose, thinking_enabled: bool) -> ReasoningLevel:
    if purpose is ReasoningPurpose.COMPACTION or not thinking_enabled:
        return ReasoningLevel.OFF
    return ReasoningLevel.LOW


def resolve_level(
    requested: ReasoningLevel,
    capabilities: ReasoningCapabilities | None,
) -> ReasoningResolution:
    if capabilities is None:
        return ReasoningResolution(requested, None, "legacy")
    if requested in capabilities.supported:
        return ReasoningResolution(requested, requested, "exact")
    alias = capabilities.aliases.get(requested)
    if alias in capabilities.supported:
        return ReasoningResolution(requested, alias, "alias")
    fallback = capabilities.fallbacks.get(requested)
    if fallback in capabilities.supported:
        return ReasoningResolution(requested, fallback, "fallback")
    return ReasoningResolution(requested, None, "legacy")
