from __future__ import annotations

from typing import Any

from src.permission.permission import AlwaysAllow
from src.workflow.state import PHASE_COVERAGE_DIMENSIONS, WorkflowPhase, WorkflowState


def record_completed_phase(
    state: WorkflowState,
    phase: WorkflowPhase,
    *,
    objective_id: str,
    target_origin: str,
    artifact_ref: str,
    no_inputs_discovered: bool = False,
) -> bool:
    """Seed explicit non-production coverage for synthetic workflow fixtures."""
    for dimension in PHASE_COVERAGE_DIMENSIONS.get(phase, ()):
        state.record_phase_coverage(
            phase,
            dimension,
            "not_applicable",
            objective_id=objective_id,
            target_origin=target_origin,
            reason="test fixture does not exercise this discovery dimension",
        )
    return state.record_phase_completion(
        phase,
        objective_id=objective_id,
        target_origin=target_origin,
        artifact_ref=artifact_ref,
        no_inputs_discovered=no_inputs_discovered,
    )


async def record_phase_coverage_for_test(tool: Any, phase: str) -> None:
    for dimension in PHASE_COVERAGE_DIMENSIONS.get(phase, ()):
        await tool.run(
            {
                "action": "record_phase_coverage",
                "phase": phase,
                "coverage_dimension": dimension,
                "coverage_status": "not_applicable",
                "coverage_reason": "test fixture does not exercise this discovery dimension",
            },
            None,
            AlwaysAllow(),
        )
