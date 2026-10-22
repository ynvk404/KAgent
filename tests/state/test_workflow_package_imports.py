"""Workflow package boundaries, public identities and deferred runtime imports."""

import importlib
from pathlib import Path
import subprocess
import sys

import pytest


MODULES = (
    "src.workflow.discovery.inventory",
    "src.workflow.discovery.attribution",
    "src.workflow.discovery.scanner",
    "src.workflow.discovery.input_view",
    "src.workflow.evidence.artifacts",
    "src.workflow.evidence.errors",
    "src.workflow.evidence.publication",
    "src.workflow.evidence.recovery",
    "src.workflow.evidence.source",
    "src.workflow.evidence.review",
    "src.workflow.validation.context",
    "src.workflow.validation.route",
    "src.workflow.validation.probe",
    "src.workflow.planning.goals",
)


@pytest.mark.parametrize("first", (*MODULES, "src.workflow.state", "src.workflow.assessment",
                                  "src.session.store", "src.tools.workflow.workflow_tool",
                                  "src.permission.runtime.generic_validation", "src.agent.agent",
                                  "src.cli.main"))
def test_fresh_import_order_preserves_runtime_boundaries(first):
    code = """
import importlib
import sys

for name in sys.argv[1:]:
    importlib.import_module(name)
assert 'mcp' not in sys.modules
assert 'src.tools.mcp.integration' not in sys.modules
assert 'src.llm.runtime.validation_budget' not in sys.modules
"""
    subprocess.run(
        [sys.executable, "-B", "-c", code, first, *MODULES],
        cwd=Path(__file__).resolve().parents[2],
        check=True, capture_output=True, text=True, timeout=30,
    )


def test_public_exports_keep_the_canonical_objects():
    import src.workflow as workflow
    from src.workflow import state
    from src.workflow.planning import goals

    expected = {
        "Candidate", "CandidateStatus", "ValidationOutcome", "ValidationResult",
        "WorkflowState", "candidate_fingerprint", "validation_result_fingerprint",
        "GoalStatus", "RequestedGoal", "extract_requested_classes",
    }
    assert set(workflow.__all__) == expected
    for name in expected:
        module = goals if name in {"GoalStatus", "RequestedGoal", "extract_requested_classes"} else state
        assert getattr(workflow, name) is getattr(module, name)
    assert state.RequestedGoal is goals.RequestedGoal
    assert state.EvidenceArtifact is importlib.import_module("src.workflow.evidence.artifacts").EvidenceArtifact
    assert state.EndpointRecord is importlib.import_module("src.workflow.discovery.inventory").EndpointRecord
