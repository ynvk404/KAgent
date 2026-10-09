from pathlib import Path

from src.browser.store import CaptureStore
from src.coverage.store import CoverageStore
from src.findings.store import Store as FindingsStore
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.engagement.state import EngagementState
from src.tools.common.ask import AskUserTool
from src.tools.common.browser_capture import register_browser_capture_tools
from src.tools.workflow.coverage import CoverageTool
from src.tools.common.capabilities import CapabilityInventory
from src.tools.discovery.content import ContentDiscoveryTool
from src.tools.execution.file import (
    FileEditTool,
    FileEditToolAlias,
    FileReadTool,
    FileReadToolAlias,
    FileWriteTool,
    FileWriteToolAlias,
)
from src.tools.workflow.finding import ConfirmFindingTool
from src.tools.http.http_tool import HTTPTool
from src.tools.skills.payloads import ReadPayloadsTool
from src.tools.common.registry import Registry
from src.tools.execution.search import GlobTool, GrepTool
from src.tools.discovery.service import ServiceDiscoveryTool
from src.tools.execution.shell import BashTool, ShellTool
from src.tools.skills.skill_file import ReadSkillFileTool
from src.tools.http.web import WebFetchTool, WebSearchTool
from src.tools.workflow.workflow_tool import WorkflowTool
from src.workflow.state import WorkflowState


SKILLS_ROOT = Path(__file__).resolve().parents[2] / "skills"


def test_default_tool_schema_budget_is_measured_and_bounded(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(SKILLS_ROOT)
    target = Target()
    workflow = WorkflowState()
    engagement = EngagementState()
    capabilities = CapabilityInventory(which=lambda _: None)
    registry = Registry()
    core = [
        ShellTool(),
        BashTool(),
        FileReadTool(),
        FileReadToolAlias(),
        FileWriteTool(),
        FileWriteToolAlias(),
        FileEditTool(),
        FileEditToolAlias(),
        GlobTool(),
        GrepTool(),
        HTTPTool(target, engagement),
        ContentDiscoveryTool(target, engagement, capabilities, lambda: "minimal"),
        ServiceDiscoveryTool(target, engagement, capabilities, lambda: "minimal"),
        WebFetchTool(engagement),
        WebSearchTool(),
        AskUserTool(None),  # type: ignore[arg-type]
        ConfirmFindingTool(FindingsStore(str(tmp_path / "findings")), workflow=workflow),
        LoadSkillTool(skills),
        ReadPayloadsTool(skills),
        ReadSkillFileTool(skills),
        CoverageTool(CoverageStore(str(tmp_path / "coverage.json"))),
        WorkflowTool(workflow, target),
    ]
    for tool in core:
        registry.register(tool)
    register_browser_capture_tools(registry.register, CaptureStore(max_entries=10))

    metrics = registry.schema_metrics()

    assert metrics["tool_count"] == 30
    # Includes ask_user, semantic discovery, permission boundaries, and the
    # workflow assessment/evidence contract. The measured default set is
    # 25,858 characters (~6,464 tokens); these fixed caps retain roughly 8%
    # regression headroom. Token estimates use characters // 4.
    assert metrics["characters"] < 28_000
    assert metrics["approx_tokens"] < 7_000
    assert metrics["tools"][0]["name"] in {
        "ask_user",
        "confirm_finding",
        "workflow",
        "coverage",
    }
