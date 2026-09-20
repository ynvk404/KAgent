from pathlib import Path

from src.browser.store import CaptureStore
from src.coverage.store import CoverageStore
from src.findings.store import Store as FindingsStore
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.ask import AskUserTool
from src.tools.browser_capture import register_browser_capture_tools
from src.tools.coverage import CoverageTool
from src.tools.file import (
    FileEditTool,
    FileEditToolAlias,
    FileReadTool,
    FileReadToolAlias,
    FileWriteTool,
    FileWriteToolAlias,
)
from src.tools.finding import ConfirmFindingTool
from src.tools.http import HTTPTool
from src.tools.payloads import ReadPayloadsTool
from src.tools.registry import Registry
from src.tools.search import GlobTool, GrepTool
from src.tools.shell import BashTool, ShellTool
from src.tools.skill_file import ReadSkillFileTool
from src.tools.web import WebFetchTool, WebSearchTool
from src.tools.workflow import WorkflowTool
from src.workflow.state import WorkflowState


SKILLS_ROOT = Path(__file__).resolve().parents[2] / "skills"


def test_default_tool_schema_budget_is_measured_and_bounded(tmp_path):
    skills = SkillRegistry()
    skills.load_dir(SKILLS_ROOT)
    target = Target()
    workflow = WorkflowState()
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
        HTTPTool(target),
        WebFetchTool(),
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

    assert metrics["tool_count"] == 28
    # Includes the ask_user interaction contract for blocking questions,
    # free-text versus finite choices, and permission-prompt boundaries while
    # retaining roughly 6% regression headroom over the measured default set.
    assert metrics["characters"] < 20_000
    assert metrics["approx_tokens"] < 5_000
    assert metrics["tools"][0]["name"] in {
        "ask_user",
        "confirm_finding",
        "workflow",
        "coverage",
    }
