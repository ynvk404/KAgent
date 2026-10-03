"""Import contracts for tool domains and deferred optional integrations."""

import importlib
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("module_name", [
    "src.tools.common.registry",
    "src.tools.common.types",
    "src.tools.common.capabilities",
    "src.tools.common.outcome",
    "src.tools.common.aliases",
    "src.tools.common.approval_display",
    "src.tools.common.tool_display",
    "src.tools.common.ask",
    "src.tools.common.permission_status",
    "src.tools.common.browser_capture",
    "src.tools.http.http_tool",
    "src.tools.http.context",
    "src.tools.http.request_builder",
    "src.tools.http.private_host",
    "src.tools.http.web",
    "src.tools.discovery.content",
    "src.tools.discovery.service",
    "src.tools.discovery.common",
    "src.tools.execution.shell",
    "src.tools.execution.file",
    "src.tools.execution.search",
    "src.tools.execution.sensitive",
    "src.tools.execution.plugin",
    "src.tools.workflow.workflow_tool",
    "src.tools.workflow.finding",
    "src.tools.workflow.coverage",
    "src.tools.skills.payloads",
    "src.tools.skills.skill_file",
    "src.tools.skills.paths",
    "src.tools.mcp.integration",
    "src.tools.mcp.session_servers",
])
def test_canonical_tool_module_imports(module_name):
    assert importlib.import_module(module_name).__name__ == module_name


@pytest.mark.parametrize("package,implementation,symbol", [
    ("src.tools.http", "src.tools.http.http_tool", "HTTPTool"),
    ("src.tools.workflow", "src.tools.workflow.workflow_tool", "WorkflowTool"),
])
def test_public_tool_reexports_keep_canonical_class_identity(package, implementation, symbol):
    public = getattr(importlib.import_module(package), symbol)
    canonical = getattr(importlib.import_module(implementation), symbol)
    assert public is canonical
    assert public.__module__ == implementation


def test_tool_packages_and_runtime_leave_mcp_sdk_deferred():
    # Use a fresh interpreter: other tests legitimately import the MCP adapter.
    code = """
import importlib
import sys

for name in (
    'src.tools', 'src.tools.common', 'src.tools.mcp', 'src.tools.mcp.session_servers',
    'src.cli.main', 'src.cli.runtime',
):
    importlib.import_module(name)
    assert 'mcp' not in sys.modules, name
    assert 'src.tools.mcp.integration' not in sys.modules, name
    assert 'src.tools.mcp_integration' not in sys.modules, name
"""
    subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[2],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
