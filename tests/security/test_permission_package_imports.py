"""Import identity and filesystem bindings after permission domain moves."""

import importlib
from pathlib import Path
import subprocess
import sys

import pytest

from src.engagement.state import EngagementState
from src.permission.runtime.execution import (
    ExecutionBlocked,
    default_execution_policy,
    invocation_digest,
)
from src.target.target import Target
from src.tools.http.http_tool import HTTPTool


PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("entrypoint", [
    "src.permission.permission",
    "src.permission.runtime.execution",
    "src.permission.runtime.verifiers",
    "src.permission.network.grants",
    "src.permission.network.transport",
    "src.permission.worker.worker",
    "src.permission.worker.broker",
    "src.engagement.state",
    "src.tools.common.registry",
    "src.cli.runtime",
])
def test_fresh_imports_share_permission_state_without_cycles(entrypoint):
    script = """
import importlib
import sys

importlib.import_module(sys.argv[1])
from src.permission.runtime import execution, invocations, observations, verifiers
from src.permission.network import grants, transport
from src.permission.worker import worker, broker
from src.engagement.state import EngagementState
from src.permission.permission import AlwaysDeny, YoloPrompter
from src.tools.common import registry
from src.tools.http import http_tool
from src.browser import scoped_store
from pathlib import Path

assert http_tool.policy_for is registry.policy_for is execution.policy_for
assert registry.permission_invocation is invocations.permission_invocation
assert broker.current_policy is transport.current_policy is execution.current_policy
assert scoped_store.ExecutionPolicy is execution.ExecutionPolicy
assert verifiers.VerifiedResult is observations.VerifiedResult
assert 'mcp' not in sys.modules
assert 'src.tools.mcp.integration' not in sys.modules

state = EngagementState()
policy = execution.ExecutionPolicy(state, Path.cwd())
prompter = YoloPrompter(AlwaysDeny())
prompter.bind_execution_policy(policy)
assert execution.policy_for(prompter) is policy
assert isinstance(state.http_permissions, grants.HTTPPermissions)
assert isinstance(policy.observations, observations.ObservationStore)
assert policy.observations._verifiers['sql-injection'] is verifiers.sql_boolean
assert worker.ExecutionBlocked is execution.ExecutionBlocked
"""
    subprocess.run(
        [sys.executable, "-c", script, entrypoint],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )


@pytest.mark.parametrize("package", [
    "src.permission",
    "src.permission.runtime",
    "src.permission.network",
    "src.permission.worker",
])
def test_package_import_keeps_runtime_initialization_deferred(package):
    script = """
import importlib
import sys

importlib.import_module(sys.argv[1])
assert all(name in ('src.permission', sys.argv[1])
           for name in sys.modules if name.startswith('src.permission'))
assert 'httpx' not in sys.modules
assert 'mcp' not in sys.modules
"""
    subprocess.run(
        [sys.executable, "-c", script, package],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )


@pytest.mark.parametrize("module_name,symbol", [
    ("src.permission.permission", "PermissionRequest"),
    ("src.permission.runtime.execution", "ExecutionPolicy"),
    ("src.permission.runtime.execution", "ExecutionReceipt"),
    ("src.permission.runtime.invocations", "ReviewTurn"),
    ("src.permission.runtime.observations", "ObservationStore"),
    ("src.permission.runtime.observations", "VerifiedResult"),
    ("src.permission.runtime.verifiers", "register_production_verifiers"),
    ("src.permission.network.control", "parse_lab_spec"),
    ("src.permission.network.grants", "HTTPPermissions"),
    ("src.permission.network.transport", "pin_request"),
    ("src.permission.worker.worker", "OfflineWorker"),
    ("src.permission.worker.broker", "broker_directory"),
    ("src.permission.worker.relay", "relay"),
])
def test_permission_symbols_have_canonical_module_identity(module_name, symbol):
    assert getattr(importlib.import_module(module_name), symbol).__module__ == module_name


def test_default_policy_still_protects_runtime_control_paths():
    policy = default_execution_policy(EngagementState(), PROJECT_ROOT)
    expected = tuple(PROJECT_ROOT / name for name in (
        "src", "skills", "AGENTS.md", ".git", ".kagent",
    ))
    assert policy.protected == expected
    for path in expected:
        with pytest.raises(ExecutionBlocked, match="protected-control-plane"):
            policy.require_path(path)


def test_tool_identity_retains_pre_move_invocation_digest():
    tool = HTTPTool(Target("http://127.0.0.1:3000"), EngagementState())
    assert type(tool).__module__ == "src.tools.http.http_tool"
    # Captured from the original permission.execution before moving modules.
    assert invocation_digest(tool, {"url": "/fixture", "phase": "recon"}) == (
        "6519282f5219c12bd211bb558e0c66bcaf23109b80030e55ff4e0b02958a1f5c"
    )


def test_worker_mounts_relay_that_runs_without_project_imports(tmp_path):
    from src.permission.worker.worker import OfflineWorker

    broker = tmp_path / "broker"
    broker.mkdir()
    worker = OfflineWorker(tmp_path, (), "/usr/bin/bwrap", "/usr/bin/prlimit")
    _, argv = worker.wrap("/bin/true", [], broker=broker)
    relay_path = Path(argv[argv.index("/relay.py") - 1])
    assert relay_path == PROJECT_ROOT / "src/permission/worker/relay.py"
    assert relay_path.is_file()
    script = """
import asyncio
import runpy
import sys

namespace = runpy.run_path(sys.argv[1])
start_server = asyncio.start_server

async def ephemeral_server(callback, host, port):
    assert (host, port) == ('127.0.0.1', 18080)
    return await start_server(callback, host, 0)

asyncio.start_server = ephemeral_server
sys.argv = ['relay.py', sys.executable, '-I', '-S', '-c',
            "print('relay-child'); raise SystemExit(7)"]
raise SystemExit(asyncio.run(namespace['main']()))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, str(relay_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 7, result.stderr
    assert result.stdout.strip() == "relay-child"
