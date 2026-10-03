

from __future__ import annotations

import pytest

from src.config.config import PluginConfig
from src.permission.permission import AlwaysAllow
from src.tools.execution.plugin import CommandPluginTool


class _NeverAborted:

    aborted = False


def test_permission_required_plugin_cannot_be_yolo_or_session_trusted():
    tool = CommandPluginTool(PluginConfig(
        name="high_impact_plugin",
        command="python",
        args=["-c", "pass"],
        description="external action",
        requires_permission=True,
    ))

    assert tool.permission_hints({}) == {
        "noSessionCache": True,
        "riskTier": "high-impact",
    }


def test_plugin_permission_cannot_be_disabled_by_legacy_config_flag():
    tool = CommandPluginTool(PluginConfig(
        name="untrusted_plugin",
        command="python",
        args=["-c", "pass"],
        description="external action",
        requires_permission=False,
    ))

    assert tool.requires_permission() is True
    assert tool.permission_hints({}) == {
        "noSessionCache": True,
        "riskTier": "high-impact",
    }


@pytest.mark.asyncio
async def test_truncates_large_plugin_output() -> None:
    tool = CommandPluginTool(
        PluginConfig(
            name="big_plugin",
            # Giống TypeScript: chỉ dùng tên executable.
            command="python",
            args=[
                "-c",
                "import sys; sys.stdout.write('a' * 300000)",
            ],
            description="",
            requires_permission=False,
        )
    )

    out = await tool.run(
        {},
        _NeverAborted(),
        AlwaysAllow(),
    )

    assert "truncated" in out
    assert len(out) < 140_000
