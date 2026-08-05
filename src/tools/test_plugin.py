"""
Test truncate cho CommandPluginTool.

Port từ:
agent/src/tools/plugin.test.ts
"""

from __future__ import annotations

import pytest

from src.config.config import PluginConfig
from src.permission.permission import AlwaysAllow
from src.tools.plugin import CommandPluginTool


class _NeverAborted:
    """Đóng vai trò AbortController().signal — không bao giờ abort."""

    aborted = False


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