

from __future__ import annotations



from src.config.config import PluginConfig
from src.tools.execution.plugin import CommandPluginTool


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
