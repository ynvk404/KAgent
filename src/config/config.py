from __future__ import annotations

import json
import os
import random
import string

from dataclasses import dataclass, field, asdict
from enum import StrEnum
from pathlib import Path
from typing import Any

# ============================================================================
# Backend
# ============================================================================

class Backend(StrEnum):
    EMPTY = ""
    OPENAI_COMPAT = "openai-compat"
    KIMI = "kimi"
    GROQ = "groq"
    OPENROUTER = "openrouter"
    DEEPSEEK = "deepseek"
    GEMINI = "gemini"
    ANTHROPIC = "anthropic"

# ============================================================================
# Tooling Profile
# ============================================================================

class ToolingProfile(StrEnum):
    MINIMAL = "minimal"
    FULL = "full"

# ============================================================================
# Constants
# ============================================================================

DEFAULT_AUTO_COMPACT_THRESHOLD = 16000

# ============================================================================
# Sub Config
# ============================================================================

@dataclass
class MCPServerConfig:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None

@dataclass
class PluginConfig:
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    description: str = ""
    schema: dict[str, Any] | None = None
    requires_permission: bool = False

# ============================================================================
# Main Config
# ============================================================================

@dataclass
class Config:
    backend: Backend | str = Backend.EMPTY
    model: str = ""
    base_url: str = ""
    api_keys: dict[str, str] = field(default_factory=dict)
    skills_dirs: list[str] = field(
        default_factory=list
    )
    disabled_skills: list[str] = field(
        default_factory=list
    )
    mcp_servers: list[MCPServerConfig] = field(
        default_factory=list
    )
    plugins: list[PluginConfig] = field(
        default_factory=list
    )
    session_path: str = ""
    thinking_enabled: bool = False
    streaming_enabled: bool = True
    max_steps: int = 0
    auto_compact_threshold: int = (
        DEFAULT_AUTO_COMPACT_THRESHOLD
    )
    temperature: float | None = None
    max_tokens: int | None = None
    gemini_thinking_budget: int | None = None
    tooling_profile: ToolingProfile | None = None

    @property
    def api_key(self) -> str:
        return self.api_keys.get(
            str(self.backend),
            "",
        )

    @api_key.setter
    def api_key(self, value: str) -> None:
        backend = str(self.backend)
        if not backend:
            return
        self.api_keys[backend] = value

# ============================================================================
# Validation
# ============================================================================

def no_shell_meta(value: str) -> bool:
    forbidden = (
        "|",
        "&",
        ";",
        "<",
        ">",
        "$",
        "`",
        "\\",
        "\n",
    )
    return (
        not any(x in value for x in forbidden)
        and "$(" not in value
        and "${" not in value
    )

# ============================================================================
# Paths
# ============================================================================

def config_path() -> Path:
    override = os.getenv(
        "pentestagent_CONFIG"
    )
    if override:
        return Path(override)
    return (
        Path.home()
        / ".pentestagent"
        / "config.json"
    )

# ============================================================================
# Serialization
# ============================================================================

def config_to_dict(
    cfg: Config,
) -> dict[str, Any]:
    data = asdict(cfg)
    if isinstance(cfg.backend, Backend):
        data["backend"] = cfg.backend.value
    else:
        data["backend"] = cfg.backend

    if isinstance(
        cfg.tooling_profile,
        ToolingProfile,
    ):
        data["tooling_profile"] = (
            cfg.tooling_profile.value
        )

    return data

def config_from_dict(
    data: dict[str, Any],
) -> Config:
    backend = data.get(
        "backend",
        "",
    )
    api_keys = data.get(
        "api_keys",
    )

    if isinstance(api_keys, dict):
        normalized_api_keys = {
            str(k): str(v)
            for k, v in api_keys.items()
            if isinstance(k, str) and isinstance(v, str)
        }
    else:
        normalized_api_keys = {}

    if not isinstance(api_keys, dict):
        old_api_key = data.get(
            "api_key",
            "",
        )
        if old_api_key and backend:
            normalized_api_keys[str(backend)] = str(old_api_key)

    return Config(
        backend=backend,
        model=data.get(
            "model",
            "",
        ),
        base_url=data.get(
            "base_url",
            "",
        ),
        api_keys=normalized_api_keys,
        skills_dirs=data.get(
            "skills_dirs",
            [],
        ),
        disabled_skills=data.get(
            "disabled_skills",
            [],
        ),
        mcp_servers=[
            _validate_mcp_server(x)
            for x in data.get(
                "mcp_servers",
                []
            )
        ],
        plugins=[
            _validate_plugin(x)
            for x in data.get(
                "plugins",
                []
            )
        ],
        session_path=data.get(
            "session_path",
            "",
        ),
        thinking_enabled=data.get(
            "thinking_enabled",
            False,
        ),
        streaming_enabled=data.get(
            "streaming_enabled",
            True,
        ),
        max_steps=data.get(
            "max_steps",
            0,
        ),
        auto_compact_threshold=data.get(
            "auto_compact_threshold",
            DEFAULT_AUTO_COMPACT_THRESHOLD,
        ),
        temperature=data.get(
            "temperature",
        ),
        max_tokens=data.get(
            "max_tokens",
        ),
        gemini_thinking_budget=data.get(
            "gemini_thinking_budget",
        ),
        tooling_profile=(
            ToolingProfile(data["tooling_profile"])
            if data.get("tooling_profile") is not None
            else None
        ),
    )

# ============================================================================
# Load / Save
# ============================================================================

def load() -> Config:
    path = config_path()
    if not path.exists():
        return default_config()

    try:
        raw = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as e:
        raise RuntimeError(
            f"config: failed to read {path}: {e}"
        )

    if not isinstance(raw, dict):
        raise RuntimeError(
            f"config: {path}: invalid json"
        )

    return config_from_dict(raw)

async def save(
    cfg: Config,
) -> None:
    path = config_path()
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    body = (
        json.dumps(
            config_to_dict(cfg),
            indent=2,
        )
        + "\n"
    )

    tmp = (
        path.parent
        /
        (
            ".pentestagent.cfg.tmp."
            +
            "".join(
                random.choices(
                    string.hexdigits.lower(),
                    k=6,
                )
            )
        )
    )

    try:
        with open(
            tmp,
            "x",
            encoding="utf-8",
        ) as f:
            f.write(body)
            f.flush()
            os.fsync(
                f.fileno()
            )

        os.replace(
            tmp,
            path,
        )

        os.chmod(
            path,
            0o600,
        )

    except Exception as e:
        if tmp.exists():
            tmp.unlink(
                missing_ok=True
            )
        raise RuntimeError(
            f"config: save failed: {e}"
        )

# ============================================================================
# Test helper
# ============================================================================

def default_config() -> Config:
    return Config()

def _validate_mcp_server(
    data: dict,
) -> MCPServerConfig:
    command = data.get(
        "command",
        ""
    )
    if not no_shell_meta(command):
        raise ValueError(
            "mcp_servers[].command must not contain shell metacharacters"
        )
    return MCPServerConfig(
        **data
    )

def _validate_plugin(
    data: dict,
) -> PluginConfig:
    command = data.get(
        "command",
        ""
    )
    if not no_shell_meta(command):
        raise ValueError(
            "plugins[].command must not contain shell metacharacters"
        )
    return PluginConfig(
        **data
    )
