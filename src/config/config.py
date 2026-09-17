from __future__ import annotations

import json
import os
import random
import string

from dataclasses import dataclass, field, asdict
from enum import StrEnum
from pathlib import Path
from typing import Any

class Backend(StrEnum):
    EMPTY = ""
    OPENAI_COMPAT = "openai-compat"
    KIMI = "kimi"
    GROQ = "groq"
    OPENROUTER = "openrouter"
    DEEPSEEK = "deepseek"
    GEMINI = "gemini"
    ANTHROPIC = "anthropic"


class ToolingProfile(StrEnum):
    MINIMAL = "minimal"
    FULL = "full"

DEFAULT_AUTO_COMPACT_THRESHOLD = 16000

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

def config_path() -> Path:
    override = os.getenv(
        "kagent_CONFIG"
    )
    if override:
        return Path(override)
    return (
        Path.home()
        / ".kagent"
        / "config.json"
    )


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
    if not isinstance(data, dict):
        raise ValueError("config must be an object")

    backend = data.get("backend", "")
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
        model=_string_field(data, "model", ""),
        base_url=_string_field(data, "base_url", ""),
        api_keys=normalized_api_keys,
        skills_dirs=_string_list_field(data, "skills_dirs"),
        disabled_skills=_string_list_field(data, "disabled_skills"),
        mcp_servers=[
            _validate_mcp_server(x)
            for x in _list_field(data, "mcp_servers")
        ],
        plugins=[
            _validate_plugin(x)
            for x in _list_field(data, "plugins")
        ],
        session_path=data.get("session_path", ""),
        thinking_enabled=_bool_field(data, "thinking_enabled", False),
        streaming_enabled=_bool_field(data, "streaming_enabled", True),
        max_steps=_int_field(data, "max_steps", 0),
        auto_compact_threshold=_int_field(
            data,
            "auto_compact_threshold",
            DEFAULT_AUTO_COMPACT_THRESHOLD,
        ),
        temperature=_number_or_none_field(data, "temperature"),
        max_tokens=_int_or_none_field(data, "max_tokens"),
        gemini_thinking_budget=_int_or_none_field(
            data,
            "gemini_thinking_budget",
        ),
        tooling_profile=_tooling_profile_field(data),
    )


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
            ".kagent.cfg.tmp."
            +
            "".join(
                random.choices(
                    string.hexdigits.lower(),
                    k=6,
                )
            )
        )
    )

    created_tmp = False
    try:
        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        created_tmp = True
        with os.fdopen(fd, "w", encoding="utf-8") as f:
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
        if created_tmp and tmp.exists():
            tmp.unlink(
                missing_ok=True
            )
        raise RuntimeError(
            f"config: save failed: {e}"
        )

def default_config() -> Config:
    return Config()


def _list_field(
    data: dict[str, Any],
    name: str,
) -> list[Any]:
    value = data.get(name, [])
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list")
    return value


def _string_list_field(
    data: dict[str, Any],
    name: str,
) -> list[str]:
    value = _list_field(data, name)
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must contain only strings")
    return value


def _string_field(
    data: dict[str, Any],
    name: str,
    default: str,
) -> str:
    value = data.get(name, default)
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _bool_field(
    data: dict[str, Any],
    name: str,
    default: bool,
) -> bool:
    value = data.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _int_field(
    data: dict[str, Any],
    name: str,
    default: int,
) -> int:
    value = data.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    return value


def _int_or_none_field(
    data: dict[str, Any],
    name: str,
) -> int | None:
    value = data.get(name)
    if value is not None and (
        not isinstance(value, int) or isinstance(value, bool)
    ):
        raise ValueError(f"{name} must be an integer or null")
    return value


def _number_or_none_field(
    data: dict[str, Any],
    name: str,
) -> float | int | None:
    value = data.get(name)
    if value is not None and (
        not isinstance(value, (int, float)) or isinstance(value, bool)
    ):
        raise ValueError(f"{name} must be a number or null")
    return value


def _tooling_profile_field(
    data: dict[str, Any],
) -> ToolingProfile | None:
    value = data.get("tooling_profile")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("tooling_profile must be a string or null")
    try:
        return ToolingProfile(value)
    except ValueError as e:
        raise ValueError(
            f"tooling_profile is invalid: {value!r}"
        ) from e


def _validate_mcp_server(
    data: Any,
) -> MCPServerConfig:
    section = "mcp_servers[]"
    if not isinstance(data, dict):
        raise ValueError(f"{section} must be an object")
    name = _required_string(data, section, "name")
    command = _required_string(data, section, "command")
    if not no_shell_meta(command):
        raise ValueError(
            f"{section}.command must not contain shell metacharacters"
        )
    return MCPServerConfig(
        name=name,
        command=command,
        args=_entry_string_list(data, section, "args"),
        env=_entry_string_dict(data, section, "env"),
    )

def _validate_plugin(
    data: Any,
) -> PluginConfig:
    section = "plugins[]"
    if not isinstance(data, dict):
        raise ValueError(f"{section} must be an object")
    name = _required_string(data, section, "name")
    command = _required_string(data, section, "command")
    if not no_shell_meta(command):
        raise ValueError(
            f"{section}.command must not contain shell metacharacters"
        )
    return PluginConfig(
        name=name,
        command=command,
        args=_entry_string_list(data, section, "args"),
        description=_entry_string(data, section, "description", ""),
        schema=_entry_dict_or_none(data, section, "schema"),
        requires_permission=_entry_bool(
            data,
            section,
            "requires_permission",
            False,
        ),
    )


def _required_string(
    data: dict[str, Any],
    section: str,
    name: str,
) -> str:
    if name not in data:
        raise ValueError(f"{section}.{name} is required")
    return _entry_string(data, section, name, "")


def _entry_string(
    data: dict[str, Any],
    section: str,
    name: str,
    default: str,
) -> str:
    value = data.get(name, default)
    if not isinstance(value, str):
        raise ValueError(f"{section}.{name} must be a string")
    return value


def _entry_string_list(
    data: dict[str, Any],
    section: str,
    name: str,
) -> list[str]:
    value = data.get(name, [])
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise ValueError(f"{section}.{name} must be a list of strings")
    return value


def _entry_string_dict(
    data: dict[str, Any],
    section: str,
    name: str,
) -> dict[str, str] | None:
    value = data.get(name)
    if value is None:
        return None
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str)
        for key, item in value.items()
    ):
        raise ValueError(f"{section}.{name} must be a string map or null")
    return value


def _entry_dict_or_none(
    data: dict[str, Any],
    section: str,
    name: str,
) -> dict[str, Any] | None:
    value = data.get(name)
    if value is not None and not isinstance(value, dict):
        raise ValueError(f"{section}.{name} must be an object or null")
    return value


def _entry_bool(
    data: dict[str, Any],
    section: str,
    name: str,
    default: bool,
) -> bool:
    value = data.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"{section}.{name} must be a boolean")
    return value
