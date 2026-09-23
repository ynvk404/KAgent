from __future__ import annotations

import copy
import json
import os
import random
import string
import uuid
import warnings
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from src.paths import user_data_root


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
class CustomProviderConfig:
    """Non-secret configuration for one OpenAI-compatible provider profile."""

    name: str
    protocol: str
    base_url: str
    default_model: str = ""


@dataclass
class Config:
    backend: Backend | str = Backend.EMPTY
    model: str = ""
    base_url: str = ""
    api_keys: dict[str, str] = field(default_factory=dict)
    skills_dirs: list[str] = field(default_factory=list)
    disabled_skills: list[str] = field(default_factory=list)
    mcp_servers: list[MCPServerConfig] = field(default_factory=list)
    plugins: list[PluginConfig] = field(default_factory=list)
    session_path: str = ""
    thinking_enabled: bool = False
    streaming_enabled: bool = True
    max_steps: int = 0
    auto_compact_threshold: int = DEFAULT_AUTO_COMPACT_THRESHOLD
    temperature: float | None = None
    max_tokens: int | None = None
    gemini_thinking_budget: int | None = None
    tooling_profile: ToolingProfile | None = None
    custom_providers: dict[str, CustomProviderConfig] = field(default_factory=dict)
    custom_provider_api_keys: dict[str, str] = field(default_factory=dict)
    active_custom_provider_id: str | None = None

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
    override = os.getenv("kagent_CONFIG")
    if override:
        return Path(override)
    return user_data_root() / "config.json"


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
        data["tooling_profile"] = cfg.tooling_profile.value

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

    custom_providers = _custom_providers_field(data)
    custom_provider_api_keys = _custom_provider_api_keys_field(data)
    _validate_custom_provider_key_references(
        custom_providers,
        custom_provider_api_keys,
    )
    active_custom_provider_id = _active_custom_provider_id_field(data)
    if (
        active_custom_provider_id is not None
        and active_custom_provider_id not in custom_providers
    ):
        raise ValueError(
            "active_custom_provider_id must reference a saved custom provider"
        )

    return Config(
        backend=backend,
        model=_string_field(data, "model", ""),
        base_url=_string_field(data, "base_url", ""),
        api_keys=normalized_api_keys,
        custom_providers=custom_providers,
        custom_provider_api_keys=custom_provider_api_keys,
        active_custom_provider_id=active_custom_provider_id,
        skills_dirs=_string_list_field(data, "skills_dirs"),
        disabled_skills=_string_list_field(data, "disabled_skills"),
        mcp_servers=[_validate_mcp_server(x) for x in _list_field(data, "mcp_servers")],
        plugins=[_validate_plugin(x) for x in _list_field(data, "plugins")],
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
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise RuntimeError(f"config: failed to read {path}: {e}")

    if not isinstance(raw, dict):
        raise RuntimeError(f"config: {path}: invalid json")

    try:
        return config_from_dict(raw)
    except ValueError as error:
        if "custom_provider" not in str(error):
            raise
        return config_from_dict(_sanitize_custom_provider_data(raw))


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

    tmp = path.parent / (
        ".kagent.cfg.tmp."
        + "".join(
            random.choices(
                string.hexdigits.lower(),
                k=6,
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
            # Apply final permissions and sync them while the file is still
            # temporary; atomic replacement is the final commit operation.
            os.chmod(tmp, 0o600)
            os.fsync(f.fileno())

        os.replace(
            tmp,
            path,
        )

    except Exception as e:
        if created_tmp and tmp.exists():
            tmp.unlink(missing_ok=True)
        raise RuntimeError(f"config: save failed: {e}")


def default_config() -> Config:
    return Config()


def add_custom_provider(
    cfg: Config,
    name: str,
    base_url: str,
    api_key: str = "",
    default_model: str = "",
) -> str:
    """Add a profile with an opaque stable ID and return that ID."""
    normalized_name = name.strip()
    normalized_base_url = base_url.strip()
    if not normalized_name:
        raise ValueError("custom provider name must not be empty")
    if not normalized_base_url:
        raise ValueError("custom provider base_url must not be empty")

    profile_id = uuid.uuid4().hex
    while profile_id in cfg.custom_providers:
        profile_id = uuid.uuid4().hex

    cfg.custom_providers[profile_id] = CustomProviderConfig(
        name=normalized_name,
        protocol="openai-compatible",
        base_url=normalized_base_url,
        default_model=default_model.strip(),
    )
    if api_key:
        cfg.custom_provider_api_keys[profile_id] = api_key
    return profile_id


def edit_custom_provider(
    cfg: Config,
    profile_id: str,
    *,
    name: str,
    base_url: str,
    api_key: str | None = None,
    default_model: str = "",
) -> CustomProviderConfig | None:
    """Edit profile metadata without changing its ID; ``None`` keeps its key."""
    existing = cfg.custom_providers.get(profile_id)
    if existing is None:
        return None

    normalized_name = name.strip()
    normalized_base_url = base_url.strip()
    if not normalized_name:
        normalized_name = existing.name
    if not normalized_base_url:
        normalized_base_url = existing.base_url

    updated = CustomProviderConfig(
        name=normalized_name,
        protocol=existing.protocol,
        base_url=normalized_base_url,
        default_model=default_model.strip(),
    )
    cfg.custom_providers[profile_id] = updated

    if api_key is not None:
        if api_key:
            cfg.custom_provider_api_keys[profile_id] = api_key
        else:
            cfg.custom_provider_api_keys.pop(profile_id, None)
    return updated


def delete_custom_provider(cfg: Config, profile_id: str) -> bool:
    """Delete an inactive profile and its associated secret."""
    if profile_id not in cfg.custom_providers:
        return False
    if cfg.active_custom_provider_id == profile_id:
        return False

    del cfg.custom_providers[profile_id]
    cfg.custom_provider_api_keys.pop(profile_id, None)
    return True


def resolve_custom_provider(
    cfg: Config,
    profile_id: str,
    *,
    model_override: str | None = None,
    base_url_override: str | None = None,
    api_key_override: str | None = None,
) -> tuple[Config, CustomProviderConfig]:
    """Return an effective OpenAI-compatible config without mutating ``cfg``.

    A missing profile key resolves to an empty key. It never falls back to the
    Manual ``api_keys["openai-compat"]`` slot.
    """
    profile = cfg.custom_providers.get(profile_id)
    if profile is None:
        raise ValueError(f"custom provider profile not found: {profile_id}")
    if not isinstance(profile, CustomProviderConfig):
        raise ValueError(f"custom provider profile is malformed: {profile_id}")
    if (
        not isinstance(profile.name, str)
        or not isinstance(profile.protocol, str)
        or not isinstance(profile.base_url, str)
        or not isinstance(profile.default_model, str)
    ):
        raise ValueError(f"custom provider profile is malformed: {profile_id}")
    if profile.protocol != "openai-compatible":
        raise ValueError(f"custom provider protocol is unsupported: {profile_id}")
    if not profile.name.strip() or not profile.base_url.strip():
        raise ValueError(f"custom provider profile is malformed: {profile_id}")

    profile_key = cfg.custom_provider_api_keys.get(profile_id, "")
    if not isinstance(profile_key, str):
        raise ValueError(f"custom provider API key is malformed: {profile_id}")

    effective = copy.deepcopy(cfg)
    effective.backend = Backend.OPENAI_COMPAT
    effective.model = (
        model_override if model_override is not None else profile.default_model
    )
    effective.base_url = (
        base_url_override if base_url_override is not None else profile.base_url
    )
    effective.api_keys[Backend.OPENAI_COMPAT.value] = (
        api_key_override if api_key_override is not None else profile_key
    )
    effective.active_custom_provider_id = profile_id
    return effective, profile


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
    if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
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
        raise ValueError(f"tooling_profile is invalid: {value!r}") from e


def _custom_providers_field(
    data: dict[str, Any],
) -> dict[str, CustomProviderConfig]:
    value = data.get("custom_providers", {})
    if not isinstance(value, dict):
        raise ValueError("custom_providers must be an object")

    profiles: dict[str, CustomProviderConfig] = {}
    for profile_id, raw_profile in value.items():
        section = f"custom_providers[{profile_id!r}]"
        _validate_custom_provider_id(profile_id, section)
        if not isinstance(raw_profile, dict):
            raise ValueError(f"{section} must be an object")

        name = _required_string(raw_profile, section, "name")
        protocol = _required_string(raw_profile, section, "protocol")
        base_url = _required_string(raw_profile, section, "base_url")
        default_model = _entry_string(
            raw_profile,
            section,
            "default_model",
            "",
        )
        if not name.strip():
            raise ValueError(f"{section}.name must not be empty")
        if protocol != "openai-compatible":
            raise ValueError(
                f"{section}.protocol must be 'openai-compatible'"
            )
        if not base_url.strip():
            raise ValueError(f"{section}.base_url must not be empty")

        profiles[profile_id] = CustomProviderConfig(
            name=name,
            protocol=protocol,
            base_url=base_url,
            default_model=default_model,
        )
    return profiles


def _sanitize_custom_provider_data(data: dict[str, Any]) -> dict[str, Any]:
    """Drop malformed Custom entries individually while retaining good data.

    ``config_from_dict`` remains strict. This recovery path is used by ``load``
    only after strict parsing has identified invalid Custom provider data.
    """
    recovered = dict(data)
    raw_profiles = data.get("custom_providers", {})
    profiles: dict[str, CustomProviderConfig] = {}
    if not isinstance(raw_profiles, dict):
        warnings.warn(
            "config: malformed custom_providers collection was ignored",
            RuntimeWarning,
            stacklevel=2,
        )
    else:
        for profile_id, raw_profile in raw_profiles.items():
            try:
                parsed = _custom_providers_field(
                    {"custom_providers": {profile_id: raw_profile}}
                )
            except ValueError as error:
                warnings.warn(
                    f"config: malformed Custom profile was ignored ({error})",
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue
            profiles.update(parsed)

    raw_keys = data.get("custom_provider_api_keys", {})
    keys: dict[str, str] = {}
    if not isinstance(raw_keys, dict):
        warnings.warn(
            "config: malformed custom provider keys were ignored",
            RuntimeWarning,
            stacklevel=2,
        )
    else:
        for profile_id, api_key in raw_keys.items():
            try:
                _validate_custom_provider_id(profile_id, "custom_provider_api_keys")
            except ValueError as error:
                warnings.warn(
                    f"config: malformed custom provider key entry was ignored ({error})",
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue
            if profile_id not in profiles:
                warnings.warn(
                    "config: custom provider key without a valid profile was ignored",
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue
            if not isinstance(api_key, str):
                warnings.warn(
                    "config: malformed custom provider key value was ignored",
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue
            keys[profile_id] = api_key

    active_id: str | None = None
    if data.get("active_custom_provider_id") is not None:
        try:
            active_id = _active_custom_provider_id_field(data)
        except ValueError as error:
            warnings.warn(
                f"config: malformed active custom provider ID was cleared ({error})",
                RuntimeWarning,
                stacklevel=2,
            )
        if active_id is not None and active_id not in profiles:
            warnings.warn(
                "config: active custom provider without a valid profile was cleared",
                RuntimeWarning,
                stacklevel=2,
            )
            active_id = None

    recovered["custom_providers"] = {
        profile_id: {
            "name": profile.name,
            "protocol": profile.protocol,
            "base_url": profile.base_url,
            "default_model": profile.default_model,
        }
        for profile_id, profile in profiles.items()
    }
    recovered["custom_provider_api_keys"] = keys
    recovered["active_custom_provider_id"] = active_id
    return recovered


def _custom_provider_api_keys_field(
    data: dict[str, Any],
) -> dict[str, str]:
    value = data.get("custom_provider_api_keys", {})
    if not isinstance(value, dict) or not all(
        isinstance(profile_id, str) and isinstance(api_key, str)
        for profile_id, api_key in value.items()
    ):
        raise ValueError("custom_provider_api_keys must be a string map")
    for profile_id in value:
        _validate_custom_provider_id(
            profile_id,
            "custom_provider_api_keys",
        )
    return dict(value)


def _validate_custom_provider_key_references(
    profiles: dict[str, CustomProviderConfig],
    api_keys: dict[str, str],
) -> None:
    orphaned = api_keys.keys() - profiles.keys()
    if orphaned:
        raise ValueError(
            "custom_provider_api_keys contains an ID without a saved profile"
        )


def _active_custom_provider_id_field(
    data: dict[str, Any],
) -> str | None:
    value = data.get("active_custom_provider_id")
    if value is None:
        return None
    _validate_custom_provider_id(value, "active_custom_provider_id")
    return value


def _validate_custom_provider_id(value: Any, section: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{section} ID must be a UUID hex string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise ValueError(f"{section} ID must be a UUID hex string") from error
    if parsed.hex != value:
        raise ValueError(f"{section} ID must be a lowercase UUID hex string")


def _validate_mcp_server(
    data: Any,
) -> MCPServerConfig:
    section = "mcp_servers[]"
    if not isinstance(data, dict):
        raise ValueError(f"{section} must be an object")
    name = _required_string(data, section, "name")
    command = _required_string(data, section, "command")
    if not no_shell_meta(command):
        raise ValueError(f"{section}.command must not contain shell metacharacters")
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
        raise ValueError(f"{section}.command must not contain shell metacharacters")
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
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
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
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
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
