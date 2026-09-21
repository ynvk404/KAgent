from __future__ import annotations

import json
import shutil
import asyncio
import base64
import inspect
import os
import secrets
import signal
import sys
import time
from types import SimpleNamespace
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, cast, TypedDict, Optional
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver
from watchdog.events import FileSystemEventHandler
GROQ_AUTO_COMPACT_THRESHOLD = 5500
BURP_DEFAULT_PORT = 8888

from src.version.version import VERSION, describe

from src.config import config
from src.config.config import ToolingProfile, Backend

from src.logger import logger
from src.logger.session_debug import (
    create_session_debug_log,
    SessionDebugOptions,
)

from src.target.target import new_target
from src.engagement.state import EngagementState

from src.agent.agent import Agent, AgentOptions
from src.agent.system_prompt import PromptToolingProfile, PromptProfile
from src.permission.permission import AlwaysAllow
from src.permission.permission import YoloPrompter

from src.llm import factory as llm_factory
from src.llm.model_warnings import model_reliability_warning
from src.llm.probe import probe_tool_support
from src.llm.providers import *

from src.memory.store import MemoryStore
from src.coverage.store import CoverageStore
from src.engagement.store import EngagementStore
from src.intelligence.store import IntelligenceStore

from src.findings.store import Store as FindingsStore
from src.findings.http_request import finding_request_for_burp

from src.session import store as session_store

from src.skills.discovery import skill_search_dirs
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry as SkillRegistry

from src.tools.plugin import CommandPluginTool
from src.tools.finding import ConfirmFindingTool
from src.tools.registry import Registry as ToolRegistry
from src.redact.redact import apply as redact
from src.tools.shell import BashTool, ShellTool
from src.tools.http import HTTPTool

from src.tools.web import (
    WebFetchTool,
    WebSearchTool,
)

from src.tools.search import (
    GlobTool,
    GrepTool,
)

from src.tools.file import (
    FileReadTool,
    FileReadToolAlias,
    FileWriteTool,
    FileWriteToolAlias,
    FileEditTool,
    FileEditToolAlias,
)

from src.tools.ask import AskUserTool
from src.tools.coverage import CoverageTool
from src.tools.payloads import ReadPayloadsTool
from src.tools.skill_file import ReadSkillFileTool
from src.tools.workflow import WorkflowTool
from src.workflow.state import WorkflowState

from src.tools.mcp_server import (
    BROWSER_MCP_NAMES,
    session_mcp_servers,
)

from src.tools.mcp_integration import (
    MCPServerConfig,
    MCPSession,
    discover_mcp_tools,
)

from src.browser.store import CaptureStore

from src.tools.browser_capture import (
    register_browser_capture_tools,
)

from src.browser.server import (
    start_ingest_server,
    IngestServerOptions,
    BurpBridgeResult,
    BurpBridgeState,
    IngestServerHandle,
)

from src.ui.core.app import (
    KAgent,
    AppProps,
    ConfigSnapshot,
    ProviderChange,
)

from src.ui.widgets.banner import BannerData, ToolSupportPill

from src.ui.core.terminal_size import (
    terminal_size_watcher,
)

from src.ui.bridges.perm_bridge import (
    BridgedPrompter,
    PermissionRequest,
)

from src.ui.bridges.ask_bridge import (
    BridgedAskPrompter,
    AskRequest,
)

from src.ui.core.first_run_picker import (
    FirstRunPicker,
    FirstRunPickerRequest,
)


_USE_COLOR = sys.stdout.isatty()
 
 
def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"
 
 
DIM = lambda t: _c("2", t)
BOLD = lambda t: _c("1", t)
GRAY = lambda t: _c("90", t)
CYAN = lambda t: _c("36", t)
YELLOW = lambda t: _c("33", t)
GREEN = lambda t: _c("32", t)
RED = lambda t: _c("31", t)
MAGENTA = lambda t: _c("35", t)
BLUE = lambda t: _c("34", t)
 
class BannerDataPatch(TypedDict, total=False):
    provider: str
    model: str
    cwd: str
    endpoint: str | None
    state: str | None
    status: str | None
    tool_support: ToolSupportPill | None
    context_window: int | None

class AbortSignal:
    def __init__(self):
        self.aborted = False

    def abort(self):
        self.aborted = True

    def throw_if_aborted(self):
        if self.aborted:
            raise Exception("aborted")
   
@dataclass
class BannerHolder:
    publish: Optional[Callable[[BannerDataPatch], None]] = None

banner_holder = BannerHolder()

@dataclass(slots=True)
class ParsedFlags:
    show_version: bool = False
    show_help: bool = False
    backend: str = ""
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    skills_dirs: list[str] = field(default_factory=list)
    resume_id: str = ""
    yolo: bool = False
    browser: bool = False
    burp: bool = False
    burp_port: int = 0 
    no_stream: bool = False
    log_path: str = ""
    debug_session: bool = False
    debug_session_path: str = ""
    list_skills: bool = False
    list_tools: bool = False


class FlagParseError(ValueError):
    pass

class NoticeHolder:
    def __init__(self):
        self._publisher: Callable[[str], None] | None = None

    def bind(self, publisher: Callable[[str], None]) -> None:
        self._publisher = publisher

    def publish(self, text: str) -> None:
        if self._publisher:
            self._publisher(text)

notice_holder = NoticeHolder()

def parse_flags(argv: list[str]) -> ParsedFlags:
    out = ParsedFlags(
        burp_port=BURP_DEFAULT_PORT,
        debug_session=os.getenv("KAgent_DEBUG_SESSION") == "1",
        debug_session_path=os.getenv("KAgent_DEBUG_SESSION_PATH", ""),
    )

    i = 0

    def next_arg(flag: str) -> str:
        nonlocal i
        i += 1
        if i >= len(argv) or argv[i].startswith("--"):
            raise FlagParseError(f"{flag} requires a value")
        return argv[i]

    while i < len(argv):
        a = argv[i]

        if a in ("--version", "-v"):
            out.show_version = True
        elif a in ("--help", "-h"):
            out.show_help = True
        elif a == "--backend":
            out.backend = next_arg(a)
        elif a == "--model":
            out.model = next_arg(a)
        elif a == "--base-url":
            out.base_url = next_arg(a)
        elif a == "--api-key":
            out.api_key = next_arg(a)
        elif a == "--skills":
            out.skills_dirs = [
                s.strip() for s in next_arg(a).split(",") if s.strip()
            ]
        elif a == "--resume":
            out.resume_id = next_arg(a)
            try:
                session_store.validate_id(out.resume_id)
            except ValueError as err:
                raise FlagParseError(f"--resume: {err}") from err
        elif a in ("--yolo", "--dangerously-skip-permissions"):
            out.yolo = True
        elif a == "--browser":
            out.browser = True
        elif a == "--no-stream":
            out.no_stream = True
        elif a in ("--burp", "--browser-ingest"):
            out.burp = True
            peek = argv[i + 1] if i + 1 < len(argv) else None
            if peek is not None and not peek.startswith("--"):
                try:
                    n = int(peek, 10)
                except ValueError:
                    raise FlagParseError("--burp port must be an integer")
                if not 0 < n < 65536:
                    raise FlagParseError("--burp port must be between 1 and 65535")
                out.burp_port = n
                i += 1
        elif a == "--log":
            out.log_path = next_arg(a)
        elif a == "--debug-session":
            out.debug_session = True
        elif a == "--debug-session-path":
            out.debug_session = True
            out.debug_session_path = next_arg(a)
        elif a == "--list-skills":
            out.list_skills = True
        elif a == "--list-tools":
            out.list_tools = True
        elif a.startswith("-"):
            raise FlagParseError(
                f"unknown option: {redacted_argv([a])[0]}"
            )

        i += 1

    return out


def redacted_argv(argv: list[str]) -> list[str]:
    out: list[str] = []
    redact_next = False

    for arg in argv:
        if redact_next:
            out.append("<redacted>")
            redact_next = False
        elif arg == "--api-key":
            out.append(arg)
            redact_next = True
        elif arg.startswith("--api-key="):
            out.append("--api-key=<redacted>")
        else:
            out.append(arg)

    return out

_background_tasks: set[asyncio.Task] = set()


def _spawn_reporting(coro, label: str) -> asyncio.Task:
    """Run a coroutine detached, keeping a reference so it is not garbage
    collected mid-flight and its failure is logged instead of dropped."""
    task = asyncio.create_task(coro)
    _background_tasks.add(task)

    def done(finished: asyncio.Task) -> None:
        _background_tasks.discard(finished)

        if finished.cancelled():
            return

        if (err := finished.exception()) is not None:
            logger.error(f"{label} task failed", {"err": str(err)})

    task.add_done_callback(done)
    return task


async def close_runtime_resources(
    root_ctl: asyncio.Event,
    reload_timer: asyncio.TimerHandle | None,
    watchers: list[Any],
    mcp_sessions: list[MCPSession],
    close_burp_bridge: Callable[[], Any],
) -> None:
    root_ctl.set()

    if reload_timer is not None:
        reload_timer.cancel()

    for observer in watchers:
        observer.stop()
    for observer in watchers:
        observer.join(timeout=1)

    await asyncio.gather(
        *(session.close() for session in mcp_sessions),
        return_exceptions=True,
    )
    await close_burp_bridge()


async def main() -> int:
    try:
        flags = parse_flags(sys.argv[1:])
    except FlagParseError as err:
        sys.stderr.write(f"kagent: {err}\n")
        return 2
    watched_dirs: set[str] = set()
    loop = asyncio.get_running_loop()
    root_ctl = asyncio.Event()
    if flags.show_version:
        sys.stdout.write(f"{describe()}\n")
        return 0

    if flags.show_help:
        print_help()
        return 0
    logger.init(flags.log_path)
    if (log_err := logger.init_error()) is not None:
        print(f"⚠ file logging disabled: {log_err}", file=sys.stderr)
    logger.info(
        "startup",
        {
            "version": VERSION,
            "pid": os.getpid(),
        },
    )
    def on_sig(sig_name: str):
        logger.warn("signal received, shutting down", {"signal": sig_name})
        root_ctl.set()

    for sig, name in ((signal.SIGINT, "SIGINT"), (signal.SIGTERM, "SIGTERM"), (signal.SIGHUP, "SIGHUP")):
        loop.add_signal_handler(sig, lambda n=name: on_sig(n))

    try:
        cfg = config.load()
    except Exception as err:
        bad_path = config.config_path()
        backup_path = f"{bad_path}.bad-{int(time.time() * 1000)}"
        try:
            os.rename(bad_path, backup_path)
            sys.stderr.write(
                f"warning: config was invalid and has been moved to {backup_path}: {err}\n"
            )
        except OSError:
            sys.stderr.write(f"warning: config was invalid: {err}\n")
        cfg = config.default_config()

    if flags.backend:
        cfg.backend = flags.backend
    if flags.model:
        cfg.model = flags.model
    if flags.base_url:
        cfg.base_url = flags.base_url
    if flags.api_key:
        cfg.api_key = flags.api_key
    if flags.skills_dirs:
        cfg.skills_dirs = [*cfg.skills_dirs, *flags.skills_dirs]

    if cfg.backend == "kimi" and not cfg.api_key:
        cfg.api_key = os.environ.get("MOONSHOT_API_KEY") or os.environ.get("KIMI_API_KEY") or ""
    if cfg.backend == "groq" and not cfg.api_key:
        cfg.api_key = os.environ.get("GROQ_API_KEY") or ""
    if cfg.backend == "openrouter" and not cfg.api_key:
        cfg.api_key = os.environ.get("OPENROUTER_API_KEY") or ""
    if cfg.backend == "deepseek" and not cfg.api_key:
        cfg.api_key = os.environ.get("DEEPSEEK_API_KEY") or ""
    if cfg.backend == "gemini" and not cfg.api_key:
        cfg.api_key = os.environ.get("GEMINI_API_KEY") or ""
    if cfg.backend == "anthropic" and not cfg.api_key:
        cfg.api_key = os.environ.get("ANTHROPIC_API_KEY") or ""

    cfg.mcp_servers = [s for s in cfg.mcp_servers if s.name not in BROWSER_MCP_NAMES]
    session_servers = session_mcp_servers(cfg.mcp_servers, flags.browser)
    if flags.browser:
        logger.info("browser MCP enabled for this session", {"source": "--browser"})

    try:
        client = llm_factory.new_from_config(cfg)
    except Exception as err:
        sys.stderr.write(f"{err}\n")
        return 1
    skills = SkillRegistry()
    all_skill_dirs = skill_search_dirs(cfg.skills_dirs)
    for d in all_skill_dirs:
        skills.load_dir(d)

    skills.set_disabled_names(cfg.disabled_skills)

    target = new_target()
    engagement_state = EngagementState()
    perm_holder: dict = {"publish": None}
    ask_holder: dict = {"publish": None}
    banner_holder = BannerHolder()
    bridged_perm = BridgedPrompter(
        lambda req: perm_holder["publish"] and perm_holder["publish"](req)
    )

    bridged_ask = BridgedAskPrompter(
        lambda req: ask_holder["publish"] and ask_holder["publish"](req)
    )
    prompter = YoloPrompter(
        bridged_perm,
        flags.yolo
    )
    findings_store = FindingsStore("findings")
    capture_store = CaptureStore(max_entries=5000)
    session_dir = session_store.dir_from_path("")
    session_store.cleanup_stale_temps(session_dir, 60_000)
    session_id = flags.resume_id
    resuming = False
    if not session_id:
        session_id = session_store.new_id()
    else:
        session_store.validate_id(session_id)
        resuming = True
    session_store_instance = session_store.Store.new_with_id(
        session_dir,
        session_id
    )
    session_debug = create_session_debug_log(
        SessionDebugOptions(
            enabled=flags.debug_session,
            path=flags.debug_session_path,
            session_id=session_id,
        )
    )
    if session_debug.enabled:
        session_debug.write(
            "session_start",
            {
                "version": VERSION,
                "argv": redacted_argv(sys.argv[1:]),
                "cwd": os.getcwd(),
                "resume": resuming,
                "backend": cfg.backend,
                "model": cfg.model,
                "base_url": cfg.base_url,
            },
        )
    sys.stderr.write(f"debug session log: {session_debug.path}\n")
    coverage_store = CoverageStore(f"findings/coverage-{session_id}.json")
    intelligence_store = IntelligenceStore()
    memory_store = MemoryStore()
    engagement = EngagementStore().load()
    workflow = WorkflowState()

    tools = ToolRegistry()
    tools.register(ShellTool())
    tools.register(BashTool())
    tools.register(FileReadTool())
    tools.register(FileReadToolAlias())
    tools.register(FileWriteTool())
    tools.register(FileWriteToolAlias())
    tools.register(FileEditTool())
    tools.register(FileEditToolAlias())
    tools.register(GlobTool())
    tools.register(GrepTool())
    tools.register(HTTPTool(target, engagement_state))
    tools.register(WebFetchTool(engagement_state, target))
    tools.register(WebSearchTool())
    tools.register(AskUserTool(bridged_ask))
    tools.register(
        ConfirmFindingTool(
            findings_store,
            lambda finding, path: capture_store.add_burp_issue(
                id=f"finding:{finding.slug}",
                title=finding.title,
                severity=finding.severity,
                confidence="Certain",
                url=finding.url,
                method=finding.method,
                parameter=finding.parameter,
                detail="\n".join(
                    [
                        finding.impact,
                        (
                            f"\nEvidence:\n{finding.responseExcerpt}"
                            if finding.responseExcerpt
                            else ""
                        ),
                        (
                            f"\nReproduce:\n{finding.curl}"
                            if finding.curl
                            else ""
                        ),
                    ]
                ),
                remediation=finding.remediation,
                path=path,
                raw_request_b64=base64.b64encode(
                    finding_request_for_burp(finding).encode("utf-8")
                ).decode("ascii"),
            ),
            workflow,
        )
    )
    tools.register(LoadSkillTool(skills))
    tools.register(ReadPayloadsTool(skills))
    tools.register(ReadSkillFileTool(skills))
    tools.register(CoverageTool(coverage_store))
    tools.register(WorkflowTool(workflow, target))

    for plugin in cfg.plugins:
        tools.register(CommandPluginTool(plugin))
    register_browser_capture_tools(
        tools.register,
        capture_store,
    )
    ingest_handle = None
    ingest_token = secrets.token_hex(16)

    def create_bridge(port: int) -> "IngestServerHandle":
        try:
            return start_ingest_server(
                IngestServerOptions(
                    store=capture_store,
                    port=port,
                    token=ingest_token,
                    on_event=lambda text: (
                        notice_holder.publish(text)
                        if getattr(notice_holder, "publish", None)
                        else None
                    ),
                )
            )
        except OSError as err:
            raise RuntimeError(
                f"Failed to bind port {port}: {err}\n"
                f"The port may already be in use (for example by another browser bridge).\n"
                f"Try `/burp <another-port>`."
            ) from err


    async def start_burp_bridge(port: int | None) -> BurpBridgeResult:
        nonlocal ingest_handle

        if ingest_handle is not None:
            if port is None or port == ingest_handle.port:
                return BurpBridgeResult(
                    status="already_running",
                    state=BurpBridgeState(
                        running=True,
                        port=ingest_handle.port,
                        url=ingest_handle.url,
                        token=ingest_handle.token,
                    ),
                )

            old_port = ingest_handle.port
            ingest_handle.close()
            ingest_handle = create_bridge(port)
            return BurpBridgeResult(
                status="restarted",
                state=BurpBridgeState(
                    running=True,
                    port=ingest_handle.port,
                    url=ingest_handle.url,
                    token=ingest_handle.token,
                ),
                old_port=old_port,
            )

        ingest_handle = create_bridge(port or BURP_DEFAULT_PORT)
        return BurpBridgeResult(
            status="started",
            state=BurpBridgeState(
                running=True,
                port=ingest_handle.port,
                url=ingest_handle.url,
                token=ingest_handle.token,
            ),
        )


    async def close_burp_bridge() -> BurpBridgeResult:
        nonlocal ingest_handle
        handle = ingest_handle

        if handle is None:
            return BurpBridgeResult(
                status="not_running",
                state=BurpBridgeState(running=False),
            )

        handle.close()
        old_port = handle.port
        ingest_handle = None
        return BurpBridgeResult(
            status="stopped",
            state=BurpBridgeState(running=False),
            old_port=old_port,
        )


    async def burp_bridge_status() -> BurpBridgeResult:
        handle = ingest_handle
        if handle is None:
            return BurpBridgeResult(
                status="not_running",
                state=BurpBridgeState(running=False),
            )
        return BurpBridgeResult(
            status="already_running",
            state=BurpBridgeState(
                running=True,
                port=handle.port,
                url=handle.url,
                token=handle.token,
            ),
        )

    if flags.burp:
        try:
            burp_start_result = await start_burp_bridge(flags.burp_port)
            logger.info(
                "burp bridge auto-started",
                {
                    "port": burp_start_result.state.port,
                    "status": burp_start_result.status,
                },
            )
        except Exception as err:
            sys.stderr.write(f"warning: failed to start burp bridge: {err}\n")

    mcp_results = await asyncio.gather(
        *(discover_mcp_tools(server) for server in session_servers),
        return_exceptions=True,
    )

    mcp_sessions: list[MCPSession] = []

    for server, result in zip(session_servers, mcp_results):
        if isinstance(result, Exception):
            print(f"mcp {server.name}: {result}", file=sys.stderr)
            continue

        result = cast(dict[str, Any], result)

        mcp_sessions.append(result["session"])

        for tool in result["tools"]:
            tools.register(tool)

    if flags.list_skills:
        for sk in skills.list():
            print(f"- {sk.name}")
            print(f"    {sk.description}")
            print(f"    ({sk.path})")

        await asyncio.gather(*(s.close() for s in mcp_sessions))
        await close_burp_bridge()
        return 0

    if flags.list_tools:
        for name in tools.names():
            tool = tools.get(name)
            gated = " [permission required]" if tool and tool.requires_permission() else ""
            print(f"- {name}{gated}")
            print(f"    {tool.description() if tool else ''}")

        await asyncio.gather(*(s.close() for s in mcp_sessions))
        await close_burp_bridge()
        return 0

    if cfg.tooling_profile is None:
        picked = await run_first_run_picker()

        if picked is None:
            await asyncio.gather(
                *(session.close() for session in mcp_sessions),
                return_exceptions=True,
            )

            await close_burp_bridge()

            print(
                "first-run setup cancelled — exiting.",
                file=sys.stderr,
            )
            return 0

        cfg.tooling_profile = picked

        try:
            await config.save(cfg)
        except Exception as err:
            print(
                f"warning: could not persist tooling_profile: {err}",
                file=sys.stderr,
            )
            
    opts = AgentOptions(
        client=client,
        tools=tools,
        skills=skills,
        prompter=prompter,
        store=session_store_instance,
        target=target,
        thinking_enabled=cfg.thinking_enabled,
        max_steps=(
            cfg.max_steps
            if cfg.max_steps > 0
            else 20
        ),
        auto_compact_threshold=effective_auto_compact_threshold(cfg),
        tooling_profile=cast(
            PromptToolingProfile,
            cfg.tooling_profile.value
            if cfg.tooling_profile is not None
            else None,
        ),
        prompt_profile=effective_prompt_profile(cfg),
        intelligence=intelligence_store,
        memory_store=memory_store,
        engagement=engagement,
        streaming_enabled=False if flags.no_stream else cfg.streaming_enabled,
        workflow=workflow,
        engagement_state=engagement_state,
    )

    agent = Agent(opts)
    resume_summary = ""

    def report_skill_validation() -> None:
        for skill_name, errors in skills.validation_errors(
            known_tools=set(tools.names()),
        ).items():
            logger.warn(
                "skill metadata validation failed",
                {
                    "skill": skill_name,
                    "errors": errors,
                },
            )

    report_skill_validation()

    if resuming:
        try:
            agent.resume_saved()

            resume_summary = build_resume_summary(
                session_id,
                agent.format_memory(),
            )

        except Exception as err:
            print(
                f"resume: {err}",
                file=sys.stderr,
            )
            return 1

    skill_dirs_to_watch = [d for d in all_skill_dirs if os.path.exists(d)]
    watchers: list[Any] = []
    reload_timer: asyncio.TimerHandle | None = None

    def trigger_reload() -> None:
        nonlocal reload_timer
        loop = asyncio.get_event_loop()

        if reload_timer is not None:
            reload_timer.cancel()

        def _do_reload() -> None:
            nonlocal reload_timer
            reload_timer = None
            try:
                skills.clear()
                for d in skill_dirs_to_watch:
                    skills.load_dir(d)
                skills.set_disabled_names(cfg.disabled_skills)
                report_skill_validation()
                agent.rebuild_from_skills()
                count = len(skills.list_enabled())
                if getattr(notice_holder, "publish", None):
                    notice_holder.publish(f"skills: reloaded ({count} enabled)")
                logger.info("skills reloaded", {"enabled": count, "total": len(skills.list())})
            except Exception as err:
                logger.warn("skills reload failed", {"err": str(err)})

        reload_timer = loop.call_later(0.25, _do_reload)
    def watch_dir(d: str) -> None:
        if d in watched_dirs or not os.path.exists(d):
            return
        watched_dirs.add(d)
        if (observer := fs_watch(d, loop, trigger_reload)) is not None:
            watchers.append(observer)

    for d in skill_dirs_to_watch:
        watch_dir(d)

    def on_skill_created(skill_root_dir: str) -> None:
        if skill_root_dir not in skill_dirs_to_watch:
            skill_dirs_to_watch.append(skill_root_dir)

        watch_dir(skill_root_dir)
        trigger_reload()

    banner_data = BannerData(
        provider=provider_label(cfg.backend),
        model=client.model() or cfg.model or "(unset)",
        endpoint=cfg.base_url or default_endpoint(cfg.backend),
        state=locality_for(cfg.backend),
        status=f"Session {session_id[:8]} — type /help to begin",
        cwd=pretty_cwd(),
        tool_support="probing",
    )
    async def run_probes(signal: asyncio.Event) -> None:
        if banner_holder.publish is not None:
            banner_holder.publish(
                {
                    "tool_support": "probing",
                    "context_window": None,
                }
            )
        backend = cfg.backend if isinstance(cfg.backend, Backend) else Backend(cfg.backend)
        warning = model_reliability_warning(backend, agent.client.model())

        if warning:
            print(warning, file=sys.stderr)
            notice_holder.publish(warning)

        result = await probe_tool_support(
            agent.client,
            signal,
        )

        if banner_holder.publish is not None:
            banner_holder.publish(
                {
                    "tool_support": result.tool_support,
                }
            )

        if result.tool_support == "no" and result.detail:
            print(
                f"⚠ model {agent.client.model()}: {result.detail}",
                file=sys.stderr,
            )

    async def persist_disabled_skills(names: list[str]) -> None:
        cfg.disabled_skills = sorted(names)
        await config.save(cfg)

    async def apply_provider(change: ProviderChange) -> None:
        cfg.backend = change.backend
        cfg.model = change.model

        if change.base_url is not None:
            cfg.base_url = change.base_url

        if change.api_key is not None:
            cfg.api_key = change.api_key

        next_client = llm_factory.new_from_config(cfg)

        agent.set_client(next_client)

        agent.set_auto_compact_threshold(
            effective_auto_compact_threshold(cfg)
        )

        agent.set_prompt_profile(
            effective_prompt_profile(cfg)
        )

        await config.save(cfg)

        if banner_holder.publish is not None:
            banner_holder.publish(
                {
                    "provider": provider_label(cfg.backend),
                    "model": (
                        next_client.model()
                        or cfg.model
                        or "(unset)"
                    ),
                    "endpoint": (
                        cfg.base_url
                        or default_endpoint(cfg.backend)
                    ),
                    "state": locality_for(cfg.backend),
                }
            )

        _spawn_reporting(run_probes(root_ctl), "probe")

    async def update_provider_api_key(provider: str, api_key: str) -> None:
        cfg.api_keys[provider] = api_key
        await config.save(cfg)

    async def test_connection() -> None:
        ping = getattr(agent.client, "ping", None)
        if not callable(ping):
            raise RuntimeError("current provider does not support ping")

        result = ping()
        if inspect.isawaitable(result):
            await result
    
    _spawn_reporting(run_probes(root_ctl), "probe")

    app = KAgent(
        AppProps(
            agent=agent,
            banner_data=banner_data,
            parent_signal=root_ctl,
            yolo_initial=flags.yolo,

            bind_perm_publisher=lambda publish:
                perm_holder.update({"publish": publish}),

            bind_ask_publisher=lambda publish:
                ask_holder.update({"publish": publish}),

            bind_banner_publisher=lambda publish:
                setattr(banner_holder, "publish", publish),

            bind_notice_publisher=lambda publish:
                notice_holder.bind(publish),

            resume_summary=resume_summary,

            session_debug=session_debug,

            set_yolo=(
                lambda on: prompter.set_yolo(on)
                if hasattr(prompter, "set_yolo")
                else None
            ),

            on_skill_created=on_skill_created,

            read_config=lambda: {
                "backend": Backend(cfg.backend),
                "base_url": cfg.base_url,
                "api_key": cfg.api_key,
                "api_keys": dict(cfg.api_keys),
                "model": cfg.model,
            },

            persist_disabled_skills=persist_disabled_skills,

            apply_provider=apply_provider,
            update_provider_api_key=update_provider_api_key,
            test_connection=test_connection,

            start_burp_bridge=start_burp_bridge,
            close_burp_bridge=close_burp_bridge,
            burp_bridge_status=burp_bridge_status,
        )
    )
    try:
        await app.run_async()
    finally:
        await close_runtime_resources(
            root_ctl,
            reload_timer,
            watchers,
            mcp_sessions,
            close_burp_bridge,
        )

    return 0

def pretty_cwd() -> str:
    cwd = str(Path.cwd())
    home = str(Path.home())

    if home and cwd.startswith(home):
        return f"~{cwd[len(home):]}"

    return cwd

def provider_label(backend: str) -> str:
    match backend:
        case "":
            return "DeepSeek"
        case "openai-compat":
            return "OpenAI-compatible"
        case "kimi":
            return "Kimi"
        case "groq":
            return "Groq"
        case "openrouter":
            return "OpenRouter"
        case "deepseek":
            return "DeepSeek"
        case "gemini":
            return "Gemini"
        case _:
            return backend

def default_endpoint(backend: str) -> str:
    match backend:
        case "" | "deepseek":
            return DEEPSEEK_DEFAULT_BASE_URL
        case "kimi":
            return KIMI_DEFAULT_BASE_URL
        case "groq":
            return GROQ_DEFAULT_BASE_URL
        case "openrouter":
            return OPENROUTER_DEFAULT_BASE_URL
        case "gemini":
            return GEMINI_DEFAULT_BASE_URL
        case _:
            return ""

def locality_for(backend: str) -> str:
    if backend in (
        "openai-compat",
        "kimi",
        "groq",
        "openrouter",
        "deepseek",
        "gemini",
    ):
        return "remote"

    return "local"
      
async def run_first_run_picker() -> ToolingProfile | None:

    picked: ToolingProfile | None = None
    finished = asyncio.Event()

    def on_pick(profile: ToolingProfile) -> None:
        nonlocal picked
        picked = profile
        finished.set()

    def on_cancel() -> None:
        nonlocal picked
        picked = None
        finished.set()

    def exit_app() -> None:
        finished.set()

    picker = FirstRunPicker(
        FirstRunPickerRequest(
            on_pick=on_pick,
            on_cancel=on_cancel,
            exit_app=exit_app,
        )
    )

    while not finished.is_set():

        print("\033[2J\033[H", end="") 

        print(
            "\n".join(
                picker.render()
            )
        )

        key = await asyncio.to_thread(
            input,
            "\n↑↓ select · Enter pick · Esc cancel: "
        )

        key = key.strip().lower()

        if key in ("up", "w"):
            picker.handle_key("up")

        elif key in ("down", "s"):
            picker.handle_key("down")

        elif key in ("", "enter"):
            picker.handle_key("enter")

        elif key in ("esc", "escape", "q"):
            picker.handle_key("escape")

    return picked

def build_resume_summary(
    session_id: str,
    memory: str,
) -> str:
    return "\n".join(
        [
            f"Resumed session {session_id}",
            "",
            "Previous session recap:",
            "",
            memory,
        ]
    )

def fs_watch(path: str, loop: asyncio.AbstractEventLoop, callback: Callable[[], None]) -> Any | None:
    class _Handler(FileSystemEventHandler):
        def on_any_event(self, event) -> None:
            loop.call_soon_threadsafe(callback)

    handler = _Handler()
    for recursive in (True, False):
        try:
            observer = Observer()
            observer.schedule(handler, path, recursive=recursive)
            observer.start()
            return observer
        except Exception as err:
            logger.debug(
                "skills: watch attempt failed",
                {"path": path, "recursive": recursive, "err": str(err)},
            )

    logger.warn(
        "skills: cannot watch directory; edits there will not hot-reload",
        {"path": path},
    )
    return None


def effective_auto_compact_threshold(cfg: config.Config) -> int:
    if cfg.backend == "groq":
        if cfg.auto_compact_threshold <= 0:
            return GROQ_AUTO_COMPACT_THRESHOLD

        return min(
            cfg.auto_compact_threshold,
            GROQ_AUTO_COMPACT_THRESHOLD,
        )
    
    if (
        cfg.backend == "kimi"
        and cfg.auto_compact_threshold
        == config.DEFAULT_AUTO_COMPACT_THRESHOLD
    ):
        kimi_threshold = kimi_auto_compact_threshold(
            cfg.model
        )

        if kimi_threshold is not None:
            return kimi_threshold

    return cfg.auto_compact_threshold

def effective_prompt_profile(
    cfg: config.Config,
) -> PromptProfile:

    if (
        cfg.backend == "groq"
        or cfg.backend == "gemini"
    ):
        return "compact"

    return "full"

def print_help() -> None:
    sys.stdout.write(
        f"""kagent {VERSION}

Usage:
  kagent [flags]

Flags:
  --backend |openai-compat|kimi|groq|openrouter|deepseek|gemini
  --model <id>
  --base-url <url>
  --api-key <key>
  --skills <dirs>            comma-separated extra skill directories
  --resume <session-id>
  --browser                  enable Browser MCP for this session only (not persisted)
  --burp [port]              start local Burp/KAgent bridge (default :8888)
  --browser-ingest [port]    deprecated alias for --burp
  --no-stream                disable streaming chat (fallback for backends
                             whose SSE/ND-JSON path drops tool_calls)
  --yolo                     YOLO mode: auto-approve non-sensitive tool calls
                             (alias: --dangerously-skip-permissions)
  --list-skills / --list-tools
  --log <path>
  --debug-session             write a complete JSONL session debug log
  --debug-session-path <p>  custom path for --debug-session
  --version / --help

In the TUI: Enter send · Esc cancel turn · Ctrl-C quit · mouse-wheel scroll
Slash: /help /plan /clear /reset /exit /target /maxsteps /thinking 
"""
    )

def emit(event: dict) -> None:
    event_type = event.get("type")
 
    if event_type == "assistant-text":
        text = event.get("text", "")
        if text:
            print(f"\n{text}")
 
    elif event_type == "assistant-delta":
        print(event.get("text", ""), end="", flush=True)
 
    elif event_type == "tool-call":
        name = event.get("name", "?")
        args = event.get("args", {})
        tool_id = event.get("id", "")[:8]
 
        print()
        print(_hr())
        print(f"{BOLD(CYAN('▶ TOOL CALL'))}  {BOLD(name)}  {DIM(f'#{tool_id}')}")
        if args:
            pretty = _pretty_args(args)
            for line in pretty.splitlines():
                print(f"  {DIM(line)}")
 
    elif event_type == "tool-result":
        name = event.get("name", "?")
        result = event.get("result", "")
        err = event.get("err", "")
        duration = event.get("duration_ms")
 
        status = RED("✖ FAILED") if err else GREEN("✔ RESULT")
        meta = f"  {DIM(f'{duration}ms')}" if duration is not None else ""
        print(f"{BOLD(status)}  {BOLD(name)}{meta}")
 
        if err:
            print(f"  {RED(_truncate(err))}")
        elif result:
            wrapped = _truncate(result, limit=800)
            for line in wrapped.splitlines():
                print(f"  {line}")
        print(_hr())
 
    elif event_type == "decision":
        summary = event.get("summary", "")
        print(f"\n{MAGENTA('◆ DECISION')}  {summary}")
 
    elif event_type == "skill-active":
        name = event.get("name", "?")
        print(f"\n{BLUE('◈ SKILL ACTIVE')}  {BOLD(name)}")
 
    elif event_type == "error":
        err = event.get("err", "")
        print(f"\n{RED(BOLD('✖ ERROR'))}  {RED(str(err))}")
 
    elif event_type == "done":
        print()
 
    else:
        print(f"\n{YELLOW('? UNKNOWN EVENT')}  {DIM(str(event))}")
 
def _term_width(default: int = 100) -> int:
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return default
 
 
def _truncate(text: str, limit: int = 500) -> str:
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + GRAY(f"\n… (+{len(text) - limit} ký tự, đã cắt bớt)")
 
 
def _pretty_args(args) -> str:
    try:
        return json.dumps(args, ensure_ascii=False, indent=2)
    except Exception:
        return str(args)
 
 
def _hr(char: str = "─") -> str:
    return GRAY(char * min(_term_width(), 80))


def cli_main() -> int:
    return asyncio.run(main())

if __name__ == "__main__":
    import sys
    sys.exit(cli_main())
