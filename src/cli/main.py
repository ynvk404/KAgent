from __future__ import annotations

# ==========================================================
# Thư viện chuẩn
# ==========================================================
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
# ==========================================================
# Phiên bản / Cấu hình / Ghi log
# ==========================================================
from src.version.version import VERSION, describe

from src.config import config
from src.config.config import ToolingProfile, Backend

from src.logger import logger
from src.logger.session_debug import (
    create_session_debug_log,
    SessionDebugOptions,
)

# ==========================================================
# Mục tiêu (Target)
# ==========================================================

from src.target.target import new_target

# ==========================================================
# Agent Core
# ==========================================================

from src.agent.agent import Agent, AgentOptions
from src.agent.system_prompt import PromptToolingProfile, PromptProfile
from src.permission.permission import AlwaysAllow
from src.permission.permission import YoloPrompter


# ==========================================================
# Mô hình ngôn ngữ (LLM)
# ==========================================================

from src.llm import factory as llm_factory
from src.llm.model_warnings import model_reliability_warning
from src.llm.probe import probe_tool_support
from src.llm.providers import *


# ==========================================================
# Bộ nhớ / Lưu trữ
# ==========================================================

from src.memory.store import MemoryStore
from src.coverage.store import CoverageStore
from src.engagement.store import EngagementStore
from src.intelligence.store import IntelligenceStore

from src.findings.store import Store as FindingsStore
from src.findings.http_request import finding_request_for_burp

from src.session import store as session_store


# ==========================================================
# Kỹ năng (Skills)
# ==========================================================

from src.skills.discovery import skill_search_dirs
from src.skills.load_skill import LoadSkillTool
from src.skills.registry import Registry as SkillRegistry


# ==========================================================
# Công cụ (Tools)
# ==========================================================

from src.tools.plugin import CommandPluginTool
from src.tools.finding import ConfirmFindingTool
from src.tools.registry import Registry as ToolRegistry

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


# ==========================================================
# Giao thức MCP
# ==========================================================

from src.tools.mcp_server import (
    BROWSER_MCP_NAMES,
    session_mcp_servers,
)

from src.tools.mcp_integration import (
    MCPServerConfig,
    MCPSession,
    discover_mcp_tools,
)


# ==========================================================
# Bắt dữ liệu Trình duyệt
# ==========================================================

from src.browser.store import CaptureStore

from src.tools.browser_capture import (
    register_browser_capture_tools,
)

from src.browser.server import (
    start_ingest_server,
    IngestServerOptions,
)


# ==========================================================
# Giao diện người dùng (UI)
# ==========================================================

from src.ui.core.app import (
    Pentestagent,
    AppProps,
    ConfigSnapshot,
    ProviderChange,
    BurpBridgeInfo,
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
 
 
# ==========================================================
# Môi trường thực thi (Runtime)
# ==========================================================

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
    burp_port: int = 0  # Cổng mặc định 8080 nếu dùng TS parser
    no_stream: bool = False
    log_path: str = ""
    debug_session: bool = False
    debug_session_path: str = ""
    list_skills: bool = False
    list_tools: bool = False

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
        burp_port=9999,
        debug_session=os.getenv("PENTESTAGENT_DEBUG_SESSION") == "1",
        debug_session_path=os.getenv("PENTESTAGENT_DEBUG_SESSION_PATH", ""),
    )

    i = 0

    def next_arg() -> str:
        nonlocal i
        i += 1
        return argv[i] if i < len(argv) else ""

    while i < len(argv):
        a = argv[i]

        if a in ("--version", "-v"):
            out.show_version = True
        elif a in ("--help", "-h"):
            out.show_help = True
        elif a == "--backend":
            out.backend = next_arg()
        elif a == "--model":
            out.model = next_arg()
        elif a == "--base-url":
            out.base_url = next_arg()
        elif a == "--api-key":
            out.api_key = next_arg()
        elif a == "--skills":
            out.skills_dirs = [
                s.strip() for s in next_arg().split(",") if s.strip()
            ]
        elif a == "--resume":
            out.resume_id = next_arg()
        elif a in ("--yolo", "--dangerously-skip-permissions"):
            # Tên cũ là --dangerously-skip-permissions, giữ làm alias hỗ trợ script cũ. Đều là chế độ YOLO.
            out.yolo = True
        elif a == "--browser":
            out.browser = True
        elif a == "--no-stream":
            out.no_stream = True
        elif a in ("--burp", "--browser-ingest"):
            out.burp = True
            # Nhận cổng tuỳ chọn: --burp 9999. Nếu tham số tiếp theo bắt đầu bằng '--' hoặc thiếu thì dùng mặc định.
            peek = argv[i + 1] if i + 1 < len(argv) else None
            if peek is not None and not peek.startswith("--"):
                try:
                    n = int(peek, 10)
                except ValueError:
                    n = None
                if n is not None and 0 < n < 65536:
                    out.burp_port = n
                    i += 1
        elif a == "--log":
            out.log_path = next_arg()
        elif a == "--debug-session":
            out.debug_session = True
        elif a == "--debug-session-path":
            out.debug_session = True
            out.debug_session_path = next_arg()
        elif a == "--list-skills":
            out.list_skills = True
        elif a == "--list-tools":
            out.list_tools = True

        i += 1

    return out

async def main() -> int:
    flags = parse_flags(sys.argv[1:])
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

    loop = asyncio.get_running_loop()
    for sig, name in ((signal.SIGINT, "SIGINT"), (signal.SIGTERM, "SIGTERM"), (signal.SIGHUP, "SIGHUP")):
        loop.add_signal_handler(sig, lambda n=name: on_sig(n))

    # Đọc cấu hình
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

    # Client LLM
    try:
        print("DEBUG backend:", cfg.backend)
        print("DEBUG model:", cfg.model)
        print("DEBUG key:", cfg.api_key[:10] if cfg.api_key else "EMPTY")
        client = llm_factory.new_from_config(cfg)
    except Exception as err:
        sys.stderr.write(f"{err}\n")
        return 1
    # Tải kỹ năng mặc định, dự án và người dùng
    skills = SkillRegistry()
    all_skill_dirs = skill_search_dirs(cfg.skills_dirs)
    for d in all_skill_dirs:
        skills.load_dir(d)

    # Tắt kỹ năng được thiết lập trong cấu hình
    skills.set_disabled_names(cfg.disabled_skills)

    # Mục tiêu đánh giá — dùng chung cho công cụ HTTP + Prompt hệ thống
    target = new_target()
    perm_holder: dict = {"publish": None}
    ask_holder: dict = {"publish": None}
    banner_holder = BannerHolder()
    bridged_perm = BridgedPrompter(
        lambda req: perm_holder["publish"] and perm_holder["publish"](req)
    )

    bridged_ask = BridgedAskPrompter(
        lambda req: ask_holder["publish"] and ask_holder["publish"](req)
    )
    # prompter = YoloPrompter(bridged_perm, flags.yolo)
    # if flags.yolo:
    #     sys.stderr.write(
    #         "⚠  YOLO mode active: every tool call will auto-approve. Authorized engagements / lab targets only.\n"
    #     )
    prompter = YoloPrompter(
        bridged_perm,
        flags.yolo
    )
    # Lưu trữ lỗ hổng + thông báo
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
                "argv": sys.argv[1:],
                "cwd": os.getcwd(),
                "resume": resuming,
                "backend": cfg.backend,
                "model": cfg.model,
                "base_url": cfg.base_url,
            },
        )
    sys.stderr.write(f"debug session log: {session_debug.path}\n")
    # Theo dõi các mục tiêu đã kiểm thử để khôi phục phiên
    coverage_store = CoverageStore(f"findings/coverage-{session_id}.json")

    # Lưu thông tin thu thập được khi pentest
    intelligence_store = IntelligenceStore()

    # Lưu bộ nhớ dài hạn của agent
    memory_store = MemoryStore()

    # Tải phạm vi và quy tắc đánh giá
    engagement = EngagementStore().load()
    # Các công cụ
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

    tools.register(HTTPTool(target))

    tools.register(WebFetchTool())
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
        )
    )
    tools.register(LoadSkillTool(skills))
    tools.register(ReadPayloadsTool(skills))
    tools.register(ReadSkillFileTool(skills))
    tools.register(CoverageTool(coverage_store))

    for plugin in cfg.plugins:
        tools.register(CommandPluginTool(plugin))
    register_browser_capture_tools(
        tools.register,
        capture_store,
    )
    ingest_handle = None
    ingest_token = secrets.token_hex(16)

    async def start_burp_bridge(
        port: int | None,
    ) -> BurpBridgeInfo:
        global ingest_handle

        # Nếu không truyền port thì dùng mặc định
        actual_port = port or 9999

        # Đã chạy sẵn
        if ingest_handle is not None:
            return {
                "url": ingest_handle.url,
                "token": ingest_handle.token,
                "already_running": True,
            }

        ingest_handle = start_ingest_server(
            IngestServerOptions(
                store=capture_store,
                port=actual_port,
                token=ingest_token,
                on_event=lambda text: (
                    notice_holder.publish(text)
                    if getattr(notice_holder, "publish", None)
                    else None
                ),
            )
        )

        return {
            "url": ingest_handle.url,
            "token": ingest_handle.token,
            "already_running": False,
        }
    
    async def close_burp_bridge() -> None:
        global ingest_handle

        handle = ingest_handle

        if handle is not None:
            handle.close()
            ingest_handle = None
    if flags.burp:
        try:
            result = await start_burp_bridge(flags.burp_port)

            sys.stderr.write(
                f"pentestagent Burp bridge listening at "
                f"{result['url']}\n"
                f"pentestagent Burp bridge token: "
                f"{result['token']}\n"
                "Set both values in the Burp plugin.\n"
            )

        except Exception as err:
            sys.stderr.write(
                f"warning: --burp failed to start on "
                f":{flags.burp_port}: {err}\n"
            )
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
    # Thiết lập lần đầu.
    # Hỏi đúng một lần trước khi tạo agent để áp dụng cấu hình công cụ vào prompt hệ thống.

    if cfg.tooling_profile is None:
        picked = await run_first_run_picker()

        if picked is None:
            # Đóng các phiên MCP
            await asyncio.gather(
                *(session.close() for session in mcp_sessions),
                return_exceptions=True,
            )

            # Đóng cầu nối Burp
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
    # Tạo đối tượng cấu hình opts
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
    )

    # Truyền opts vào Agent
    agent = Agent(opts)
    resume_summary = ""

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

    # Live skill reload
    skill_dirs_to_watch = [
        d for d in all_skill_dirs
        if Path(d).exists()
    ]
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
                # Persisted disabled state stays — only what's on disk changes.
                skills.set_disabled_names(cfg.disabled_skills)
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

        #ollama context
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

        asyncio.create_task(
            run_probes(root_ctl)
        )
    
    probe_task = asyncio.create_task(
        run_probes(root_ctl)
    )

    app = Pentestagent(
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
                "model": cfg.model,
            },

            persist_disabled_skills=persist_disabled_skills,

            apply_provider=apply_provider,

            start_burp_bridge=start_burp_bridge,
        )
    )
    await app.run_async()
    return 0


# ============================================================
# Helpers
# ============================================================

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
    """
    Chuyển thể từ hàm TS runFirstRunPicker().

    Hiển thị giao diện chọn thiết lập lần đầu,
    trả về ToolingProfile nếu người dùng chọn,
    None nếu hủy.
    """

    picked: ToolingProfile | None = None
    finished = asyncio.Event()

    def on_pick(profile: ToolingProfile) -> None:
        nonlocal picked

        picked = profile

        # Tương đương: inkApp.unmount()

        finished.set()

    def on_cancel() -> None:
        nonlocal picked

        picked = None

        # Tương đương: inkApp.unmount()

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

    # Tương đương:
    # const inkApp = render(tree)
    # Python chưa có thư viện Ink nên dùng vòng lặp terminal.

    while not finished.is_set():

        print("\033[2J\033[H", end="")  # Xóa màn hình terminal

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
    """Start a watchdog Observer on `path` that calls `callback()` on the
    event loop thread whenever anything changes. Tries recursive watching
    first; falls back to shallow if unsupported. Returns None on failure
    (best-effort — a watcher failure shouldn't block startup)."""

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
        except Exception:
            continue
    return None


def effective_auto_compact_threshold(cfg: config.Config) -> int:
    """
    Xác định ngưỡng tự động nén ngữ cảnh theo backend/mô hình.

    Tương đương TS: effectiveAutoCompactThreshold()
    """

    # Groq có ngữ cảnh nhỏ hơn nên giới hạn ngưỡng nén
    if cfg.backend == "groq":
        if cfg.auto_compact_threshold <= 0:
            return GROQ_AUTO_COMPACT_THRESHOLD

        return min(
            cfg.auto_compact_threshold,
            GROQ_AUTO_COMPACT_THRESHOLD,
        )

    # Kimi K2.x có ngữ cảnh lớn (256K)
    # Nếu chưa tùy chỉnh thì dùng ngưỡng mặc định theo mô hình
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
    """
    Groq/Gemini dùng prompt rút gọn (compact).
    Các backend khác dùng prompt đầy đủ (full).
    """

    if (
        cfg.backend == "groq"
        or cfg.backend == "gemini"
    ):
        return "compact"

    return "full"

def print_help() -> None:
    sys.stdout.write(
        f"""pentestagent {VERSION}

Usage:
  pentestagent [flags]

Flags:
  --backend |openai-compat|kimi|groq|openrouter|deepseek|gemini
  --model <id>
  --base-url <url>
  --api-key <key>
  --skills <dirs>            comma-separated extra skill directories
  --resume <session-id>
  --browser                  enable Browser MCP for this session only (not persisted)
  --burp [port]              start local Burp/Pentestagent bridge (default :9999)
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
 
    # ---------------- assistant text ----------------
 
    if event_type == "assistant-text":
        text = event.get("text", "")
        if text:
            print(f"\n{text}")
 
    elif event_type == "assistant-delta":
        print(event.get("text", ""), end="", flush=True)
 
    # ---------------- tool call / result ----------------
 
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
 
    # ---------------- planner decision ----------------
 
    elif event_type == "decision":
        summary = event.get("summary", "")
        print(f"\n{MAGENTA('◆ DECISION')}  {summary}")
 
    # ---------------- skill loaded / active ----------------
 
    elif event_type == "skill-active":
        name = event.get("name", "?")
        print(f"\n{BLUE('◈ SKILL ACTIVE')}  {BOLD(name)}")
 
    # ---------------- error ----------------
 
    elif event_type == "error":
        err = event.get("err", "")
        print(f"\n{RED(BOLD('✖ ERROR'))}  {RED(str(err))}")
 
    # ---------------- turn done ----------------
 
    elif event_type == "done":
        print()
 
    # ---------------- fallback: event lạ / chưa xử lý ----------------
 
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


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())