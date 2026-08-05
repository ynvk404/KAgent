from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from src.agent.agent import DEFAULT_MAX_STEPS, AgentRunOptions
from src.llm.models import list_models
from src.ui.commands.slash_items import SLASH_ITEMS
from src.ui.core.state import Append, Clear, TranscriptEntry

if TYPE_CHECKING:
    from src.agent.agent import Agent
    from src.ui.core.app import KAgent, RunAgentOptions

DEFAULT_THINKING_ENABLED = False
DEFAULT_YOLO_ENABLED = False
_DOMAIN_LABEL_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


_KEYBINDINGS: list[tuple[str, str]] = [
    ("@<file>", "inline a file into the next turn (Tab opens a picker)"),
    (
        "#<text>",
        "remember a durable fact (#!<text> = personal); recalled automatically",
    ),
    ("/", "open the slash-command menu"),
    (
        "↑ / ↓",
        "walk session prompt history (on first / last line of input)",
    ),
    ("Ctrl-N / Ctrl-J", "insert a newline inside the input"),
    ("Ctrl-A / Ctrl-E", "jump to start / end of the current line"),
    ("Ctrl-O", "reprint the latest truncated tool output in full"),
    ("Ctrl-F", "cycle the transcript filter"),
    (
        "mouse wheel / scrollbar",
        "scroll the conversation (native terminal scrollback)",
    ),
    (
        "Esc",
        "cancel an in-flight turn / clear the input draft",
    ),
    ("Ctrl-C", "quit kagent"),
]


_TIPS: list[str] = [
    "browser_capture_* tools surface live request / cookie / storage data once Burp/browser traffic is forwarding to a --burp bridge.",
    "coverage(action=\"untested\", candidates=[...], vuln_classes=[...]) returns the (endpoint, param, class) tuples you have NOT tested yet — drive the next pass off of it.",
    "read_payloads(skill=\"<name>\") pulls curated wordlists from disk. Skills like ssti / jwt ship pre-canned payload files in their payloads/ directory.",
    "Disabled skills are hidden from the agent's system prompt entirely. Use /skills to flip a skill back on without restarting.",
    "/model list opens an interactive backend model picker; /model <id> validates against the live catalog and suggests the closest match on typo.",
    "/memory intel stats shows learned background scenarios count; /memory intel clear wipes them (project/personal/all). Intelligence is auto-pruned but grows to the cap on long engagements.",
]



def build_help_text(agent: "Agent", read_config) -> str:
    cfg = read_config()

    enabled = len(agent.skills.list_enabled())
    total = len(agent.skills.list())
    target = agent.target.base_url() or "(none — engagement unset)"
    provider = cfg.get("backend") or "ollama"
    model = cfg.get("model") or agent.client.model() or "(unset)"
    memory = agent.get_memory_stats()

    out: list[str] = []

    out.append("kagent — quick reference")
    out.append("─" * 60)
    out.append("")

    out.append("Session")
    out.append(f"  provider   {provider}")
    out.append(f"  model      {model}")
    out.append(f"  target     {target}")
    out.append(
        f"  limits     max-steps {agent.get_max_steps()}"
        f"  ·  auto-compact {agent.get_auto_compact_threshold()} tok"
        f"  ·  thinking {'on' if agent.thinking_is_enabled() else 'off'}"
    )
    out.append(f"  skills     {enabled}/{total} enabled")
    out.append(
        f"  memory     {memory.items} items"
        f"  ·  compactions {memory.compactions}"
    )
    out.append("")

    out.append("Slash commands")
    namelines = [f"{s.name} {s.args}" if s.args else s.name for s in SLASH_ITEMS]
    w = min(36, (max((len(n) for n in namelines), default=0)) + 2)
    for name_line, item in zip(namelines, SLASH_ITEMS):
        out.append(f"  {name_line.ljust(w)}{item.description}")
    out.append("")

    out.append("Input & navigation")
    kw = max((len(k) for k, _ in _KEYBINDINGS), default=0) + 2
    for keys, desc in _KEYBINDINGS:
        out.append(f"  {keys.ljust(kw)}{desc}")
    out.append("")

    out.append("Tips")
    for tip in _TIPS:
        words = tip.split(" ")
        line = "  • "
        for word in words:
            if len(line) + len(word) + 1 > 88:
                out.append(line.rstrip())
                line = "    "
            line += f"{word} "
        if line.strip():
            out.append(line.rstrip())
    out.append("")
    out.append("Type / for the live command menu.")

    return "\n".join(out)


def normalize_target_url(raw: str) -> str | None:
    candidate = raw.strip()
    if not candidate or any(ch.isspace() for ch in candidate):
        return None

    if not (candidate.startswith("http://") or candidate.startswith("https://")):
        candidate = f"http://{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    try:
        host = parsed.hostname
        _ = parsed.port
    except ValueError:
        return None

    if not host:
        return None

    if host == "localhost":
        return candidate

    try:
        ipaddress.ip_address(host)
        return candidate
    except ValueError:
        pass

    labels = host.split(".")
    if len(labels) < 2:
        return None

    if all(_DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        return candidate

    return None


def build_plan_prompt(objective: str) -> str:
    subject = (
        f"Plan this objective:\n\n{objective}"
        if objective
        else "Create a plan for the current objective using the existing conversation context."
    )

    return f"""{subject}

You are in plan-only mode for this turn.

Rules:
- Do not call tools, run commands, fetch URLs, scan targets, or modify files.
- Reason from the conversation context and the user's objective only.
- If important product, scope, safety, or implementation details are missing, ask concise clarifying questions instead of inventing details.
- If the intent is clear enough, produce a decision-complete implementation plan that another engineer or agent can execute without making major choices.
- Keep the plan concise and practical.

When you are ready to finalize, return the plan wrapped exactly in:
<proposed_plan>
...
</proposed_plan>

Use Markdown inside the block. Prefer these sections: Summary, Key Changes, Test Plan, Assumptions."""


def build_coverage_next_prompt(objective: str, coverage_context: str) -> str:
    subject = (
        f"Objective for next steps:\n\n{objective}"
        if objective
        else "Objective for next steps: choose the highest-value tests to run next from the current engagement context."
    )

    return f"""{subject}

You are in coverage-driven planning mode for this turn.

Coverage state:
{coverage_context}

Rules:
- Do not call tools, run commands, fetch URLs, scan targets, or modify files.
- Use the coverage state before suggesting any test.
- Prioritize endpoint/parameter/vulnerability-class combinations that are not already covered.
- Treat passed, failed, skipped, waf-blocked, and tried entries as already covered unless retesting is explicitly justified.
- If there are no candidates in coverage, tell the user what candidate inventory is missing and how to collect it.
- Output 5 to 10 concrete next tests with endpoint, parameter, vuln class, why it is next, and the exact coverage mark to record after testing.
- Keep it concise and actionable."""


def suggest_closest(target: str, known: list[str]) -> str | None:
    needle = target.lower()
    best_name: str | None = None
    best_score = -1

    for cand in known:
        lower = cand.lower()
        score = 0

        pref_len = min(len(needle), len(lower))
        for i in range(pref_len):
            if needle[i] != lower[i]:
                break
            score += 2

        if lower in needle or needle in lower:
            score += 5

        if score > best_score:
            best_name = cand
            best_score = score

    return best_name if best_name is not None and best_score >= 4 else None


def handle_slash(app: "KAgent", raw: str) -> bool:
    parts = raw.strip().split()
    if not parts:
        return False

    cmd, *rest = parts

    agent = app.agent
    dispatch = app.dispatch

    if cmd in ("/exit", "/quit"):
        app.exit()
        return True

    if cmd == "/yolo":
        if not rest:
            current = "on" if app.state.yolo else "off"
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=f"yolo currently {current}",
                    )
                )
            )
            return True

        arg = rest[0].lower()
        if arg not in ("on", "off", "default"):
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text="usage: /yolo <on|off|default>",
                    )
                )
            )
            return True

        next_state = DEFAULT_YOLO_ENABLED if arg == "default" else arg == "on"
        app.apply_yolo(next_state)

        if arg == "default":
            text = "YOLO reset to default (off)"
        elif next_state:
            text = (
                "YOLO enabled. Tool calls will be auto-approved. "
                "Authorized / lab targets only."
            )
        else:
            text = "YOLO disabled. Tool calls will prompt for confirmation."

        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="system",
                    text=text,
                )
            )
        )
        return True

    if cmd == "/clear":
        dispatch(Clear())
        return True

    if cmd == "/reset":
        async def _reset():
            await agent.reset()

        asyncio.create_task(_reset())
        dispatch(Clear())
        dispatch(Append(entry=TranscriptEntry(kind="system", text="conversation reset")))
        return True

    if cmd == "/help":
        dispatch(
            Append(
                entry=TranscriptEntry(kind="system", text=build_help_text(agent, app.read_config))
            )
        )
        return True

    if cmd == "/memory":
        asyncio.create_task(_handle_memory(agent, rest, dispatch))
        return True


    if cmd == "/snapshot":
        async def _snapshot():
            try:
                path = await agent.save_context_snapshot("manual /snapshot")
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="system",
                            text=(f"context snapshot saved: {path}" if path else "no session store configured"),
                        )
                    )
                )
            except Exception as err:
                dispatch(Append(entry=TranscriptEntry(kind="error", text=f"/snapshot: {err}")))

        asyncio.create_task(_snapshot())
        return True

    if cmd == "/burp":
        bridge = app.start_burp_bridge
        stop_bridge = app.close_burp_bridge
        status_bridge = app.burp_bridge_status

        if bridge is None or stop_bridge is None or status_bridge is None:
            dispatch(
                Append( 
                    entry=TranscriptEntry(
                        kind="error",
                        text="/burp is unavailable in this runtime.",
                    )
                )
            )
            return True

        sub = rest[0] if rest else ""

        if sub == "status":
            async def _status():
                r = await status_bridge()
                if r.status == "not_running":
                    text = "Burp bridge: not running."
                else:
                    text = (
                        f"Burp bridge: running at {r.state.url} (port {r.state.port})\n"
                        f"Token: {r.state.token}"
                    )
                dispatch(Append(entry=TranscriptEntry(kind="system", text=text)))

            asyncio.create_task(_status())
            return True

        if sub == "stop":
            async def _stop():
                r = await stop_bridge()
                text = (
                    f"Burp bridge stopped (was on port {r.old_port})."
                    if r.status == "stopped"
                    else "Burp bridge: nothing to stop (not running)."
                )
                dispatch(Append(entry=TranscriptEntry(kind="system", text=text)))

            asyncio.create_task(_stop())
            return True

        port_raw = sub
        port: int | None = None
        if port_raw:
            try:
                port = int(port_raw)
            except ValueError:
                port = None

            if port is None or not (1 <= port <= 65535):
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="error",
                            text="usage: /burp [port] | /burp stop | /burp status",
                        )
                    )
                )
                return True

        async def _burp():
            try:
                r = await bridge(port)
                match r.status:
                    case "restarted":
                        text = (
                            f"Burp bridge stopped on port {r.old_port}, "
                            f"restarted at {r.state.url}\n"
                            f"Token: {r.state.token}"
                        )
                    case "already_running":
                        text = (
                            f"Burp bridge already running at {r.state.url}\n"
                            f"Token: {r.state.token}"
                        )
                    case _:  
                        text = (
                            f"Burp bridge listening at {r.state.url}\n"
                            f"Token: {r.state.token}"
                        )
                dispatch(Append(entry=TranscriptEntry(kind="system", text=text)))
            except Exception as err:
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="error",
                            text=f"/burp: {err}",
                        )
                    )
                )

        asyncio.create_task(_burp())
        return True

    if cmd == "/compact":
        if agent.is_running():
            dispatch(
                Append(entry=TranscriptEntry(kind="error", text="compact: a turn is already running"))
            )
            return True
        app.run_agent_compact()
        return True


    if cmd == "/next":
        if agent.is_running():
            dispatch(Append(entry=TranscriptEntry(kind="error", text="next: a turn is already running")))
            return True

        objective = " ".join(rest).strip()

        async def _next():
            try:
                signal = asyncio.Event() 
                coverage_context = await agent.coverage_context(signal)

                await app.run_agent_turn(
                    build_coverage_next_prompt(objective, coverage_context),
                    _run_opts(
                        transcript_user_text=f"/next {objective}" if objective else "/next",
                        system_text="coverage-driven next steps — tools disabled",
                        run_options=AgentRunOptions(tools=False),
                    ),
                )
            except Exception as err:
                dispatch(Append(entry=TranscriptEntry(kind="error", text=f"/next: {err}")))

        asyncio.create_task(_next())
        return True
    
    if cmd == "/plan":
        objective = " ".join(rest).strip()
        prompt = build_plan_prompt(objective)
        
        async def _plan():
            await app.run_agent_turn(
                prompt,
                _run_opts(
                    transcript_user_text=f"/plan {objective}" if objective else "/plan",
                    system_text="planning only — tools disabled",
                    run_options=AgentRunOptions(tools=False),
                ),
            )

        asyncio.create_task(_plan())
        return True

    if cmd == "/provider":
        from src.ui.commands.provider_picker import open_provider_picker
        open_provider_picker(
            dispatch,
            app.read_config,
            app.apply_provider,
            app.prompt_text,
            app.update_provider_api_key,
            app.test_connection,
        )
        return True

    if cmd == "/model":
        asyncio.create_task(_handle_model(app, rest, dispatch))
        return True

    if cmd == "/target":
        u = " ".join(rest).strip()
        if not u:
            current = agent.target.base_url()
            text = f"target currently: {current}" if current else "no target configured"
            dispatch(Append(entry=TranscriptEntry(kind="system", text=text)))
            return True

        if u.lower() == "clear":
            agent.target.clear()

            async def _target_clear():
                try:
                    await agent.clear_target()
                except Exception as err:
                    dispatch(
                        Append(
                            entry=TranscriptEntry(
                                kind="error",
                                text=f"target clear failed: {err}",
                            )
                        )
                    )

            asyncio.create_task(_target_clear())
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text="target cleared (no target configured)",
                    )
                )
            )
            return True

        normalized = normalize_target_url(u)
        if normalized is None:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text="usage: /target <url|clear>",
                    )
                )
            )
            return True

        async def _target_set():
            try:
                await agent.set_target_base_url(normalized)
            except Exception as err:
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="error",
                            text=f"target set failed: {err}",
                        )
                    )
                )

        agent.target.set_base_url(normalized)
        asyncio.create_task(_target_set())
        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="system",
                    text=f"target set to {normalized}",
                )
            )
        )
        return True

    if cmd == "/maxsteps":
        if not rest:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=f"max steps currently {agent.get_max_steps()}",
                    )
                )
            )
            return True

        arg = rest[0].lower()
        if arg == "default":
            agent.set_max_steps(DEFAULT_MAX_STEPS)
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=f"max steps reset to default ({DEFAULT_MAX_STEPS})",
                    )
                )
            )
            return True

        try:
            n = int(arg)
        except ValueError:
            n = 0

        if n <= 0:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text="usage: /maxsteps <n|default>",
                    )
                )
            )
            return True

        agent.set_max_steps(n)
        dispatch(Append(entry=TranscriptEntry(kind="system", text=f"max steps set to {n}")))
        return True

    if cmd == "/thinking":
        if not rest:
            current = "on" if agent.thinking_is_enabled() else "off"
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=f"thinking currently {current}",
                    )
                )
            )
            return True

        v = rest[0].lower()
        if v not in ("on", "off", "default"):
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text="usage: /thinking <on|off|default>",
                    )
                )
            )
            return True

        enabled = DEFAULT_THINKING_ENABLED if v == "default" else v == "on"

        async def _thinking():
            await agent.set_thinking_enabled(enabled)
            
        asyncio.create_task(_thinking())

        if v == "default":
            text = "thinking reset to default (off)"
        else:
            text = "thinking enabled" if enabled else "thinking disabled"

        dispatch(Append(entry=TranscriptEntry(kind="system", text=text)))
        return True

    if cmd == "/skills":
        from src.ui.commands.skills_handler import handle_skills_command
        handle_skills_command(agent, rest, dispatch, app.persist_disabled_skills, app.on_skill_created)
        return True

    skill_name = cmd[1:] if cmd.startswith("/") else ""
    if skill_name and agent.skills.has(skill_name):
        async def _inject():
            try:
                n = await agent.inject_skill(skill_name)
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="system", text=f"loaded /{n} — it'll apply to your next prompt."
                        )
                    )
                )
            except Exception as err:
                dispatch(Append(entry=TranscriptEntry(kind="error", text=f"/{skill_name}: {err}")))
                
        asyncio.create_task(_inject())
        return True

    return False


async def _handle_memory(agent, rest: list[str], dispatch) -> None:
    from src.agent.agent import AddMemoryInput  

    sub = (rest[0] if rest else "").lower()

    KNOWN_SUBS = ("clear", "forget", "add", "list", "intel")
    if sub and sub not in KNOWN_SUBS:
        hint = suggest_closest(sub, list(KNOWN_SUBS))
        text = f'unknown /memory subcommand "{sub}"'
        text += f'. did you mean "{hint}"?' if hint else ""
        text += "\nusage: /memory [add <text>|list|forget <text>|clear|intel [stats|clear ...]]"
        dispatch(Append(entry=TranscriptEntry(kind="error", text=text)))
        return

    if sub == "clear":
        try:
            await agent.clear_memory()
            dispatch(Append(entry=TranscriptEntry(kind="system", text="session memory cleared")))
        except Exception as err:
            dispatch(Append(entry=TranscriptEntry(kind="error", text=f"memory clear failed: {err}")))
        return

    if sub == "forget":
        query = " ".join(rest[1:]).strip()
        if not query:
            dispatch(Append(entry=TranscriptEntry(kind="error", text="usage: /memory forget <text>")))
            return
        try:
            removed = await agent.forget_memory(query)
            if removed:
                body = "\n".join(f"- {r}" for r in removed)
                text = f"forgot {len(removed)} item{'' if len(removed) == 1 else 's'}:\n{body}"
            else:
                text = f'no memory items matched "{query}"'
            dispatch(Append(entry=TranscriptEntry(kind="system", text=text)))
        except Exception as err:
            dispatch(Append(entry=TranscriptEntry(kind="error", text=f"memory forget failed: {err}")))
        return

    if sub == "add":
        text = " ".join(rest[1:]).strip()
        if not text:
            dispatch(
                Append(
                    entry=TranscriptEntry(kind="error", text="usage: /memory add <text>  (or use #<text>)")
                )
            )
            return
        try:
            fact = await agent.add_memory(AddMemoryInput(text=text, scope="project"))
            if fact:
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="system", text=f"remembered ({fact.scope}/{fact.type}): {fact.name}"
                        )
                    )
                )
            else:
                dispatch(Append(entry=TranscriptEntry(kind="error", text="memory not saved")))
        except Exception as err:
            dispatch(Append(entry=TranscriptEntry(kind="error", text=f"memory save failed: {err}")))
        return

    if sub == "list":
        try:
            facts = agent.list_curated_memory()
            text = (
                f"Saved memory ({len(facts)}):\n"
                + "\n".join(f"- [{f.type}] {f.name} — {f.description}" for f in facts)
                if facts
                else "no saved memory yet — add one with #<text> or /memory add <text>"
            )
            dispatch(Append(entry=TranscriptEntry(kind="system", text=text)))
        except Exception as err:
            dispatch(Append(entry=TranscriptEntry(kind="error", text=f"memory list failed: {err}")))
        return

    if sub == "intel":
        action = rest[1].lower() if len(rest) > 1 else "stats"

        if action == "clear":
            which = rest[2].lower() if len(rest) > 2 else "all"
            if which not in ("project", "personal", "all"):
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="error",
                            text=f'usage: /memory intel clear [project|personal|all] (got "{which}")',
                        )
                    )
                )
                return
            try:
                await agent.clear_intelligence(which)
                dispatch(
                    Append(entry=TranscriptEntry(kind="system", text=f"intelligence cleared ({which})"))
                )
            except Exception as err:
                dispatch(Append(entry=TranscriptEntry(kind="error", text=f"intel clear failed: {err}")))
            return

        if action in ("stats", "list"):
            try:
                stats = agent.get_intelligence_stats()
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="system",
                            text=(
                                f"Intelligence (learned scenarios) — "
                                f"project: {stats.get('project', 0)} · personal: {stats.get('personal', 0)}\n"
                                "(auto-capped + pruned to most recent per scope; use "
                                "/memory intel clear [project|personal|all] to wipe)"
                            ),
                        )
                    )
                )
            except Exception as err:
                dispatch(Append(entry=TranscriptEntry(kind="error", text=f"intel stats failed: {err}")))
            return

        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="error", text="usage: /memory intel [stats|clear [project|personal|all]]"
                )
            )
        )
        return

    try:
        facts = agent.list_curated_memory()
        curated = (
            f"Saved memory ({len(facts)}):\n"
            + "\n".join(f"- [{f.type}] {f.name} — {f.description}" for f in facts)
            if facts
            else "No saved memory yet. Add one with #<text> or /memory add <text>."
        )
        dispatch(Append(entry=TranscriptEntry(kind="system", text=f"{curated}\n\n{agent.format_memory()}")))
    except Exception as err:
        dispatch(Append(entry=TranscriptEntry(kind="error", text=f"memory view failed: {err}")))


async def _handle_model(app: "KAgent", rest: list[str], dispatch) -> None:
    from src.ui.core.app import ProviderChange  

    agent = app.agent
    m = " ".join(rest).strip()

    if not m:
        cur = app.read_config()
        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="system",
                    text=(
                        f"current model: {cur.get('model') or '(unset)'}\n"
                        "usage: /model <id>  ·  /model list  ·  or run /provider "
                        "for an interactive picker"
                    ),
                )
            )
        )
        return

    cur = app.read_config()

    if m.lower() in ("list", "ls"):
        from src.ui.commands.model_picker import fetch_and_pick_model
        await fetch_and_pick_model(
            cur["backend"],
            cur["base_url"],
            cur["api_key"],
            dispatch,
            app.apply_provider,
            current_model=cur.get("model") or agent.client.model(),
            success_text=lambda picked: f"model set to {picked}",
        )
        return

    known: list[str] = []
    try:
        known = await asyncio.to_thread(
            list_models,
            cur["backend"],
            cur["base_url"],
            cur["api_key"],
        )
    except Exception as err:
        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="system",
                    text=f"(could not list models from backend: {err} — proceeding without validation)",
                )
            )
        )

    if known and m not in known:
        suggestion = suggest_closest(m, known)
        text = (
            f'model "{m}" not found on backend. did you mean: {suggestion}?'
            if suggestion
            else (
                f'model "{m}" not found on backend. available: '
                + ", ".join(known[:8])
                + (", …" if len(known) > 8 else "")
            )
        )
        dispatch(Append(entry=TranscriptEntry(kind="error", text=text)))
        return

    try:
        await app.apply_provider(ProviderChange(backend=cur["backend"], model=m))
        dispatch(Append(entry=TranscriptEntry(kind="system", text=f"model set to {m}")))
    except Exception as err:
        dispatch(Append(entry=TranscriptEntry(kind="error", text=f"model: {err}")))


def _run_opts(**kwargs) -> "RunAgentOptions":
    from src.ui.core.app import RunAgentOptions as _RunAgentOptions

    return _RunAgentOptions(**kwargs)