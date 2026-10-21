from __future__ import annotations

from src.engagement.state import format_tcp_ports

import asyncio
import ipaddress
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from src.agent.agent import (
    DEFAULT_MAX_STEPS,
    DEFAULT_WHOLE_TARGET_MAX_STEPS,
    AgentRunOptions,
    ensure_system_prompt,
)
from src.config.config import Backend
from src.llm.core.models import list_models
from src.ui.core.state import Append, Clear, TranscriptEntry
from src.ui.render.help import HelpDocument, HelpSection
from src.ui.render.permissions import permissions_details, permissions_summary, yolo_target_summary
from src.ui.render.sanitize import sanitize_text
from src.ui.widgets.text_input_modal import TextInputRequest
from src.permission.network.control import parse_lab_spec, GRANT_SYNTAX
from src.permission.runtime.execution import policy_for

if TYPE_CHECKING:
    from src.agent.agent import Agent
    from src.ui.core.app import KAgent, RunAgentOptions

DEFAULT_THINKING_ENABLED = False
DEFAULT_YOLO_ENABLED = False
_DOMAIN_LABEL_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


_KEYBINDINGS: list[tuple[str, str]] = [
    ("/ + Tab", "complete / run command"),
    ("#text / #!text", "save project / personal memory"),
    ("↑ / ↓", "prompt history"),
    ("Ctrl-J / Ctrl-N", "insert newline"),
    ("Ctrl-A / Ctrl-E", "line start / end"),
    ("Esc / Ctrl-C", "cancel / quit"),
]

_COMMAND_GROUPS: list[tuple[str, tuple[str, ...]]] = [
    ("Everyday", ("/help", "/target", "/scope", "/plan", "/provider", "/model", "/clear", "/reset", "/exit")),
    ("Workflow", ("/report", "/turn-details", "/compact", "/memory", "/skills")),
    ("Advanced", ("/permissions", "/burp", "/maxsteps", "/thinking", "/yolo")),
]

_QUICK_HELP: dict[str, tuple[str, str]] = {
    "/help": ("", "commands + keys"),
    "/target": ("[url|clear]", "show/set target"),
    "/scope": ("[...]", "manage HTTP/TCP scope"),
    "/plan": ("[objective]", "plan without tools"),
    "/provider": ("", "configure provider"),
    "/model": ("[id|list]", "switch/list model"),
    "/clear": ("", "clear transcript"),
    "/reset": ("", "reset conversation/session"),
    "/exit": ("", "quit"),
    "/report": ("[file.pdf]", "export assessment"),
    "/turn-details": ("", "latest turn diagnostics"),
    "/compact": ("", "compact conversation"),
    "/memory": ("[...]", "manage memory"),
    "/skills": ("[...]", "use/manage skills"),
    "/permissions": ("[...]", "permissions + grants"),
    "/burp": ("[...]", "Burp bridge/captures"),
    "/maxsteps": ("[n]", "tool-call limit"),
    "/thinking": ("[...]", "reasoning mode"),
    "/yolo": ("[...]", "auto-approval profile"),
}



def build_help_document(agent: "Agent", read_config) -> HelpDocument:
    cfg = read_config()

    enabled = len(agent.skills.list_enabled())
    total = len(agent.skills.list())
    target = agent.target.base_url() or "(not set)"
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
    compact_threshold = agent.get_auto_compact_threshold()
    compact_label = (
        f"{compact_threshold // 1000}k" if compact_threshold >= 1000
        else f"{compact_threshold} tok"
    )
    max_steps_override = agent.get_max_steps_override()
    whole_target_steps = (
        max_steps_override
        if max_steps_override is not None
        else DEFAULT_WHOLE_TARGET_MAX_STEPS
    )
    out.append(
        f"  limits     Direct Mode {agent.get_max_steps()} / Whole-target {whole_target_steps} steps"
        f"  ·  {compact_label} compact"
        f"  ·  thinking {'on' if agent.thinking_is_enabled() else 'off'}"
    )
    out.append(f"  skills     {enabled}/{total} enabled")
    out.append(f"  memory     {memory.items} items")
    out.append("")

    summary = sanitize_text("\n".join(out).rstrip())
    sections: list[HelpSection] = []
    for group, names in _COMMAND_GROUPS:
        rows: list[tuple[str, str]] = []
        for name in names:
            args, description = _QUICK_HELP[name]
            rows.append((f"{name} {args}".rstrip(), description))
        sections.append(HelpSection(group, tuple(rows)))
    sections.append(HelpSection("Skill picker", (
        ("↑↓ / Tab", "select"),
        ("Space", "enable / disable"),
        ("Enter", "use selected skill"),
        ("a / d", "enable / disable all"),
        ("Esc / q", "close picker"),
    )))
    sections.append(HelpSection("Input", tuple(_KEYBINDINGS)))
    return HelpDocument(summary, tuple(sections), "Type / for commands.")


def build_help_text(agent: "Agent", read_config) -> str:
    return build_help_document(agent, read_config).plain_text()


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


def _target_yolo_status(app: "KAgent") -> str:
    agent = app.agent
    engagement = getattr(agent, "engagement_state", None)
    policy = policy_for(getattr(agent, "prompter", None))
    return yolo_target_summary(
        agent.target.base_url(), policy.yolo if policy is not None else app.state.yolo,
        engagement.http_permissions if engagement is not None else None, policy,
    )


def handle_slash(app: "KAgent", raw: str) -> bool:
    parts = raw.strip().split()
    if not parts:
        return False

    cmd, *rest = parts

    agent = app.agent
    dispatch = app.dispatch

    if cmd == "/turn-details":
        app.show_turn_details()
        return True

    if cmd == "/report":
        from src.ui.commands.report_handler import start_report
        start_report(app, rest)
        return True

    if cmd == "/permissions":
        rights = agent.engagement_state.http_permissions
        policy = policy_for(getattr(agent, "prompter", None))
        rights.sync_target()
        try:
            sub = rest[0] if rest else "show"
            if sub == "show" and len(rest) <= 1:
                text = permissions_details(rights, policy) if rest else permissions_summary(rights, policy)
            elif sub == 'browser' and policy is not None:
                binding = policy.browser_local
                if binding is None:
                    raise ValueError('Browser MCP is not enabled. Start with --browser and --target.')
                if rest == ['browser', 'revoke']:
                    binding.revoke_grant()
                    text = 'Browser grant revoked. Queued auto-approvals cannot dispatch. Already-sent effects are not rolled back.'
                elif rest == ['browser']:
                    text = binding.grant_status()
                else:
                    raise ValueError('usage: /permissions browser [revoke]')
            elif sub == "revoke-tool" and len(rest) == 2 and policy is not None:
                policy.revoke(rest[1])
                text = f"Tool revoked: {rest[1]}. YOLO and ordinary approval cannot override this rule."
            elif sub == "restore-tool" and len(rest) == 2 and policy is not None:
                policy.restore_tool(rest[1])
                text = f"Tool restored: {rest[1]}. Resource and adapter checks still apply."
            elif sub == "retry-tools" and len(rest) == 1 and policy is not None:
                policy.retry()
                text = "Declined actions can be reviewed again. Explicit tool and resource revocations remain in effect."
            elif sub == "network-refresh" and len(rest) == 1 and policy is not None:
                policy.refresh_network()
                text = "DNS bindings cleared. The next native connection rechecks its declared origin. Quotas are unchanged."
            elif sub == "limits" and len(rest) == 3 and policy is not None:
                calls, concurrency = (None if rest[1] == 'session' else int(rest[1])), int(rest[2])
                if (calls is not None and calls <= 0) or concurrency <= 0:
                    raise ValueError("limits must be positive: /permissions limits <session-calls|session> <concurrency>")
                policy.max_calls, policy.concurrency = calls, concurrency
                policy.revision += 1
                policy.persist()
                text = permissions_summary(rights, policy)
            elif sub == "deny" and len(rest) == 1:
                rights.deny_session()
                text = "HTTP denied for this session. Active grants revoked. Explicit retry or a new grant is required."
            elif sub == "revoke" and len(rest) == 2:
                rights.revoke(rest[1])
                text = "HTTP grant revoked. New dispatch blocked. Already-sent effects cannot be undone."
            elif sub == "retry" and len(rest) == 2:
                rights.retry(rest[1])
                text = ("HTTP review reopened for this origin. An expired or exhausted exact-only "
                        "execution envelope can renew with default limits. Lab grant budgets are unchanged. "
                        "No exact request was approved. Active YOLO can reopen scoped autonomy.")
            elif sub == "grant" and len(rest) == 2:
                origin, limits, mode = parse_lab_spec(rest[1])
                async def _review_http_grant():
                    try:
                        review = getattr(agent.prompter, "operator_review_prompter", lambda: agent.prompter)()
                        grant = await rights.review_grant(origin, limits, mode, review)
                        if policy is not None:
                            policy.persist()
                        result = permissions_summary(rights, policy) if grant else "HTTP grant declined. No permissions were granted."
                        dispatch(Append(entry=TranscriptEntry(kind="system", text=result)))
                    except Exception as err:
                        dispatch(Append(entry=TranscriptEntry(kind="error", text=f"HTTP permissions: {err}")))
                asyncio.create_task(_review_http_grant())
                return True
            else:
                raise ValueError("usage: /permissions [show|browser [revoke]|grant <spec>|revoke <id>|deny|retry <origin>|revoke-tool <name>|restore-tool <name>|retry-tools|network-refresh|limits <calls> <concurrency>]\n" + GRANT_SYNTAX)
        except (ValueError, PermissionError) as err:
            dispatch(Append(entry=TranscriptEntry(kind="error", text=str(err))))
            return True
        if policy is not None:
            policy.persist()
        dispatch(Append(entry=TranscriptEntry(kind="system", text=text)))
        return True

    if cmd in ("/exit", "/quit"):
        app.exit()
        return True

    if cmd == "/yolo":
        if not rest:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=_target_yolo_status(app),
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
        engagement = getattr(agent, "engagement_state", None)
        if engagement is not None:
            engagement.http_permissions.set_yolo(next_state)

        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="system",
                    text=_target_yolo_status(app),
                )
            )
        )
        return True

    if cmd == "/clear":
        dispatch(Clear())
        return True

    if cmd == "/reset":
        cancel_selection = getattr(agent, "cancel_capture_selection", None)
        if callable(cancel_selection):
            cancel_selection()
        async def _reset():
            await agent.reset()
            app.refresh_assessment_progress()

        asyncio.create_task(_reset())
        dispatch(Clear(message="conversation reset"))
        return True

    if cmd == "/help":
        document = build_help_document(agent, app.read_config)
        dispatch(
            Append(
                entry=TranscriptEntry(kind="system", text=document.plain_text(), help_document=document)
            )
        )
        return True

    if cmd == "/memory":
        asyncio.create_task(_handle_memory(agent, rest, dispatch))
        return True


    if cmd == "/burp":
        sub = rest[0] if rest else ""
        if sub in {"list", "use", "all"}:
            from src.browser.selection import LIST_DISPLAY_LIMIT, MAX_SELECTED_REQUESTS
            changing = sub != "list"
            if changing and agent.is_running():
                dispatch(Append(entry=TranscriptEntry(kind="error", text="/burp: a turn is already running. Selection cannot change.")))
                return True
            # Synchronous selection makes a following prompt see exactly this
            # snapshot; no scheduled task can select after that prompt starts.
            if (sub in {"list", "all"} and len(rest) != 1) or (sub == "use" and len(rest) > 2):
                if changing:
                    agent.cancel_capture_selection()
                dispatch(Append(entry=TranscriptEntry(kind="error", text="usage: /burp list | /burp use [id|cancel] | /burp all\nPending selection cleared." if changing else "usage: /burp list")))
                return True
            try:
                if sub == "list":
                    rows = agent.list_burp_captures()
                    shown = rows[:LIST_DISPLAY_LIMIT]
                    text = f"Showing {len(shown)}/{len(rows)} requests"
                    text += "\n" + "\n".join(f"{row.retrieval_id}  {row.method}  {row.endpoint}" for row in shown)
                    if not rows:
                        text += "No matching Burp requests for the active target."
                elif len(rest) == 2 and rest[1] == "cancel":
                    agent.cancel_capture_selection()
                    text = "Pending Burp selection cancelled. Captured requests were kept."
                else:
                    selection, total = agent.select_burp_captures(
                        rest[1] if len(rest) == 2 else None, all_recent=sub == "all")
                    text = f"Selected {len(selection.requests)}/{total} requests for the next Agent turn."
                    text += "\n" + "\n".join(f"{row.retrieval_id}  {row.method}  {row.endpoint}" for row in selection.requests)
                    if sub == "all" and total > MAX_SELECTED_REQUESTS:
                        text += "\nSelection is limited to the 50 most recent matching Burp records."
                    text += "\nEnter a prompt to analyze or test the selected context. Selection grants no HTTP permission."
                dispatch(Append(entry=TranscriptEntry(kind="system", text=text)))
            except (ValueError, PermissionError) as err:
                text = f"/burp: {err}"
                if changing:
                    agent.cancel_capture_selection()
                    text += "\nPending selection cleared. Agent was not started."
                dispatch(Append(entry=TranscriptEntry(kind="error", text=text)))
            return True

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

        if sub in {"status", "credentials"}:
            async def _status():
                r = await status_bridge()
                if r.status == "not_running":
                    text = "Burp bridge: not running."
                else:
                    if sub == "credentials":
                        app.show_bridge_credentials(r.state)
                        return
                    text = (
                        f"Burp bridge: running at {r.state.url} (port {r.state.port})\n"
                        "Bridge token hidden. Use /burp credentials to view or copy it locally."
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
                            "Bridge token hidden. Use /burp credentials to view or copy it locally."
                        )
                    case "already_running":
                        text = (
                            f"Burp bridge already running at {r.state.url}\n"
                            "Bridge token hidden. Use /burp credentials to view or copy it locally."
                        )
                    case _:  
                        text = (
                            f"Burp bridge listening at {r.state.url}\n"
                            "Bridge token hidden. Use /burp credentials to view or copy it locally."
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
            adapter=getattr(app, "custom_provider_adapter", None),
        )
        return True

    if cmd == "/model":
        asyncio.create_task(_handle_model(app, rest, dispatch))
        return True

    if cmd == "/scope":
        sub = rest[0].lower() if rest else "show"

        if sub == "show" and len(rest) <= 1:
            if agent.target.empty():
                text = "No active engagement. Set a target with /target <url>."
            else:
                origins = sorted(agent.engagement_state.allowed_origins)
                lines = [
                    f"Active target: {agent.target.base_url()}",
                    "Allowed origins:",
                    *(f"  - {origin.as_url()}" for origin in origins),
                    "Allowed TCP destinations:",
                    *(f"  - {entry.address} ports {format_tcp_ports(entry.ports)}"
                      for entry in sorted(agent.engagement_state.allowed_tcp)),
                    f"Engagement revision: {agent.engagement_state.revision}",
                ]
                text = "\n".join(lines)
            dispatch(Append(entry=TranscriptEntry(kind="system", text=text)))
            return True

        if sub not in {"add", "remove", "reset", "tcp-add", "tcp-remove"}:
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text="usage: /scope [show|add <origin>|remove <origin>|tcp-add <ip> <ports>|tcp-remove <ip> [ports]|reset]",
                    )
                )
            )
            return True

        if agent.target.empty():
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="error",
                        text="No active engagement. Set a target with /target <url>.",
                    )
                )
            )
            return True

        if sub in {"tcp-add", "tcp-remove"}:
            if len(rest) not in ({3} if sub == "tcp-add" else {2, 3}):
                dispatch(Append(entry=TranscriptEntry(kind="error", text=(
                    "usage: /scope tcp-add <ip> <ports> | /scope tcp-remove <ip> [ports]"))))
                return True
            try:
                changed = agent.update_tcp_scope(rest[1], rest[2] if len(rest) == 3 else None,
                                                 remove=sub == "tcp-remove")
                text = f"TCP scope {'updated' if changed else 'unchanged'}: {rest[1]}"
            except ValueError as err:
                dispatch(Append(entry=TranscriptEntry(kind="error", text=f"invalid TCP scope: {err}")))
                return True
        elif sub == "reset":
            if len(rest) != 1:
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="error",
                            text="usage: /scope reset",
                        )
                    )
                )
                return True
            origin, changed = agent.reset_scope_to_target()
            text = (
                f"Scope reset to active target only:\n  {origin.as_url()}"
                if changed
                else f"Scope already contains only the active target: {origin.as_url()}"
            )
        else:
            if len(rest) != 2:
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="error",
                            text=f"usage: /scope {sub} <origin>",
                        )
                    )
                )
                return True
            try:
                if sub == "add":
                    origin, changed = agent.add_scope_origin(rest[1])
                    text = (
                        f"Added scope origin: {origin.as_url()}"
                        if changed
                        else f"Origin is already in scope: {origin.as_url()}"
                    )
                else:
                    origin, changed = agent.remove_scope_origin(rest[1])
                    text = (
                        f"Removed scope origin: {origin.as_url()}"
                        if changed
                        else f"Origin is not in scope: {origin.as_url()}"
                    )
            except ValueError as err:
                if str(err) == "cannot remove the active target origin":
                    text = (
                        "Cannot remove the active target origin from scope.\n"
                        "Change the active target first."
                    )
                else:
                    text = f"invalid scope origin: {rest[1]}"
                dispatch(Append(entry=TranscriptEntry(kind="error", text=text)))
                return True

        async def _persist_scope():
            try:
                await agent.save()
            except Exception as err:
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="error",
                            text=f"scope save failed (state remains updated): {err}",
                        )
                    )
                )

        asyncio.create_task(_persist_scope())
        dispatch(Append(entry=TranscriptEntry(kind="system", text=text)))
        return True

    if cmd == "/target":
        u = " ".join(rest).strip()
        if not u:
            current = agent.target.base_url()
            text = f"target currently: {current}" if current else "no target configured"
            dispatch(Append(entry=TranscriptEntry(kind="system", text=text)))
            return True

        if u.lower() == "clear":
            # State + system prompt rebuild happen synchronously right here
            # so the very next turn is guaranteed to see the cleared target
            # in its context — this must not depend on the event loop
            # scheduling an async task before the user's next message runs.
            apply_clear = getattr(agent, "apply_target_clear", None)
            if callable(apply_clear):
                apply_clear()
            else:
                agent.target.clear()
                agent.rebuild_system_prompt()
                agent.history = ensure_system_prompt(agent.history, agent.sys_prompt)

            async def _persist_target_clear():
                try:
                    await agent.save()
                except Exception as err:
                    dispatch(
                        Append(
                            entry=TranscriptEntry(
                                kind="error",
                                text=(
                                    f"target clear save failed (state is "
                                    f"still updated in-memory): {err}"
                                ),
                            )
                        )
                    )

            asyncio.create_task(_persist_target_clear())
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

        # Same fix here: set_base_url + rebuild_system_prompt + history
        # patch run synchronously, so agent.history[0] already contains
        # the new target before this function returns. Only the disk
        # write (agent.save()) is pushed to the background — it doesn't
        # affect what the next turn sees.
        apply_target = getattr(agent, "apply_target_base_url", None)
        if callable(apply_target):
            apply_target(normalized)
        else:
            agent.target.set_base_url(normalized)
            agent.rebuild_system_prompt()
            agent.history = ensure_system_prompt(agent.history, agent.sys_prompt)

        async def _persist_target_set():
            try:
                await agent.save()
            except Exception as err:
                dispatch(
                    Append(
                        entry=TranscriptEntry(
                            kind="error",
                            text=(
                                f"target save failed (state is still "
                                f"updated in-memory): {err}"
                            ),
                        )
                    )
                )

        asyncio.create_task(_persist_target_set())
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
            agent.reset_max_steps()
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=(
                            f"max steps reset to defaults ({DEFAULT_MAX_STEPS} direct, "
                            f"{DEFAULT_WHOLE_TARGET_MAX_STEPS} whole-target)"
                        ),
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
            status_fn = getattr(agent, "reasoning_status", None)
            status_value = status_fn() if callable(status_fn) else None
            text = (
                status_value if isinstance(status_value, str)
                else f"thinking currently {current}"
            )
            dispatch(
                Append(
                    entry=TranscriptEntry(
                        kind="system",
                        text=text,
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
        status_fn = getattr(agent, "reasoning_status", None)
        if callable(status_fn):
            status_value = status_fn(enabled)
            if isinstance(status_value, str):
                text = status_value

        dispatch(Append(entry=TranscriptEntry(kind="system", text=text)))
        return True

    if cmd == "/skills":
        from src.ui.commands.skills_handler import handle_skills_command
        handle_skills_command(agent, rest, dispatch, app.persist_disabled_skills, app.on_skill_created)
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
                                "Keeps the most recent entries within each scope's limit.\n"
                                "Clear: /memory intel clear [project|personal|all]"
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
        current_model = (
            cur.get("active_custom_provider_model")
            if cur.get("active_custom_provider_id")
            else cur.get("model")
        )
        dispatch(
            Append(
                entry=TranscriptEntry(
                    kind="system",
                    text=(
                        f"current model: {current_model or '(unset)'}\n"
                        "usage: /model <id>  ·  /model list  ·  or run /provider "
                        "for an interactive picker"
                    ),
                )
            )
        )
        return

    cur = app.read_config()
    custom_provider_id = cur.get("active_custom_provider_id")
    model_backend = (
        Backend.OPENAI_COMPAT if custom_provider_id else cur["backend"]
    )
    model_base_url = (
        cur.get("active_custom_provider_base_url", "")
        if custom_provider_id
        else cur["base_url"]
    )
    model_api_key = (
        cur.get("active_custom_provider_api_key", "")
        if custom_provider_id
        else cur["api_key"]
    )
    current_model = (
        cur.get("active_custom_provider_model", "")
        if custom_provider_id
        else cur.get("model")
    )

    if m.lower() in ("list", "ls"):
        from src.ui.commands.model_picker import fetch_and_pick_model
        await fetch_and_pick_model(
            model_backend,
            model_base_url,
            model_api_key,
            dispatch,
            app.apply_provider,
            current_model=current_model or agent.client.model(),
            success_text=lambda picked: f"model set to {picked}",
            custom_provider_id=custom_provider_id,
            manual_model_prompt=lambda reason: app.prompt_text(
                TextInputRequest(
                    header="Manual model ID",
                    question=(
                        f"Model discovery could not complete: {reason}. "
                        "Enter a model ID manually."
                    ),
                    placeholder="model-id",
                    resolve=lambda _value: None,
                    reject=lambda _error: None,
                )
            ),
        )
        return

    known: list[str] = []
    try:
        known = await asyncio.to_thread(
            list_models,
            model_backend,
            model_base_url,
            model_api_key,
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
        await app.apply_provider(
            ProviderChange(
                backend=model_backend,
                model=m,
                # Resolve the active profile again inside the config
                # transaction; discovery may have overlapped a profile edit.
                base_url=None,
                api_key=None,
                custom_provider_id=custom_provider_id,
            )
        )
        # The banner contains the active model, so refresh it along with the
        # successful switch while preserving the confirmation message.
        dispatch(Clear())
        dispatch(Append(entry=TranscriptEntry(kind="system", text=f"model set to {m}")))
    except Exception as err:
        dispatch(Append(entry=TranscriptEntry(kind="error", text=f"model: {err}")))


def _run_opts(**kwargs) -> "RunAgentOptions":
    from src.ui.core.app import RunAgentOptions as _RunAgentOptions

    return _RunAgentOptions(**kwargs)
