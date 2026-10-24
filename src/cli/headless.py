"""One-turn frontend for the existing Agent and permission/runtime lifecycle."""
from __future__ import annotations

import asyncio
from contextlib import ExitStack, redirect_stderr
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Callable, cast

from src.agent.agent import Agent
from src.agent.ownership import join
from src.permission.permission import OperatorInputUnavailable
from src.redaction.redact import redact_payload
from src.tools.common.approval_display import redact_approval


class UnavailableInput:
    """No permission decisions and no invented answers when there is no operator."""
    def __init__(self) -> None:
        self.needed = asyncio.Event()
        self.tool = ""

    async def ask(self, request: Any = None, signal: Any = None, *, q: Any = None) -> Any:
        self.tool = str(getattr(request, "tool", "ask_user"))[:128]
        self.needed.set()
        if signal is not None and callable(getattr(signal, "set", None)):
            signal.set()
        raise OperatorInputUnavailable("headless requires operator input; no action approved")

    async def close(self) -> None:
        pass


class RunSignal(asyncio.Event):
    @property
    def aborted(self) -> bool:
        return self.is_set()


class EventSink:
    def __init__(self, destination: Path, secret_values: tuple[str, ...] = ()):
        destination = destination.absolute()
        if any(p.is_symlink() for p in (destination, *destination.parents)):
            raise ValueError("headless output cannot use symlinks")
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.destination = destination
        self.secrets = tuple(sorted((v for v in secret_values if v), key=len, reverse=True))
        self.stdout_broken = False
        self.additional_secrets: Callable[[], list[str]] = lambda: []
        fd = os.open(destination / "events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.stream = os.fdopen(fd, "w", encoding="utf-8")

    def safe(self, value: Any) -> Any:
        if is_dataclass(value) and not isinstance(value, type):
            value = asdict(value)
        if isinstance(value, BaseException):
            # Provider errors may include arbitrary credential-bearing text.
            return {"error_type": type(value).__name__}
        if isinstance(value, dict):
            return {str(k): self.safe(v) for k, v in value.items()}
        if isinstance(value, (tuple, list)):
            return [self.safe(v) for v in value]
        if isinstance(value, str):
            for secret in sorted(filter(None, (*self.secrets, *self.additional_secrets())), key=len, reverse=True):
                value = value.replace(secret, "[REDACTED]")
            return redact_approval(value)
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return type(value).__name__

    def write(self, event: dict[str, Any]) -> None:
        safe = redact_payload(self.safe(event))
        line = json.dumps({"ts": datetime.now(timezone.utc).isoformat(), **safe}, ensure_ascii=False)
        self.stream.write(line + "\n")
        self.stream.flush()
        if not self.stdout_broken:
            try:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
            except OSError:
                self.stdout_broken = True
                raise

    def close(self) -> None:
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.stream.close()


class PrivateDiagnostics:
    """Redact the frontend's stderr and existing log handlers without changing Agent."""
    def __init__(self, sink: EventSink):
        self.sink = sink
        self.stream = sys.stderr

    def write(self, value: str) -> int:
        safe = self.sink.safe(value)
        self.stream.write("".join(c for c in safe if c in "\n\t" or c.isprintable()))
        return len(value)

    def flush(self) -> None:
        self.stream.flush()

    def isatty(self) -> bool:
        return self.stream.isatty()

    def fileno(self) -> int:
        return self.stream.fileno()

    def filter(self, record: logging.LogRecord) -> bool:
        from src.logger.logger import LOG_RECORD_FIELDS
        record.msg = self.sink.safe(record.getMessage())
        record.args = ()
        if record.exc_info:
            record.exc_text = type(record.exc_info[1]).__name__
            record.exc_info = None
        for key in list(record.__dict__):
            if key not in LOG_RECORD_FIELDS:
                record.__dict__[key] = self.sink.safe(record.__dict__[key])
        return True


def private_diagnostics(sink: EventSink) -> ExitStack:
    from src.logger.logger import logger
    stack = ExitStack()
    private = PrivateDiagnostics(sink)
    stack.enter_context(redirect_stderr(private))
    for handler in logger().handlers:
        handler.addFilter(private)
        stack.callback(handler.removeFilter, private)
    return stack


async def run_headless(agent: Agent, prompt: str, root_signal: asyncio.Event,
                       operator: UnavailableInput, output: Path, session_debug: Any) -> int:
    """Never interpret input, create workflow records, approve, or auto-continue."""
    policy = getattr(agent.prompter, "execution_policy", None)
    sink = EventSink(output, policy.internal_secret_values() if policy else ())
    sink.additional_secrets = lambda: getattr(operator, "answers", [])
    diagnostics = private_diagnostics(sink)
    signal = RunSignal()
    started = time.monotonic()
    done: dict[str, Any] = {}
    failed = False
    exhausted_steps: int | None = None
    status = "error"
    turn = None
    waiters: list[asyncio.Task] = []

    def emit(event: Any) -> None:
        nonlocal failed, exhausted_steps
        row: dict[str, Any] = asdict(event) if is_dataclass(event) and not isinstance(event, type) else dict(cast(Any, event))
        if row.get("type") == "done":
            done.update(row)
        if row.get("type") == "error" and type(row.get("err")).__name__ != "MaxStepsError":
            failed = True
        if row.get("type") == "error" and type(row.get("err")).__name__ == "MaxStepsError":
            exhausted_steps = row["err"].steps
        try:
            sink.write({"event": "agent", "data": row})
        except OSError:
            signal.set()
            root_signal.set()
            raise
        session_debug.agent_event(sink.safe(row))

    try:
        sink.write({"event": "headless_start", "mode": "headless", "yolo": bool(policy and policy.yolo),
                    "provider": agent.client.name(), "model": agent.client.model(),
                    "target_origin": agent.target.base_url()})
        if operator.needed.is_set():
            status = "needs_operator"
        elif root_signal.is_set():
            status = "cancelled"
        else:
            turn = asyncio.create_task(agent.run(prompt, signal=signal, emit=emit))
            waiters = [asyncio.create_task(root_signal.wait()), asyncio.create_task(operator.needed.wait())]
            await asyncio.wait([turn, *waiters], return_when=asyncio.FIRST_COMPLETED)
            if operator.needed.is_set() or root_signal.is_set():
                status = "needs_operator" if operator.needed.is_set() else "cancelled"
                signal.set()
                if not turn.done():
                    turn.cancel()
                await join(turn)
            else:
                await turn
                reason = done.get("stop_reason")
                if reason == "max_steps":
                    status = "budget_exhausted"
                elif failed:
                    status = "error"
                elif reason in {"workflow_blocked", "context_capacity"}:
                    status = "blocked"
                elif reason == "cancelled":
                    status = "cancelled"
                elif reason in {"final_response", "workflow_completed"}:
                    status = "completed"
                else:
                    status = "error"
        if status == "needs_operator":
            sink.write({"event": "needs_operator", "tool": operator.tool, "error_kind": "input_unavailable"})
        if status == "budget_exhausted":
            # TUI Continue calls Agent.run again, resetting its per-turn step
            # window. There is no same-turn resume API or approved extra window.
            sink.write({"event": "budget_exhausted", "step_limit": exhausted_steps,
                        "continuation": "unavailable", "reason": "runtime_continue_starts_new_turn",
                        "turn_restarted": False})
            if hasattr(operator, "answers"):
                sys.stderr.write("Step budget exhausted. Continue unavailable within this turn and approved run budget; session saved.\n")
    except asyncio.CancelledError:
        status = "cancelled"
        signal.set()
        if turn is not None:
            turn.cancel()
            await join(turn)
        raise
    except Exception as error:
        status = "error"
        sink.write({"event": "headless_error", "error_type": type(error).__name__})
    finally:
        signal.set()
        for waiter in waiters:
            waiter.cancel()
            await join(waiter)
        if turn is not None and not turn.done():
            turn.cancel()
            await join(turn)
        try:
            # After join: no earlier checkpoint writer can race final persistence.
            await agent.save()
            await agent.save_context_snapshot("headless terminal checkpoint")
            agent.request_metrics.export_jsonl(output / "llm-metrics.jsonl")
        except Exception as error:
            status = "error"
            sink.write({"event": "persistence_error", "error_type": type(error).__name__})
        finally:
            if sink.stdout_broken:
                status = "error"
            try:
                sink.write({"event": "headless_result", "status": status, "stop_reason": done.get("stop_reason"),
                            "duration_seconds": round(time.monotonic() - started, 3),
                            "request_metric_records": len(agent.request_metrics.records),
                            "cost_usd": "Not measured", "workflow_verdict": "Not evaluated"})
            finally:
                try:
                    sink.close()
                finally:
                    diagnostics.close()
    return {"completed": 0, "needs_operator": 3, "blocked": 4,
            "budget_exhausted": 5, "cancelled": 130, "error": 1}[status]
