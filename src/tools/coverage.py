from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from dataclasses import asdict
from src.coverage.store import CoverageStore, CoverageStatus
from src.permission.permission import Prompter
from .types import Tool, arg_string

ACTIONS = (
    "mark",
    "list",
    "untested",
    "summary",
    "clear",
)

STATUSES: tuple[CoverageStatus, ...] = (
    "tried",
    "passed",
    "failed",
    "waf-blocked",
    "skipped",
)


class CoverageTool(Tool):

    def __init__(
        self,
        store: CoverageStore,
    ):
        self.store = store

    def name(self) -> str:
        return "coverage"

    def description(self) -> str:
        return "\n".join(
            [
                "Track which (endpoint, parameter, vuln_class) tuples have been tested this session, and figure out what still needs to be tried. Persists across resumes.",
                "",
                "Use this as a working set as you sweep a target. After each test call action='mark'. Before the next test call action='untested'.",
                "",
                "Vuln classes are free-form lowercase strings.",
            ]
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": list(ACTIONS),
                },
                "endpoint": {
                    "type": "string",
                },
                "param": {
                    "type": "string",
                },
                "vuln_class": {
                    "type": "string",
                },
                "status": {
                    "type": "string",
                    "enum": list(STATUSES),
                },
                "notes": {
                    "type": "string",
                },
                "candidates": {
                    "type": "array",
                },
                "vuln_classes": {
                    "type": "array",
                },
            },
            "required": ["action"],
        }

    def requires_permission(self) -> bool:
        return False

    async def run(
        self,
        args: dict[str, Any],
        _signal,
        _prompter: Prompter,
    ) -> str:

        action = arg_string(args, "action") or ""

        if action not in ACTIONS:
            return (
                f"error: action must be one of: "
                f"{', '.join(ACTIONS)}"
            )

        if action == "mark":
            return await self.run_mark(args)

        if action == "list":
            return await self.run_list(args)

        if action == "untested":
            return await self.run_untested(args)

        if action == "summary":
            return await self.run_summary()

        await self.store.clear()
        return "cleared."

    async def run_mark(
        self,
        args: dict[str, Any],
    ) -> str:

        endpoint = arg_string(args, "endpoint")
        param = arg_string(args, "param")
        vuln_class = arg_string(args, "vuln_class")

        status = (
            arg_string(args, "status")
            or "tried"
        )

        notes = arg_string(args, "notes") or None

        if not endpoint or not param or not vuln_class:
            return (
                "error: mark requires endpoint, "
                "param, vuln_class"
            )

        if status not in STATUSES:
            return (
                f"error: status must be one of: "
                f"{', '.join(STATUSES)}"
            )

        entry = await self.store.mark(
            endpoint=endpoint,
            param=param,
            vulnClass=vuln_class,
            status=status,
            notes=notes,
        )

        entry_dict = asdict(entry)

        return json.dumps(
            {
                "ok": True,
                "entry": {
                    **entry_dict,
                    "firstSeen": datetime.fromtimestamp(
                        entry.firstSeen / 1000
                    ).isoformat(),
                    "lastSeen": datetime.fromtimestamp(
                        entry.lastSeen / 1000
                    ).isoformat(),
                },
            },
            indent=2,
        )

    async def run_list(
        self,
        args: dict[str, Any],
    ) -> str:

        endpoint = arg_string(args, "endpoint") or None
        param = arg_string(args, "param") or None
        vuln_class = arg_string(args, "vuln_class") or None

        status = arg_string(args, "status")
        if status not in STATUSES:
            status = None

        rows = await self.store.list(
            endpoint=endpoint,
            param=param,
            vulnClass=vuln_class,
            status=status,
        )

        if not rows:
            return "no entries match."

        out = []

        for e in rows:
            out.append(
                {
                    "endpoint": e.endpoint,
                    "param": e.param,
                    "vuln_class": e.vulnClass,
                    "status": e.status,
                    "count": e.count,
                    "first_seen": datetime.fromtimestamp(
                        e.firstSeen / 1000
                    ).isoformat(),
                    "last_seen": datetime.fromtimestamp(
                        e.lastSeen / 1000
                    ).isoformat(),
                    "notes": e.notes,
                }
            )

        return json.dumps(out, indent=2)

    async def run_untested(
        self,
        args: dict[str, Any],
    ) -> str:

        candidates = args.get("candidates", [])
        vuln_classes = args.get("vuln_classes", [])

        pairs = []

        for c in candidates:
            endpoint = c.get("endpoint", "")
            param = c.get("param", "")

            if endpoint and param:
                pairs.append(
                    {
                        "endpoint": endpoint,
                        "param": param,
                    }
                )

        classes = [
            v
            for v in vuln_classes
            if isinstance(v, str) and v
        ]

        if not pairs or not classes:
            return (
                "error: untested requires candidates "
                "and vuln_classes"
            )

        out = await self.store.untested(
            pairs,
            classes,
        )

        if not out:
            return (
                "all combinations marked already — "
                "go find more endpoints/params or move on."
            )

        return json.dumps(
            out,
            indent=2,
        )

    async def run_summary(self) -> str:

        summary = await self.store.summary()

        return json.dumps(
            asdict(summary),
            indent=2,
        )