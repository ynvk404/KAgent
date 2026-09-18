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
                "Use this as a working set as you sweep a target. After each test (whether it confirmed a bug, came back clean, or hit a WAF), call action='mark'. Before picking the next test, call action='untested' with the candidates you have and the vuln classes you want to cover — it returns only the tuples you haven't tried.",
                "",
                "Vuln classes are free-form lowercase strings; the convention is to match a loaded skill name where possible (sqli, xss, ssti, idor, ssrf, jwt, deserialize, graphql, race, ...).",
            ]
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": list(ACTIONS),
                    "description": (
                        "'mark' records one test; 'list' shows all recorded "
                        "entries (filterable); 'untested' returns the "
                        "candidate x vuln-class tuples that have not been "
                        "marked yet; 'summary' returns counts; 'clear' wipes "
                        "the session's coverage state."
                    ),
                },
                "endpoint": {
                    "type": "string",
                    "description": (
                        "For mark: target endpoint, ideally 'METHOD /path' "
                        "(e.g. 'GET /api/users/{id}'). Query string is "
                        "stripped automatically. For list: optional filter "
                        "substring. For untested: not used here — provide "
                        "endpoints inside each item of 'candidates' instead."
                    ),
                },
                "param": {
                    "type": "string",
                    "description": (
                        "Parameter under test (header, query, body, or "
                        "cookie name). For list: exact filter. For "
                        "untested: not used here — provide params inside "
                        "each item of 'candidates' instead."
                    ),
                },
                "vuln_class": {
                    "type": "string",
                    "description": (
                        "Vulnerability class label, lowercase. Match a "
                        "skill name when possible (e.g. 'sqli', 'xss', "
                        "'jwt', 'ssrf', 'idor'). For list: filter."
                    ),
                },
                "status": {
                    "type": "string",
                    "enum": list(STATUSES),
                    "description": (
                        "Result: 'tried' (attempted, inconclusive), "
                        "'passed' (confirmed vuln), 'failed' (definitely "
                        "not vulnerable), 'waf-blocked' (could not test), "
                        "'skipped' (out of scope / not applicable)."
                    ),
                },
                "notes": {
                    "type": "string",
                    "description": "Optional short note (payload class, reason).",
                },
                "candidates": {
                    "type": "array",
                    "description": (
                        "For action='untested': list of {endpoint, param} "
                        "pairs to cross with vuln_classes. Each item must "
                        "be an object with only 'endpoint' and 'param' "
                        "keys — do NOT put vuln_class inside these items, "
                        "it goes in the separate 'vuln_classes' field. "
                        "Example: [{\"endpoint\": \"/rest/products\", "
                        "\"param\": \"search\"}]"
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "endpoint": {"type": "string"},
                            "param": {"type": "string"},
                        },
                        "required": ["endpoint", "param"],
                    },
                },
                "vuln_classes": {
                    "type": "array",
                    "description": (
                        "For action='untested': list of vuln class labels "
                        "(strings) to check against every candidate. "
                        "Example: [\"sqli\"]"
                    ),
                    "items": {"type": "string"},
                },
            },
            "required": ["action"],
        }

    def requires_permission(self) -> bool:
        return False

    def requires_permission_for(self, args: dict[str, Any]) -> bool:
        return arg_string(args, "action") == "clear"

    async def run(
        self,
        args: dict[str, Any],
        signal,
        prompter: Prompter,
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
                "error: mark requires endpoint, param, vuln_class "
                '(status optional, defaults to "tried")'
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
        raw_candidates = args.get("candidates", [])
        raw_vuln_classes = args.get("vuln_classes", [])

        candidates = (
            raw_candidates
            if isinstance(raw_candidates, list)
            else []
        )
        vuln_classes = (
            raw_vuln_classes
            if isinstance(raw_vuln_classes, list)
            else []
        )

        pairs = []

        for c in candidates:
            if not isinstance(c, dict):
                continue

            endpoint = c.get("endpoint", "")
            param = c.get("param", "")

            if not isinstance(endpoint, str) or not isinstance(param, str):
                continue

            endpoint = endpoint.strip()
            param = param.strip()

            if endpoint and param:
                pairs.append(
                    {
                        "endpoint": endpoint,
                        "param": param,
                    }
                )

        classes = [
            v.strip()
            for v in vuln_classes
            if isinstance(v, str) and v.strip()
        ]

        if not pairs or not classes:
            return (
                "error: untested requires `candidates` (non-empty list "
                "of {endpoint, param}) and `vuln_classes` (non-empty "
                "list of strings)"
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
