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

DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 25
MAX_COLLECTION_RESULT_CHARS = 24_000
COLLECTION_TEXT_LIMIT = 200
COLLECTION_NOTES_LIMIT = 300
SUMMARY_VULN_CLASS_LIMIT = 20

class CoverageTool(Tool):
    def __init__(
        self,
        store: CoverageStore,
    ):
        self.store = store

    def name(self) -> str:
        return "coverage"

    def description(self) -> str:
        return (
            "Track tested (endpoint, parameter, vulnerability-class) tuples "
            "across resumes. Mark each meaningful test; query untested tuples "
            "before choosing more work. Candidate-class aliases are normalized. "
            "list/untested are paginated: complete=true only when one response "
            "contains the full matching set; use has_more and next_cursor to "
            "continue."
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": list(ACTIONS),
                    "description": (
                        "mark, list, untested, or summary; clear "
                        "removes session coverage after permission."
                    ),
                },
                "endpoint": {
                    "type": "string",
                    "description": (
                        "For mark/list: endpoint such as 'GET /api/users/{id}'. "
                        "Query strings are stripped."
                    ),
                },
                "param": {
                    "type": "string",
                    "description": (
                        "Parameter name for mark or exact list filter."
                    ),
                },
                "vuln_class": {
                    "type": "string",
                    "description": (
                        "Canonical candidate/vulnerability class or alias."
                    ),
                },
                "status": {
                    "type": "string",
                    "enum": list(STATUSES),
                    "description": (
                        "Test result: tried, passed, failed, waf-blocked, or skipped."
                    ),
                },
                "notes": {
                    "type": "string",
                    "description": "Optional short note (payload class, reason).",
                },
                "candidates": {
                    "type": "array",
                    "description": (
                        "For untested: {endpoint, param} pairs crossed with vuln_classes."
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
                        "For untested: classes to check for every candidate."
                    ),
                    "items": {"type": "string"},
                },
                "limit": {
                    "type": "number",
                    "description": (
                        "For list/untested: page size "
                        f"(default {DEFAULT_PAGE_SIZE}, max {MAX_PAGE_SIZE})."
                    ),
                },
                "cursor": {
                    "type": "string",
                    "description": (
                        "For list/untested: continuation offset returned as "
                        "next_cursor. Omit for the first page and reuse the "
                        "same filters/candidates on continuation calls."
                    ),
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
            return self._error(
                action,
                f"action must be one of: {', '.join(ACTIONS)}",
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
        return json.dumps(
            {"ok": True, "action": "clear", "cleared": True},
            indent=2,
        )

    async def run_mark(
        self,
        args: dict[str, Any],
    ) -> str:
        endpoint = arg_string(args, "endpoint").strip()
        param = arg_string(args, "param").strip()
        vuln_class = arg_string(args, "vuln_class").strip()

        status = (
            arg_string(args, "status")
            or "tried"
        )

        notes = arg_string(args, "notes") or None

        if not endpoint or not param or not vuln_class:
            return self._error(
                "mark",
                "mark requires endpoint, param, vuln_class "
                '(status optional, defaults to "tried")',
            )

        if status not in STATUSES:
            return self._error(
                "mark",
                f"status must be one of: {', '.join(STATUSES)}",
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
                "action": "mark",
                "created": entry.count == 1,
                "updated": entry.count > 1,
                "entry": {
                    **entry_dict,
                    "endpoint": self._brief(entry.endpoint),
                    "param": self._brief(entry.param),
                    "vulnClass": self._brief(entry.vulnClass),
                    "notes": self._brief(entry.notes, COLLECTION_NOTES_LIMIT),
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
        if status and status not in STATUSES:
            return self._error(
                "list",
                f"status must be one of: {', '.join(STATUSES)}",
            )
        if not status:
            status = None

        rows = await self.store.list(
            endpoint=endpoint,
            param=param,
            vulnClass=vuln_class,
            status=status,
        )

        out: list[dict[str, Any]] = []

        for e in rows:
            out.append(
                {
                    "endpoint": self._brief(e.endpoint),
                    "param": self._brief(e.param),
                    "vuln_class": self._brief(e.vulnClass),
                    "status": e.status,
                    "count": e.count,
                    "first_seen": datetime.fromtimestamp(
                        e.firstSeen / 1000
                    ).isoformat(),
                    "last_seen": datetime.fromtimestamp(
                        e.lastSeen / 1000
                    ).isoformat(),
                    "notes": self._brief(e.notes, COLLECTION_NOTES_LIMIT),
                }
            )

        return self._page("list", out, args)

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
            return self._error(
                "untested",
                "untested requires `candidates` (non-empty list "
                "of {endpoint, param}) and `vuln_classes` (non-empty "
                "list of strings)",
            )

        out = await self.store.untested(
            pairs,
            classes,
        )

        bounded = [
            {
                "endpoint": self._brief(item["endpoint"]),
                "param": self._brief(item["param"]),
                "vulnClass": self._brief(item["vulnClass"]),
            }
            for item in out
        ]
        return self._page("untested", bounded, args)

    async def run_summary(self) -> str:
        summary = await self.store.summary()
        ordered_classes = sorted(
            summary.byVulnClass.items(),
            key=lambda item: (-item[1], item[0]),
        )
        selected = ordered_classes[:SUMMARY_VULN_CLASS_LIMIT]
        return json.dumps(
            {
                "ok": True,
                "action": "summary",
                "total": summary.total,
                "byStatus": summary.byStatus,
                "vulnClassCount": len(ordered_classes),
                "returnedVulnClassCount": len(selected),
                "vulnClassesComplete": len(selected) == len(ordered_classes),
                "topVulnClasses": [
                    {
                        "vuln_class": self._brief(name),
                        "count": count,
                    }
                    for name, count in selected
                ],
            },
            indent=2,
        )

    @staticmethod
    def _brief(
        value: str | None,
        limit: int = COLLECTION_TEXT_LIMIT,
    ) -> str | None:
        if value is None:
            return None
        return value[:limit]

    @staticmethod
    def _error(action: str, message: str) -> str:
        return json.dumps(
            {
                "ok": False,
                "action": action[:40],
                "error": message[:500],
            },
            indent=2,
        )

    def _page(
        self,
        action: str,
        items: list[dict[str, Any]],
        args: dict[str, Any],
    ) -> str:
        parsed = self._page_request(action, args, len(items))
        if isinstance(parsed, str):
            return parsed
        offset, limit = parsed
        selected = items[offset : offset + limit]

        while True:
            payload = self._page_payload(
                action,
                selected,
                total_count=len(items),
                offset=offset,
                limit=limit,
            )
            rendered = json.dumps(payload, indent=2)
            if len(rendered) <= MAX_COLLECTION_RESULT_CHARS or len(selected) <= 1:
                return rendered
            selected.pop()

    def _page_request(
        self,
        action: str,
        args: dict[str, Any],
        total_count: int,
    ) -> tuple[int, int] | str:
        raw_limit = args.get("limit")
        if raw_limit is None:
            limit = DEFAULT_PAGE_SIZE
        elif (
            isinstance(raw_limit, bool)
            or not isinstance(raw_limit, (int, float))
            or not float(raw_limit).is_integer()
            or raw_limit <= 0
        ):
            return self._error(action, "limit must be a positive integer")
        else:
            limit = min(int(raw_limit), MAX_PAGE_SIZE)

        raw_cursor = args.get("cursor")
        if raw_cursor is None:
            offset = 0
        elif not isinstance(raw_cursor, str) or not raw_cursor.isdigit():
            return self._error(
                action,
                "cursor must be a non-negative integer string",
            )
        elif len(raw_cursor) > 12:
            return self._error(action, "cursor is outside the supported range")
        else:
            offset = int(raw_cursor)

        if offset > total_count:
            return self._error(
                action,
                f"cursor {offset} is past total_count {total_count}",
            )
        return offset, limit

    @staticmethod
    def _page_payload(
        action: str,
        items: list[dict[str, Any]],
        *,
        total_count: int,
        offset: int,
        limit: int,
    ) -> dict[str, Any]:
        returned_count = len(items)
        next_offset = offset + returned_count
        has_more = next_offset < total_count
        complete = offset == 0 and not has_more
        next_cursor = str(next_offset) if has_more else None
        page_metadata = {
            "returned_count": returned_count,
            "total_count": total_count,
            "complete": complete,
            "has_more": has_more,
            "next_cursor": next_cursor,
        }
        return {
            "ok": True,
            "action": action,
            **page_metadata,
            "cursor": str(offset),
            "limit": limit,
            "items": items,
            # The tail copy lets distributed-window reduction retain an
            # explicit completeness signal when middle JSON is omitted.
            "page_end": page_metadata,
        }
