from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from dataclasses import asdict
from src.coverage.store import CoverageStore, CoverageStatus
from src.coverage.context import CoverageContext, normalize_contextual_endpoint
from src.permission.permission import Prompter
from src.tools.common.types import Tool, PermissionHints, arg_string

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
            "Progress projection, never proof/completion. context selects exact variants; "
            "omit for legacy unspecified mark/untested. list shows context. "
            "Summaries do not prove siblings tested. Classes normalize. "
            "list/untested paginate via next_cursor; complete=true means full set."
        )

    def schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "context": self._context_schema(),
                "action": {
                    "type": "string",
                    "enum": list(ACTIONS),
                    "description": (
                        "clear erases coverage after permission."
                    ),
                },
                "endpoint": {
                    "type": "string",
                    "description": (
                        "mark/list: GET /api/users/{id}; strips query."
                    ),
                },
                "param": {
                    "type": "string",
                    "description": (
                        "mark/exact list parameter."
                    ),
                },
                "vuln_class": {
                    "type": "string",
                    "description": (
                        "Class or alias."
                    ),
                },
                "status": {
                    "type": "string",
                    "enum": list(STATUSES),
                    "description": (
                        "Test status."
                    ),
                },
                "notes": {
                    "type": "string",
                    "description": "Short note.",
                },
                "candidates": {
                    "type": "array",
                    "description": (
                        "untested: endpoint/param/context crossed with vuln_classes."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "endpoint": {"type": "string"},
                            "param": {"type": "string"},
                            "context": {"type": "object"},
                        },
                        "required": ["endpoint", "param"],
                    },
                },
                "vuln_classes": {
                    "type": "array",
                    "description": (
                        "untested classes."
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
                        "list/untested: next_cursor offset; reuse filters."
                    ),
                },
            },
            "required": ["action"],
        }

    def requires_permission(self) -> bool:
        return False

    def requires_permission_for(self, args: dict[str, Any]) -> bool:
        return arg_string(args, "action") == "clear"

    def permission_hints(self, args: dict[str, Any]) -> PermissionHints:
        if arg_string(args, "action") == "clear":
            return {"noSessionCache": True, "riskTier": "high-impact"}
        return {}

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
            from src.permission.runtime.execution import policy_for
            if policy_for(prompter) is not None:
                return self._error("mark", "unverified: model mark cannot establish tested coverage; use verifier-backed workflow")
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

        try:
            context = CoverageContext.parse(args["context"]) if "context" in args else None
            if context is not None:
                normalize_contextual_endpoint(endpoint, context)
        except ValueError as err:
            return self._error("mark", str(err))
        previous = await self.store.get(
            endpoint=endpoint, param=param, vulnClass=vuln_class, context=context,
        )
        previous_count = previous.count if previous else 0
        entry = await self.store.mark(
            endpoint=endpoint,
            param=param,
            vulnClass=vuln_class,
            status=status,
            notes=notes,
            context=context,
        )

        entry_dict = asdict(entry)

        return json.dumps(
            {
                "ok": True,
                "action": "mark",
                "created": previous is None,
                "updated": previous is not None and entry.count > previous_count,
                "deduplicated": previous is not None and entry.count == previous_count,
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

        try:
            context = CoverageContext.parse(args["context"]) if "context" in args else None
            if endpoint and context is not None:
                normalize_contextual_endpoint(endpoint, context)
        except ValueError as err:
            return self._error("list", str(err))
        rows = await self.store.list(
            endpoint=endpoint,
            param=param,
            vulnClass=vuln_class,
            status=status,
            context=context,
        )

        out: list[dict[str, Any]] = []

        for e in rows:
            out.append(
                {
                    "endpoint": self._brief(e.endpoint),
                    "param": self._brief(e.param),
                    "vuln_class": self._brief(e.vulnClass),
                    "status": e.status,
                    "context": asdict(e.context) if e.context is not None else None,
                    "view": "contextual" if e.context is not None else "legacy-unspecified",
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
        try:
            default_context = CoverageContext.parse(args["context"]) if "context" in args else None
        except ValueError as err:
            return self._error("untested", str(err))
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
                pair: dict[str, Any] = {"endpoint": endpoint, "param": param}
                if "context" in c:
                    pair["context"] = c["context"]
                elif default_context is not None:
                    pair["context"] = asdict(default_context)
                pairs.append(pair)

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

        try:
            out = await self.store.untested(pairs, classes)
        except ValueError as err:
            return self._error("untested", str(err))

        bounded = [
            {
                "endpoint": self._brief(item["endpoint"]),
                "param": self._brief(item["param"]),
                "vulnClass": self._brief(item["vulnClass"]),
                **({"context": item["context"]} if "context" in item else {}),
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
                "view": "projection-summary",
                "variant_proof": False,
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
    def _context_schema() -> dict[str, Any]:
        return {
            "type": "object",
            "description": (
                "Identity strings/null: objective_id, target_origin, method, location, media_type, "
                "auth_context_ref, test_case. Missing=unknown. Also in untested candidates. No credentials."
            ),
        }

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
