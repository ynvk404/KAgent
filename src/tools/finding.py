from __future__ import annotations

import json
from datetime import datetime
from typing import Callable, TypeGuard, Any

from src.findings.store import (
    Finding,
    Store,
    Severity,
    slugify,
)

from src.permission.permission import Prompter
from .types import Tool, arg_string

SEVERITIES: tuple[Severity, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)

FindingNotifier = Callable[[Finding, str], None]


class ConfirmFindingTool:

    def __init__(
        self,
        store: Store,
        notifier: FindingNotifier | None = None,
    ) -> None:
        self.store = store
        self.notifier = notifier or (lambda *_: None)

    def name(self) -> str:
        return "confirm_finding"

    def description(self) -> str:
        return (
            "Persist a CONFIRMED vulnerability finding. "
            "Call this ONLY after you have reproduced the bug "
            "end-to-end with a real request and observed a "
            "response that proves it.\n\n"
            "Writes a markdown report under "
            "./findings/<slug>.md and surfaces a banner in the "
            "TUI. Do not call for theoretical findings, scanner "
            "hits you haven't manually verified, or "
            "'suspected' behavior."
        )

    def schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short descriptive title.",
                },
                "severity": {
                    "type": "string",
                    "enum": list(SEVERITIES),
                    "description": (
                        "Severity (Bugcrowd VRT "
                        "P1–P5 → critical/high/medium/low/info)."
                    ),
                },
                "url": {
                    "type": "string",
                    "description": "Exact affected endpoint URL.",
                },
                "parameter": {
                    "type": "string",
                    "description": "Parameter injected/abused.",
                },
                "payload": {
                    "type": "string",
                    "description": "Exact payload.",
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method.",
                },
                "response_excerpt": {
                    "type": "string",
                    "description": "Response snippet.",
                },
                "impact": {
                    "type": "string",
                    "description": "Concrete impact.",
                },
                "curl": {
                    "type": "string",
                    "description": "Reproduction curl.",
                },
                "remediation": {
                    "type": "string",
                    "description": "Optional remediation.",
                },
            },
            "required": [
                "title",
                "severity",
                "url",
                "impact",
            ],
        }

    def requires_permission(self) -> bool:
        return False

    def summarize(self, args: dict) -> dict:
        title = arg_string(args, "title")
        severity = arg_string(args, "severity")

        return {
            "summary": f"finding ({severity}): {title}",
            "detail": json.dumps(args, indent=2),
        }

    async def run(
        self,
        args: dict[str, Any],
        signal: Any,
        prompter: Prompter,
    ) -> str:

        title = arg_string(args, "title")
        severity = arg_string(args, "severity").lower()
        url = arg_string(args, "url")
        impact = arg_string(args, "impact")

        if not title:
            raise Exception("title is required")

        if not url:
            raise Exception("url is required")

        if not impact:
            raise Exception("impact is required")

        if not is_severity(severity):
            raise Exception(
                "severity must be one of: "
                + ", ".join(SEVERITIES)
            )
        finding = Finding(
            title=title,
            severity=severity,
            url=url,
            impact=impact,
            method=arg_string(args, "method") or None,
            parameter=arg_string(args, "parameter") or None,
            payload=arg_string(args, "payload") or None,
            responseExcerpt=arg_string(args, "response_excerpt") or None,
            curl=arg_string(args, "curl") or None,
            remediation=arg_string(args, "remediation") or None,
            createdAt=datetime.utcnow().isoformat(),
            slug=slugify(title) or f"finding-{int(datetime.utcnow().timestamp())}",
        )

        path = await self.store.save(finding)

        self.notifier(finding, path)

        return f'Finding "{finding.title}" written to {path}'


def is_severity(value: str) -> TypeGuard[Severity]:
    return value in SEVERITIES