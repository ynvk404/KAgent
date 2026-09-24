from __future__ import annotations

import json
import re
from datetime import datetime, UTC
from typing import Callable, TypeGuard, Any
from urllib.parse import urlparse

from src.findings.store import (
    Finding,
    Store,
    Severity,
    slugify,
)
from src.findings.classification import classify
from src.permission.permission import Prompter
from src.redact.redact import apply as redact
from src.logger.logger import get_logger
from src.workflow.state import WorkflowState
from src.skills.registry import normalize_candidate_class
from src.target.origin import HTTPOrigin
from .types import Tool, arg_string

SEVERITIES: tuple[Severity, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)

FindingNotifier = Callable[[Finding, str], None]
log = get_logger("tools.finding")

class ConfirmFindingTool:
    def __init__(
        self,
        store: Store,
        notifier: FindingNotifier | None = None,
        workflow: WorkflowState | None = None,
    ) -> None:
        self.store = store
        self.notifier = notifier or (lambda *_: None)
        self.workflow = workflow

    def name(self) -> str:
        return "confirm_finding"

    def description(self) -> str:
        return (
            "Persist a CONFIRMED vulnerability finding. "
            "Call this ONLY after you have reproduced the bug "
            "end-to-end with a real request and observed a "
            "response that proves it.\n\n"
            "Writes a markdown report under "
            "./artifacts/findings/<slug>.md and surfaces a banner in the "
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
                "candidate_id": {
                    "type": "string",
                    "description": (
                        "Optional structured Candidate ID. When supplied, its "
                        "latest ValidationResult must be confirmed."
                    ),
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
                "vuln_class": {
                    "type": "string",
                    "description": (
                        "Canonical class used by Workflow/Coverage, such as "
                        "sql-injection, cross-site-scripting, access-control, "
                        "or ssrf. Classification supplies CWE/OWASP values."
                    ),
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

    def context_reduction_policy(self) -> str:
        """Preserve persistence success/failure and the final report path."""
        return "preserve"

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
        candidate_id = arg_string(args, "candidate_id")

        if not title:
            raise Exception("title is required")

        if not url:
            raise Exception("url is required")

        if not impact:
            raise Exception("impact is required")

        if candidate_id and self.workflow is None:
            raise ValueError("candidate ID requires workflow state")

        if (
            candidate_id
            and self.workflow is not None
            and not self.workflow.eligible_for_finding(candidate_id)
        ):
            raise Exception(
                "candidate is not eligible for confirm_finding: its latest "
                "ValidationResult must have outcome=confirmed and registered evidence"
            )

        evidence_refs: list[str] | None = None
        if candidate_id and self.workflow is not None:
            candidate = self.workflow.candidates[candidate_id]
            latest = self.workflow.latest_result(candidate_id)
            assert latest is not None
            root = self.store.project_dir
            if not all(
                self.workflow.evidence[ref].is_resolvable_for_resume(root)
                for ref in latest.evidence_refs
            ):
                raise ValueError("candidate evidence artifact changed or is unavailable")
            requested_class = arg_string(args, "vuln_class")
            if requested_class and normalize_candidate_class(requested_class) != candidate.candidate_class:
                raise ValueError("finding class does not match candidate class")
            if candidate.target:
                try:
                    if HTTPOrigin.from_url(url) != HTTPOrigin.from_url(candidate.target):
                        raise ValueError("finding target does not match candidate target")
                except ValueError as exc:
                    raise ValueError("finding target does not match candidate target") from exc
            if candidate.endpoint:
                expected_path = urlparse(candidate.endpoint).path
                actual_path = urlparse(url).path
                template = re.escape(expected_path).replace(r"\{", "{").replace(r"\}", "}")
                template = re.sub(r"\{[^{}]+\}", r"[^/]+", template)
                if not re.fullmatch(template, actual_path):
                    raise ValueError("finding endpoint does not match candidate endpoint")
            requested_method = arg_string(args, "method")
            if candidate.method and requested_method and requested_method.upper() != candidate.method:
                raise ValueError("finding method does not match candidate method")
            evidence_refs = list(latest.evidence_refs)

        if not is_severity(severity):
            raise Exception(
                "severity must be one of: "
                + ", ".join(SEVERITIES)
            )

        classification = classify(
            arg_string(args, "vuln_class")
            or (
                self.workflow.candidates[candidate_id].candidate_class
                if candidate_id and self.workflow is not None else ""
            )
        )
        redacted_title = redact(title)

        finding = Finding(
            # Finding reports are durable evidence artifacts.  Preserve the
            # minimum useful reproduction details, but never write credentials
            # or session material supplied in tool arguments verbatim.
            title=redacted_title,
            severity=severity,
            url=redact(url),
            impact=redact(impact),
            method=redact(arg_string(args, "method")) or None,
            parameter=redact(arg_string(args, "parameter")) or None,
            payload=redact(arg_string(args, "payload")) or None,
            responseExcerpt=redact(arg_string(args, "response_excerpt")) or None,
            curl=redact(arg_string(args, "curl")) or None,
            remediation=redact(arg_string(args, "remediation")) or None,
            vulnerabilityType=(classification.type if classification else None),
            cwe=(classification.cwe if classification else None),
            owasp=(classification.owasp if classification else None),
            createdAt=datetime.now(UTC).isoformat(),
            slug=slugify(redacted_title) or f"finding-{int(datetime.now(UTC).timestamp())}",
            candidate_id=candidate_id or None,
            evidence_refs=evidence_refs,
        )

        path = await self.store.save(finding)

        try:
            self.notifier(finding, path)
        except Exception:
            # Persistence succeeded.  Reporting a tool failure here invites a
            # retry, which would create a duplicate numbered report.
            log.warning("finding notifier failed after persistence", exc_info=True)

        return f'Finding "{finding.title}" written to {path}'

def is_severity(value: str) -> TypeGuard[Severity]:
    return value in SEVERITIES
