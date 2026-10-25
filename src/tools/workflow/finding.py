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
from src.redaction.redact import apply as redact, apply_evidence
from src.logger.logger import get_logger
from src.workflow.state import WorkflowState
from src.workflow.evidence.artifacts import verify_evidence_reads
from src.workflow.evidence.review import review_snapshot, confirmation_binding
from src.workflow.assessment import accepted_result
from src.skills.registry import normalize_candidate_class
from src.target.origin import HTTPOrigin
from src.workflow.validation.route import GENERIC_VALIDATOR
from src.tools.common.outcome import ToolOutput, annotate_error
from src.tools.common.types import Tool, arg_string

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
        *,
        export_summary: bool = True,
    ) -> None:
        self.store = store
        self.notifier = notifier or (lambda *_: None)
        self.workflow = workflow
        self._export_summary = export_summary

    def persisted_context(self, candidate_id: str):
        """Bind one existing report to its unchanged confirmed assessment."""
        state = self.workflow
        if state is None or not state.finding_is_persisted(candidate_id):
            raise ValueError("persisted finding required for summary export")
        candidate = state.candidates[candidate_id]
        latest = state.latest_result(candidate_id)
        assert latest is not None
        snapshot = review_snapshot(state, candidate_id)
        generation = state.generation
        artifacts = [state.evidence[ref] for ref in latest.evidence_refs]

        def guard(finding: Finding) -> None:
            if (self.workflow is not state or state.generation != generation
                    or review_snapshot(state, candidate_id) != snapshot
                    or not state.finding_is_persisted(candidate_id)
                    or not state.eligible_for_finding(candidate_id)
                    or finding.candidate_id != candidate_id
                    or finding.canonical_class != candidate.candidate_class
                    or finding.confirmation_binding != confirmation_binding(state, candidate_id)
                    or finding.evidence_refs != latest.evidence_refs
                    or finding.binding_version != latest.assessment_contract_version
                    or finding.assessment_result_id != latest.result_id
                    or finding.assessment_attempt_id != latest.attempt_id):
                raise ValueError("finding summary does not match current validation")
            if latest.assessment_contract_version >= 2 and (
                    finding.assessment_source != latest.assessment_source
                    or finding.severity != latest.assessment.get("severity")
                    or finding.observed_impact != apply_evidence(
                        latest.assessment.get("observed_impact", "")).strip("\n")):
                raise ValueError("finding summary assessment changed")
            if ((candidate.method and finding.method != candidate.method)
                    or (candidate.parameter and finding.parameter != redact(candidate.parameter))
                    or (candidate.target and HTTPOrigin.from_url(finding.url) != HTTPOrigin.from_url(candidate.target))):
                raise ValueError("finding summary endpoint identity changed")
            if candidate.endpoint:
                endpoint = re.sub(r"^\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", "",
                                  candidate.endpoint, count=1, flags=re.I)
                template = re.escape(urlparse(endpoint).path).replace(r"\{", "{").replace(r"\}", "}")
                template = re.sub(r"\{[^{}]+\}", r"[^/]+", template)
                if not re.fullmatch(template, urlparse(finding.url).path):
                    raise ValueError("finding summary endpoint identity changed")

        return candidate, latest, artifacts, guard

    async def write_summary(self, candidate_id: str) -> str | None:
        """Export only a persisted current Finding; retries regenerate the derivative."""
        if not self._export_summary:
            return None
        from src.findings.presentation import SummaryContext
        candidate, latest, artifacts, guard = self.persisted_context(candidate_id)
        return await self.store.export_summary(
            candidate_id, SummaryContext.from_validation(candidate, latest), artifacts, guard=guard,
        )

    def name(self) -> str:
        return "confirm_finding"

    def description(self) -> str:
        return (
            "Persist reproducible confirmed findings to ./artifacts/findings/<slug>.md with a TUI banner. "
            "Require candidate_id with latest confirmed result and integrity-checked registered evidence. "
            "No theoretical/unverified scanner hits."
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
                    "minLength": 1,
                    "description": (
                        "Returned Candidate ID."
                    ),
                },
                "severity": {
                    "type": "string",
                    "enum": list(SEVERITIES),
                    "description": (
                        "Bugcrowd VRT P1–P5: critical/high/medium/low/info."
                    ),
                },
                "url": {
                    "type": "string",
                    "description": "Exact URL matching Candidate origin/path.",
                },
                "parameter": {
                    "type": "string",
                    "description": "Match recorded Candidate parameter.",
                },
                "payload": {
                    "type": "string",
                    "description": "Exact payload.",
                },
                "method": {
                    "type": "string",
                    "description": "Match recorded Candidate HTTP method.",
                },
                "response_excerpt": {
                    "type": "string",
                    "description": "Response snippet.",
                },
                "observed_impact": {
                    "type": "string",
                    "description": (
                        "Only impact shown by linked validation evidence; never treat untested consequences as facts."
                    ),
                },
                "potential_impact": {
                    "type": "string",
                    "description": (
                        "Untested consequences are conditional; if none: "
                        "'No additional impact assessed.'"
                    ),
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
                        "Canonical Workflow/Coverage class matching Candidate; CWE/OWASP auto-assigned."
                    ),
                },
            },
            "required": [
                "title",
                "candidate_id",
                "severity",
                "url",
                "observed_impact",
                "potential_impact",
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
        observed_impact = arg_string(args, "observed_impact")
        potential_impact = arg_string(args, "potential_impact")
        raw_candidate_id = args.get("candidate_id")
        candidate_id = raw_candidate_id.strip() if isinstance(raw_candidate_id, str) else ""

        if not title:
            raise Exception("title is required")

        if not url:
            raise Exception("url is required")

        if not is_severity(severity):
            raise ValueError("severity must be one of: " + ", ".join(SEVERITIES))
        if not candidate_id:
            raise ValueError("candidate_id is required and must be a non-empty string")

        if not observed_impact:
            raise ValueError("observed_impact is required")

        if not potential_impact:
            raise ValueError("potential_impact is required")

        if self.workflow is None:
            raise ValueError("workflow state is required to confirm a finding")

        candidate = self.workflow.candidates.get(candidate_id)
        if candidate is None:
            raise ValueError(f"unknown candidate: {candidate_id}")

        if (
            not self.workflow.eligible_for_finding(candidate_id)
        ):
            raise Exception(
                "candidate is not eligible for confirm_finding: its latest "
                "ValidationResult must have outcome=confirmed and registered evidence"
            )

        latest = self.workflow.latest_result(candidate_id)
        assert latest is not None  # eligibility above guarantees a result
        result_snapshot = review_snapshot(self.workflow, candidate_id)
        evidence_artifacts = [self.workflow.evidence[ref] for ref in latest.evidence_refs]
        evidence_read_approvals: set[str] = set()
        from src.permission.runtime.execution import policy_for
        policy = policy_for(prompter)
        generic = latest.skill_name == GENERIC_VALIDATOR
        def check_generic():
            if generic:
                if policy is None or policy.generic_validation is None:
                    raise ValueError("generic finding requires runtime policy/current objective")
                policy.generic_validation.require(candidate_id)
                policy.generic_validation.idle()
                if self.workflow is not policy.generic_validation.state:
                    raise ValueError("generic finding workflow context changed")
        check_generic()
        generic_snapshot = None
        if generic:
            assert policy is not None
            generic_snapshot = policy.generic_validation.snapshot(candidate_id)
        def check_generic_snapshot():
            check_generic()
            if generic_snapshot is not None:
                assert policy is not None
                policy.generic_validation.unchanged(candidate_id, generic_snapshot)
                if not accepted_result(self.workflow, candidate, latest, policy):
                    raise ValueError("generic finding assessment evidence changed")
        if not accepted_result(self.workflow, candidate, latest, policy):
            raise ValueError("current accepted confirmed assessment with intact primary evidence required")
        if latest.assessment_contract_version >= 2:
            observed_impact = latest.assessment["observed_impact"]
            severity = latest.assessment["severity"]
            response_excerpt = latest.assessment.get("response_excerpt", "")
        else:
            assert policy is not None
            legacy = policy.observations.result(candidate_id, tuple(latest.evidence_refs),
                                               policy.engagement.http_permissions.epoch, candidate)
            assert legacy is not None
            observed_impact, severity, response_excerpt = legacy.observed_impact, legacy.severity, legacy.response_excerpt
        root = self.store.project_dir
        if not await verify_evidence_reads(
            evidence_artifacts, root, prompter, signal,
            approved_paths=evidence_read_approvals,
        ):
            raise ValueError("candidate evidence artifact changed or is unavailable")
        if review_snapshot(self.workflow, candidate_id) != result_snapshot:
            raise ValueError("candidate validation result changed during finalization")
        check_generic_snapshot()

        requested_class = arg_string(args, "vuln_class").strip()
        if requested_class and normalize_candidate_class(requested_class) != candidate.candidate_class:
            raise ValueError("finding class does not match candidate class")
        if candidate.target:
            try:
                if HTTPOrigin.from_url(url) != HTTPOrigin.from_url(candidate.target):
                    raise ValueError("finding target does not match candidate target")
            except ValueError as exc:
                raise ValueError("finding target does not match candidate target") from exc
        if candidate.endpoint:
            candidate_endpoint = re.sub(
                r"^\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+",
                "",
                candidate.endpoint,
                count=1,
                flags=re.IGNORECASE,
            )
            expected_path = urlparse(candidate_endpoint).path
            actual_path = urlparse(url).path
            template = re.escape(expected_path).replace(r"\{", "{").replace(r"\}", "}")
            template = re.sub(r"\{[^{}]+\}", r"[^/]+", template)
            if not re.fullmatch(template, actual_path):
                raise ValueError("finding endpoint does not match candidate endpoint")

        requested_method = arg_string(args, "method").strip()
        if candidate.method and requested_method and requested_method.upper() != candidate.method:
            raise ValueError("finding method does not match candidate method")
        requested_parameter = arg_string(args, "parameter").strip()
        if candidate.parameter and requested_parameter and requested_parameter != candidate.parameter:
            raise ValueError("finding parameter does not match candidate parameter")
        evidence_refs = list(latest.evidence_refs)

        if not is_severity(severity):
            raise Exception(
                "severity must be one of: "
                + ", ".join(SEVERITIES)
            )

        classification = classify(candidate.candidate_class)
        redacted_title = redact(title)
        from src.workflow.assessment import assessment_provenance
        provenance = assessment_provenance(self.workflow, candidate, latest, policy)
        source_label = latest.assessment_source if latest.assessment_contract_version >= 2 else provenance["source"]

        finding = Finding(
            # Finding reports are durable evidence artifacts.  Preserve the
            # minimum useful reproduction details, but never write credentials
            # or session material supplied in tool arguments verbatim.
            title=redacted_title,
            severity=severity,
            url=redact(url),
            observed_impact=apply_evidence(observed_impact),
            potential_impact=redact(potential_impact),
            method=redact(candidate.method or requested_method.upper()) or None,
            parameter=redact(candidate.parameter or requested_parameter) or None,
            payload=redact(arg_string(args, "payload")) or None,
            responseExcerpt=apply_evidence(response_excerpt) or None,
            curl=redact(arg_string(args, "curl")) or None,
            remediation=redact(arg_string(args, "remediation")) or None,
            vulnerabilityType=(classification.type if classification else None),
            cwe=(classification.cwe if classification else None),
            owasp=(classification.owasp if classification else None),
            createdAt=datetime.now(UTC).isoformat(),
            slug=slugify(redacted_title) or f"finding-{int(datetime.now(UTC).timestamp())}",
            candidate_id=candidate_id,
            evidence_refs=evidence_refs,
            canonical_class=candidate.candidate_class,
            confirmation_binding=confirmation_binding(self.workflow, candidate_id),
            assessment_source=source_label,
            assessment_result_id=latest.result_id,
            assessment_attempt_id=latest.attempt_id,
            binding_version=latest.assessment_contract_version,
            classification_provenance=(
                {"origin": "verified-local", "selected_cwe": classification.cwe[0], "revision": 1}
                if classification and classification.cwe else None
            ),
            classification_revision=(1 if classification and classification.cwe else 0),
        )

        check_generic_snapshot()
        try:
            path = await self.store.save(finding)
        except Exception as error:
            annotate_error(error, "persistence")
            raise
        if review_snapshot(self.workflow, candidate_id) != result_snapshot:
            raise ValueError("candidate validation result changed during finalization")
        if (finding.confirmation_binding != confirmation_binding(self.workflow, candidate_id)
                or finding.binding_version != latest.assessment_contract_version
                or finding.assessment_result_id != latest.result_id
                or (latest.assessment_contract_version >= 2 and finding.assessment_source != source_label)
                or finding.evidence_refs != latest.evidence_refs):
            raise ValueError('Historical report does not match the current assessment revision. Finding remains pending.')

        # Store.save() may wait on disk while the workflow advances. A report
        # may already have been written, but it must not be finalized or
        # announced as matching a result that changed during that wait.
        if review_snapshot(self.workflow, candidate_id) != result_snapshot:
            raise ValueError("candidate validation result changed during finalization")
        check_generic_snapshot()
        if not await verify_evidence_reads(
            evidence_artifacts, root, prompter, signal,
            approved_paths=evidence_read_approvals,
        ):
            raise ValueError("candidate evidence artifact changed or is unavailable")
        if review_snapshot(self.workflow, candidate_id) != result_snapshot:
            raise ValueError("candidate validation result changed during finalization")
        check_generic_snapshot()

        if not accepted_result(self.workflow, candidate, latest, policy):
            raise ValueError("assessment evidence changed during Finding persistence")
        # A confirmed ValidationResult and a persisted canonical report are
        # separate workflow facts.  Record the latter only after the atomic
        # store write (or idempotent candidate lookup) has succeeded so a
        # malformed/missed tool call cannot make whole-target completion lie.
        self.workflow.mark_finding_persisted(candidate_id)

        enrichment_notice = ''
        if not finding.cwe:
            from src.findings.cwe_review import enrich_missing
            try:
                finding, enrichment_notice = await enrich_missing(self, candidate_id, policy)
            except Exception:
                # Finding persistence is already committed. Enrichment failure
                # never revokes evidence, creates another report or retests it.
                log.warning('automatic CWE enrichment unavailable after Finding persistence')
                enrichment_notice = 'CWE enrichment review/persistence unavailable; inspect the saved report or use /cwe.'
            if not await verify_evidence_reads(
                evidence_artifacts, root, prompter, signal, approved_paths=evidence_read_approvals,
            ):
                raise ValueError('candidate evidence artifact changed during CWE enrichment')
        if review_snapshot(self.workflow, candidate_id) != result_snapshot:
            raise ValueError('candidate validation result changed during CWE enrichment')
        check_generic_snapshot()
        if not accepted_result(self.workflow, candidate, latest, policy):
            raise ValueError('assessment evidence changed during CWE enrichment')

        summary_notice = ""
        export_failed = False
        try:
            summary_path = await self.write_summary(candidate_id)
            if summary_path:
                summary_notice = f"\nCompact report written to {summary_path}"
        except Exception:
            # Canonical persistence is already committed. A derivative failure
            # must not revoke it or encourage retesting; retry the same Candidate.
            summary_notice = (
                "\nFinding persisted; compact report export failed. "
                "Retry confirm_finding with the same candidate_id to regenerate the report."
            )
            export_failed = True
            log.warning("compact finding report export failed")

        try:
            self.notifier(finding, path)
        except Exception:
            # Persistence succeeded.  Reporting a tool failure here invites a
            # retry, which would create a duplicate numbered report.
            log.warning("finding notifier failed after persistence", exc_info=True)

        if review_snapshot(self.workflow, candidate_id) != result_snapshot:
            raise ValueError("candidate validation result changed during finalization")

        return ToolOutput(f'Finding "{finding.title}" written to {path}\n'
                f'Classification: {finding.vulnerabilityType or "unknown"} · '
                f'CWE: {", ".join(finding.effective_cwe) or "none"} · '
                f'OWASP: {", ".join(finding.owasp or []) or "none"}' + summary_notice
                + ('\n' + enrichment_notice if enrichment_notice else ''),
                presentation_impact="persistence" if export_failed else None)

def is_severity(value: str) -> TypeGuard[Severity]:
    return value in SEVERITIES
