"""Presentation admission. No traffic retention, execution or persistence."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from src.agent.events import Invocation, SkillActiveEvent, ToolCallEvent, ToolResultEvent
from src.ui.render.sanitize import sanitize_text
from src.ui.render.shell_outcome import shell_issues


@dataclass(frozen=True, slots=True)
class PendingCall:
    id: str
    name: str
    operation: str
    identity: str
    search: bool = False
    candidate_id: str = ""
    activity: str = ""
    recovery_identity: str = ""
    scope: str = ""
    skill: str = ""
    attempt_id: str = ""
    invocation: Invocation | None = None
    retired: bool = False
    resolved: bool = False
    http_redirects: bool = False
    dispatch_order: int = 0
    retry_of: str = ""
    resource: str = ""
    result_expectations: tuple[tuple[str, str], ...] = ()


def result_field_digest(key: str, value) -> str:
    if key in {'evidence_refs', 'observation_ids'} and isinstance(value, list) and all(isinstance(ref, str) for ref in value):
        value = sorted(value)
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def result_matches_call(call: PendingCall, recorded: dict) -> bool:
    values = dict(recorded)
    values['observation_ids'] = [entry['source']['id'] for entry in recorded.get('evidence_manifest', [])
                                if isinstance(entry.get('source'), dict) and entry['source'].get('id')]
    return all(result_field_digest(key, values.get(key)) == expected
               for key, expected in call.result_expectations)


def invocation_call(calls: tuple[PendingCall, ...],
                    event: ToolCallEvent | ToolResultEvent | SkillActiveEvent) -> PendingCall | None:
    identifier = event.call_id if isinstance(event, SkillActiveEvent) else event.id
    name = 'load_skill' if isinstance(event, SkillActiveEvent) else event.name
    return next((call for call in calls if identifier and call.id == identifier and call.name == name
                 and call.invocation == event.invocation), None)


def call_metadata(ev: ToolCallEvent) -> PendingCall:
    args = ev.args
    if not args and ev.args_json:
        try:
            parsed = json.loads(ev.args_json)
            args = parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            args = {}
    command = args.get("command", "")
    # Exit 1 means no matches only for a simple search, never a pipeline.
    search = (ev.name in {"shell", "bash", "BashTool"} and isinstance(command, str)
              and bool(re.match(r"^\s*(?:rg|grep)\s", command))
              and not any(token in command for token in ("|", ";", "&&", "\n")))
    operation = args.get("action", "") if ev.name == "workflow" else ""
    candidate_id = args.get("candidate_id", "")
    identity_args = args
    if ev.name == "http":
        # Hash the complete requested intent, including values/body/auth/profile.
        # Effective native receipt matching provides the second runtime check.
        identity_args = args
    elif ev.name in {"workflow", "confirm_finding"}:
        identity_args = {key: args.get(key) for key in
                         ("action", "candidate_id", "result_id", "attempt_id", "skill_name", "phase",
                          "target", "endpoint", "method", "parameter", "input_id", "goal_id", "artifact_ref", "force")}
    identity = hashlib.sha256(json.dumps(identity_args, sort_keys=True, default=str).encode()).hexdigest()
    recovery_identity = hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()
    if ev.name == "workflow" and operation == "record_result":
        recovery_identity = identity
    activity = ""
    if (ev.name == "http" and args.get("url")) or args.get("endpoint"):
        endpoint = str(args.get("url") or args.get("endpoint") or "")
        method = str(args.get('method') or '').upper()
        # Presentation only: coverage endpoints may already use METHOD /path.
        prefixed = re.match(r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S.*)$", endpoint, re.I)
        if prefixed:
            method = method or prefixed.group(1).upper()
            endpoint = prefixed.group(2)
        try:
            path = urlsplit(endpoint).path or "/"
        except ValueError:
            path = "[invalid endpoint]"
        parameter = args.get("parameter")
        activity = sanitize_text(f"{method or 'GET'} {path}" +
                                 (f" · input {parameter}" if parameter else ""))
    elif operation:
        activity = sanitize_text(operation.replace("_", " "))
    skill = args.get("name") if ev.name == "load_skill" else args.get("skill_name")
    attempt_id = args.get("attempt_id")
    return PendingCall(ev.id, ev.name, operation[:80] if isinstance(operation, str) else "", identity, search,
                       candidate_id[:80] if isinstance(candidate_id, str) else "", activity, recovery_identity,
                       skill=skill if isinstance(skill, str) else "",
                       attempt_id=attempt_id if isinstance(attempt_id, str) else "",
                       invocation=ev.invocation,
                       result_expectations=tuple((key, result_field_digest(key, args[key]))
                           for key in ('candidate_id', 'attempt_id', 'skill_name', 'outcome', 'evidence_refs', 'observation_ids')
                           if key in args) if ev.name == 'workflow' and operation == 'record_result' else (),
                       http_redirects=(ev.name == 'http' and type(args.get('max_redirects')) is int
                                       and 0 < args['max_redirects'] <= 5))


def http_activity(ev: ToolResultEvent, call: PendingCall | None, context: str) -> str:
    """Last-response metadata cannot identify the destination of a redirect."""
    label = "http" + (" · initial request" if call and call.http_redirects else "")
    if context:
        label += " · " + context
    if ev.http_status is not None:
        label += " · " + ("Last response " if call is None or call.http_redirects else "") + str(ev.http_status)
    return sanitize_text(label)


def issue_category(text: str, ev: ToolResultEvent) -> str:
    if "compact report export failed" in text:
        return "export"
    if text.startswith(("Validation ", "Cleanup ", "Coverage synchronization")):
        return "incomplete"
    if text.startswith(("WARNING:", "Warning:", "Shell stderr:", "Tool output truncated", "MCP output truncated",
                        "Response body truncated", "Last response body truncated")):
        return "diagnostic"
    if (ev.name in {"read_payloads", "read_skill_file"} and ev.status == "success"
            and not ev.err and not ev.error_kind and ev.truncated
            and re.fullmatch(r".+ · chars [0-9]+–[0-9]+ · more available", text)):
        return "diagnostic"
    if (ev.name == "read_discovery_source" and ev.status == "success"
            and not ev.err and not ev.error_kind and ev.truncated
            and re.fullmatch(r"Retained body · chars [0-9]+–[0-9]+ of [0-9]+ · more available", text)):
        return "diagnostic"
    if ev.status == "cancelled" or ev.error_kind == "cancelled":
        return "cancelled"
    if ev.name in {"shell", "bash", "BashTool"} and text.startswith("Shell cancelled"):
        return "cancelled"
    if ev.status == 'pending' or ev.error_kind in {'permission_pending', 'permission_timeout', 'permission_stale'}:
        return 'pending'
    if ev.error_kind == "network":
        return "network"
    if ev.error_kind in {"permission", "permission_denied", "refusal", "authorization"} or "permission denied" in text.lower():
        return "denial"
    return "failure"


def result_issues(ev: ToolResultEvent, call: PendingCall | None) -> list[str]:
    """Use explicit failures and known receipt warnings, never success guesses."""
    issues: list[str] = []
    shell = ev.name in {"shell", "bash", "BashTool"}
    if shell:
        issues.extend(shell_issues(ev.runtime_metadata, status=ev.status, error_kind=ev.error_kind,
                                   reported_error=bool(ev.err), search=bool(call and call.search)))
    elif ev.err:
        issues.append(ev.err.split("(raw:", 1)[0].rstrip() if ev.error_kind == "invalid_args" else ev.err)
    elif ev.status in {"error", "cancelled", "pending"} or ev.error_kind:
        issues.append(ev.error_kind or ev.status)
        if ev.result.lower().startswith(("error:", "permission denied", "scope denied")):
            issues[0] = ev.result.splitlines()[0]
    if ev.name == "workflow":
        if ev.result.startswith("error:") and not ev.err:
            issues = [ev.result.removeprefix("error:").strip()]
        else:
            try:
                receipt = json.loads(ev.result)
            except (ValueError, TypeError):
                receipt = None
            if isinstance(receipt, dict):
                if receipt.get("ok") is False:
                    issues.append(str(receipt.get("error") or "Workflow operation rejected"))
                if receipt.get("coverage_sync") == "pending":
                    issues.append("Coverage synchronization pending" +
                                  (": " + str(receipt["coverage_error"]) if receipt.get("coverage_error") else ""))
                result = receipt.get("result")
                if isinstance(result, dict):
                    outcome = result.get("outcome")
                    if isinstance(outcome, str) and outcome in {"blocked", "insufficient-evidence", "deferred", "browser-required", "authorization-required"}:
                        issues.append("Validation " + outcome +
                                      (": " + str(result["deferred_reason"]) if result.get("deferred_reason") else ""))
                    cleanup = result.get("cleanup_state")
                    if isinstance(cleanup, str) and cleanup in {"pending", "failed", "requires-user-action"}:
                        issues.append("Cleanup " + cleanup)
    if ev.name == "confirm_finding" and "Finding persisted; compact report export failed." in ev.result:
        issues.append("Finding persisted; compact report export failed. Retry confirm_finding with the same candidate_id to regenerate the report.")
    if not shell and not issues and ev.result.lower().startswith("error:"):
        issues.append(ev.result.splitlines()[0].partition(":")[2].strip())
    if ev.name not in {"http", "shell", "bash", "BashTool"}:
        notice_text = ev.result
        if ev.name.startswith("mcp_"):
            try:
                content, _ = json.JSONDecoder().raw_decode(ev.result.lstrip())
            except (ValueError, TypeError):
                pass
            else:
                from src.tools.mcp.integration import extract_mcp_text
                notice_text = extract_mcp_text(content)
            if re.search(r"\[\.\.\. truncated \d+ chars \.\.\.\]", ev.result):
                issues.append("MCP output truncated. Omitted output may limit validation.")
            issues.extend(line for line in notice_text.splitlines() if line.startswith("ERROR:"))
        issues.extend(line for line in notice_text.splitlines()
                      if line.startswith(("WARNING:", "Warning:")) and line not in issues)
    if ev.truncated:
        if ev.name == "http":
            subject = "Last response body" if call is None or call.http_redirects else "Response body"
            issues.append(subject + " truncated; validation may be limited.")
        else:
            notice = "Tool output truncated. Omitted output may limit validation."
            if ev.name == "read_discovery_source" and ev.status == "success" and not ev.err and not ev.error_kind:
                try:
                    header, separator, body = ev.result.partition('\n')
                    page = json.loads(header)
                    if not separator or not isinstance(page, dict):
                        raise ValueError('page metadata unavailable')
                    start, end, total = (page.get(key) for key in ('start_char', 'end_char', 'source_chars'))
                    if (type(start) is not int or type(end) is not int or type(total) is not int
                            or not 0 <= start < end < total or len(body) != end - start
                            or page.get('offset_unit') != 'unicode_characters'
                            or type(page.get('next_start_char')) is not int or page['next_start_char'] != end
                            or page.get('complete') is not True or page.get('adapter_truncated') is not False):
                        raise ValueError('complete capture/page range unavailable')
                    notice = f'Retained body · chars {start}–{end} of {total} · more available'
                except (ValueError, TypeError):
                    pass
            if ev.name in {"read_payloads", "read_skill_file"} and ev.status == "success" and not ev.err and not ev.error_kind:
                try:
                    # These readers publish their relative filename in the
                    # heading and exact Unicode ranges in the final footer.
                    title = ev.result.split('\n', 1)[0]
                    filename = title.removeprefix('# ').split(' — ', 1)[0].partition('/')[2]
                    page = json.loads(ev.result.rpartition('\nContinuation: ')[2])
                    if not title.startswith('# ') or not filename or not isinstance(page, dict):
                        raise ValueError('page metadata unavailable')
                    start, end, total = (page.get(key) for key in ('start_char', 'end_char', 'source_chars'))
                    if (type(start) is not int or type(end) is not int or type(total) is not int
                            or not 0 <= start < end < total
                            or page.get('offset_unit') != 'unicode_characters'
                            or type(page.get('next_start_char')) is not int or page['next_start_char'] != end):
                        raise ValueError('page range unavailable')
                    notice = f'{filename} · chars {start}–{end} · more available'
                except (ValueError, TypeError):
                    pass  # Keep the generic warning when the range is unknown.
            issues.append(notice)
    if ev.status not in {"success", "observation", "error", "cancelled", "pending"}:
        issues.append("Unrecognized tool outcome. Review the operation.")
    # Failure references can be needed for repair; retain them in the safe copy.
    return list(dict.fromkeys(sanitize_text(issue) for issue in issues))
