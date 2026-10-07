"""Bounded read-only reconciliation and sanitized presentation."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from src.coverage.store import _is_valid_entry
from src.findings.store import MAX_REPORT_BYTES, _REPORT_SECTIONS, Finding, read_report_bytes
from src.redaction.redact import _is_secret_field, apply, apply_evidence
from src.report.model import (
    MAX_COVERAGE, MAX_COVERAGE_BYTES, MAX_DOCUMENT, MAX_FINDINGS, MAX_ID,
    MAX_INTAKE, MAX_PROSE, MAX_REASON, MAX_RECORDS, MAX_REFS, MAX_RESULTS,
    MAX_SCAN, MAX_TEXT_INTAKE, MAX_TITLE, Record, ReportDocument, ReportError,
    ReportFinding, Resources, SourceSnapshot, freeze,
)
from src.target.origin import HTTPOrigin
from src.tools.execution.sensitive import is_sensitive_path
from src.workflow.state import REQUIRED_WHOLE_TARGET_PHASES, PHASE_COVERAGE_DIMENSIONS

SEMANTIC_WARNING = (
    "Tested does not mean safe. No finding is not proof of absence. "
    "Contextual coverage describes recorded variants, not exhaustive request or role coverage."
)
SEVERITIES = ("critical", "high", "medium", "low", "info")
COVERAGE_WORDING = {
    "passed": "Recorded check did not confirm the tested behavior.",
    "failed": "Coverage records a positive check result; finding status shown separately.",
    "tried": "Attempt recorded; terminal validation not established.",
    "waf-blocked": "Testing blocked by recorded WAF condition.",
    "skipped": "Check skipped; no validation conclusion.",
}


def origin(url: str | None) -> str | None:
    try:
        return HTTPOrigin.from_url(url or "").as_url()
    except (ValueError, TypeError):
        return None


def owned_origin(target: str | None, endpoint: str | None, objective_origin: str | None) -> str | None:
    if target:
        return origin(target)
    endpoint = re.sub(r"^[A-Z]+\s+", "", endpoint or "")
    try:
        if urlsplit(endpoint).netloc:
            return origin(urljoin((objective_origin or "") + "/", endpoint))
    except ValueError:
        return None
    return origin(objective_origin)


def endpoint_matches_origin(endpoint: str | None, assessment_origin: str | None) -> bool:
    """Resolve relative/network-path endpoints using the assessment's scheme."""
    if not assessment_origin:
        return False
    if endpoint is None or endpoint == "":
        return True
    if not isinstance(endpoint, str):
        return False
    endpoint = re.sub(r"^\s*[A-Z]+\s+", "", endpoint, flags=re.I)
    try:
        return origin(urljoin(assessment_origin + "/", endpoint)) == assessment_origin
    except ValueError:
        return False


def _plain(value: str) -> str:
    value = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))", "", value)
    value = value.encode("utf-8", "replace").decode("utf-8")
    return unicodedata.normalize("NFC", "".join(
        c for c in value if c in "\n\t" or unicodedata.category(c) not in {"Cc", "Cf", "Cs"}
    ))


class Sanitizer:
    def __init__(self) -> None:
        self.omissions = 0
        self.truncations = 0

    def text(self, value, limit: int = MAX_ID, *, proof: bool = False) -> str:
        if value is None or value == "":
            return "Not recorded"
        if not isinstance(value, str):
            return "Not recorded"
        if len(value) > MAX_TEXT_INTAKE or len(value.encode("utf-8", "replace")) > MAX_TEXT_INTAKE:
            self.omissions += 1
            return "Omitted: source text exceeds report intake limit"
        value = _plain(value)
        # Suppress entire suspicious credential-bearing prose/blocks. This also
        # covers short YAML secrets, CLI arguments and visually obfuscated labels.
        detection = unicodedata.normalize("NFKC", unquote(value)).lower()
        detection += "\n" + re.sub(r"(?<=[a-z])[_.\-\s]+(?=[a-z])", "", detection)
        # A redacted header does not establish a safe end to a multiline
        # credential value. Suppress the whole field, including continuation
        # lines, using the canonical secret-label vocabulary before regex masks.
        if any(_is_secret_field(match[1]) for match in
               re.finditer(r"(?m)^[ \t]*(?:-[ \t]+)?([^:=\n]+?)\s*[:=]", detection)):
            return "[REDACTED]"
        if re.search(r"password|passwd|authorization|setcookie|cookie\s*[:=]|"
                     r"apikey|clientsecret|accesstoken|refreshtoken|bearer\s|basic\s|"
                     r"(?:^|\s)-u(?:\s|[^-])|(?:^|\s)--(?:token|secret)\b|"
                     r"(?:^|\W)(?:pwd|secret|token|jwt)\s*[:=]", detection):
            return "[REDACTED]"
        # Strip credentials and query values from every URL occurring in prose.
        def url(match: re.Match) -> str:
            return safe_url(match[0])
        value = re.sub(r"https?://[^\s<>\"']+", url, value, flags=re.I)
        value = apply_evidence(value) if proof else apply(value)
        value = re.sub(r".{2}…\[REDACTED:[^\]]+\]….{2}", "[REDACTED]", value)
        if len(value) > limit:
            self.truncations += 1
            return value[:limit] + " [truncated]"
        return value

    def url(self, value: str | None) -> str:
        if not value:
            return "Not recorded"
        if len(value.encode("utf-8", "replace")) > MAX_TEXT_INTAKE:
            return self.text(value)
        return self.text(safe_url(value))

    def endpoint(self, value: str | None, assessment_origin: str) -> str:
        if value and value.startswith("//"):
            value = urljoin(assessment_origin + "/", value)
        return self.url(value)


def safe_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        if parts.netloc:
            base = origin(value)
            if not base:
                return "URL unavailable"
            return base + (parts.path or "/")
        return urlunsplit(("", "", parts.path, "", ""))
    except ValueError:
        return "URL unavailable"


def timestamp(value: str | None, clean: Sanitizer) -> str:
    if not value or len(value) > 80:
        return "Not recorded"
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return "Not recorded"
    return clean.text(value)


def open_directory(path: Path) -> int:
    """Walk every component without following symlinks; caller owns the fd."""
    path = path.absolute()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            if component in {".", ".."}:
                raise ValueError("unsafe resource")
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def bounded_read(path: Path, maximum: int, *, private: bool = True, directory_fd: int | None = None) -> bytes:
    if private and (is_sensitive_path(str(path)) or is_sensitive_path(str(path.resolve()))):
        raise ValueError("protected resource")
    parent = os.dup(directory_fd) if directory_fd is not None else open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
                raise ValueError("unsafe or oversized resource")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(maximum + 1)
            after = os.fstat(fd)
            if (len(raw) > maximum or
                (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError("resource changed or exceeded bound")
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _header(raw: bytes) -> tuple[dict[str, list[str]], bool]:
    """Validate export ambiguity only; canonical parser owns body semantics."""
    lines = raw.decode("utf-8").splitlines()
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if line.startswith("## ") and line[3:] in _REPORT_SECTIONS:
            break
        if not line.strip():
            continue
        match = re.fullmatch(r"- \*\*(.+?):\*\* (.*)", line)
        if not match:
            raise ValueError("ambiguous metadata")
        headers.setdefault(match[1], []).append(match[2])
    if any(len(v) != 1 for k, v in headers.items() if k != "Evidence"):
        raise ValueError("duplicate metadata")
    # A legacy impact heading counts only outside fenced payloads.
    fence = None
    legacy = False
    observed = False
    for line in lines:
        match = re.fullmatch(r"(`{3,})[a-zA-Z]*", line)
        if fence:
            if line == fence:
                fence = None
        elif match:
            fence = match[1]
        elif line == "## Impact":
            legacy = True
        elif line == "## Observed impact":
            observed = True
    return headers, legacy and not observed


def _reports(resources: Resources, selected: set[str]):
    matches: dict[str, list[tuple[Finding, bytes, bool]]] = {cid: [] for cid in selected}
    scanned = total = 0
    uncertain = False
    for root in dict.fromkeys(resources.finding_roots):
        if is_sensitive_path(str(root)) or is_sensitive_path(str(root.resolve())):
            uncertain = True
            continue
        try:
            directory_fd = open_directory(root)
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            uncertain = True
            continue
        try:
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    scanned += 1
                    if scanned > MAX_SCAN:
                        raise ReportError("Finding directory scan limit exceeded; reduce report resources and retry.")
                    if not entry.name.endswith(".md"):
                        continue
                    try:
                        raw = bounded_read(root / entry.name, MAX_REPORT_BYTES, directory_fd=directory_fd)
                        total += len(raw)
                        if total > MAX_INTAKE:
                            raise ReportError("Finding intake limit exceeded; reduce report resources and retry.")
                        header, legacy = _header(raw)
                        cid = (header.get("Candidate ID") or [""])[0]
                        if cid in selected:
                            finding = read_report_bytes(raw, slug=Path(entry.name).stem)
                            matches[cid].append((finding, raw, legacy))
                    except (OSError, UnicodeError, ValueError, TypeError):
                        # Unknown malformed records could hide a duplicate owner.
                        uncertain = True
        finally:
            os.close(directory_fd)
    return matches, uncertain


def _current_admissible(result: Record) -> bool:
    # V1 export preserves its historical matching contract. V2 needs the
    # captured structural resolver decision, never a saved binding alone.
    return result.get("assessment_contract_version", 1) < 2 or result.get("current_admissible") is True


def _finding_matches(f: Finding, candidate: Record, result: Record, target: str) -> bool:
    if not _current_admissible(result):
        return False
    if (f.candidate_id != candidate.get("id") or origin(f.url) != target or
        f.canonical_class != candidate.get("candidate_class") or
        sorted(f.evidence_refs or []) != sorted(result.get("evidence_refs", ())) or
        not f.evidence_refs or len(f.evidence_refs) > MAX_REFS or
        len(set(f.evidence_refs)) != len(f.evidence_refs) or
        not f.confirmation_binding or f.confirmation_binding != result.get("binding")):
        return False
    if result.get("assessment_contract_version", 1) >= 2 and (
            f.assessment_source != result.get("assessment_source")
            or f.assessment_result_id != result.get("result_id")
            or f.assessment_attempt_id != result.get("attempt_id")
            or f.binding_version != result.get("assessment_contract_version")):
        return False
    if candidate.get("method") and (f.method or "").upper() != candidate.get("method"):
        return False
    if candidate.get("parameter") and f.parameter != candidate.get("parameter"):
        return False
    endpoint = candidate.get("endpoint")
    if not endpoint:
        return False
    endpoint = re.sub(r"^\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", "", endpoint, flags=re.I)
    if not endpoint_matches_origin(endpoint, target):
        return False
    template = re.escape(urlsplit(endpoint).path).replace(r"\{", "{").replace(r"\}", "}")
    template = re.sub(r"\{[^{}]+\}", r"[^/]+", template)
    return re.fullmatch(template, urlsplit(f.url).path) is not None


def _valid_evidence(record: Record, ref: str, cid: str) -> bool:
    path, sha, size = record.get("path"), record.get("sha256"), record.get("size")
    return bool(record.get("id") == ref and record.get("candidate_id") == cid and
                isinstance(path, str) and path and not Path(path).is_absolute() and ".." not in Path(path).parts and
                isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha) and
                isinstance(size, int) and not isinstance(size, bool) and 0 < size <= MAX_REPORT_BYTES)


def _evidence_row(record: Record, resources: Resources, clean: Sanitizer) -> tuple[str, str]:
    path = record.get("path", "")
    source = record.get("source_path")
    if not isinstance(path, str) or not path:
        return clean.text(record.get("id")), "Evidence reference metadata unavailable"
    absolute = resources.evidence_root / path
    status = "Referenced; content not opened"
    display = "Path withheld"
    try:
        if (Path(path).is_absolute() or ".." in Path(path).parts or
            not absolute.resolve().is_relative_to(resources.evidence_root.resolve()) or
            is_sensitive_path(str(absolute)) or is_sensitive_path(str(absolute.resolve())) or
            source and is_sensitive_path(source)):
            pass
        else:
            display = clean.text(path)
            if not absolute.is_file() or absolute.is_symlink():
                status = "Referenced evidence file unavailable"
            else:
                status = "Referenced evidence file present; content not opened; integrity not checked"
    except (OSError, ValueError):
        status = "Evidence availability not checked"
    sha = record.get("sha256", "")
    digest = sha if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha) else "Digest unavailable"
    size = record.get("size")
    size = str(size) if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else "Not recorded"
    return clean.text(record.get("id")), (
        f"Candidate: {clean.text(record.get('candidate_id'))}; {display}; "
        f"Stored bytes: {size}; SHA-256: {digest}; {status}"
    )


def _coverage(source: SourceSnapshot, resources: Resources, clean: Sanitizer, limitations: list[str], results: list[Record]):
    rows = source.coverage
    if rows is None:
        for path in resources.coverage_paths:
            try:
                raw = bounded_read(path, MAX_COVERAGE_BYTES)
                parsed = json.loads(raw)
                if parsed.get("version") != 1 or not isinstance(parsed.get("entries"), list):
                    raise ValueError("invalid coverage")
                if len(parsed["entries"]) > MAX_COVERAGE:
                    raise ValueError("coverage bound")
                # Explicit field whitelist; never invoke lazy store parsing/loading.
                allowed = ("endpoint", "param", "vulnClass", "status", "count", "firstSeen", "lastSeen",
                           "notes", "observationIds", "resultIds", "context")
                detached_rows = []
                context_fields = ("objective_id", "target_origin", "method", "location", "media_type", "auth_context_ref", "test_case")
                for row in parsed["entries"]:
                    if not _is_valid_entry(row):
                        limitations.append("Malformed coverage row omitted.")
                        continue
                    context = row.get("context")
                    if context is not None and (not isinstance(context, dict) or set(context) - set(context_fields) or
                        any(v is not None and (not isinstance(v, str) or len(v) > 500) for v in context.values())):
                        limitations.append("Malformed coverage context omitted; no exact variant established.")
                        continue
                    values = {k: row.get(k) for k in allowed if k != "context"}
                    values["context"] = {k: context.get(k) for k in context_fields} if context is not None else None
                    detached_rows.append(freeze(values))
                rows = tuple(detached_rows)
                break
            except FileNotFoundError:
                continue
            except (OSError, ValueError, TypeError, AttributeError, ReportError):
                break
    if rows is None:
        limitations.append("Coverage projection unavailable; canonical validation records shown separately.")
        return ()
    if not rows:
        limitations.append("Coverage projection available; no recorded coverage rows.")
    selected: list[tuple[Record, bool]] = []
    objective_id = source.objective.get("id")
    target = origin(source.target)
    for row in rows:
        context = row.get("context")
        ep = row.get("endpoint", "")
        if not isinstance(ep, str):
            limitations.append("Malformed coverage row omitted.")
            continue
        if not endpoint_matches_origin(ep, target):
            limitations.append("Report incomplete: coverage rows with foreign/conflicting endpoints were withheld.")
            continue
        exact = False
        if isinstance(context, Record):
            owner, host = context.get("objective_id"), context.get("target_origin")
            if owner and owner != objective_id or host and origin(host) != target:
                continue
            exact = bool(objective_id and owner == objective_id and host and origin(host) == target)
        selected.append((row, exact))
    mirrors = {identity for row, exact in selected if exact
               for identity in (*(row.get("observationIds") or ()), *(row.get("resultIds") or ()))}
    output = []
    latest_results = {r.get("candidate_id"): r for r in results}
    for row, exact in selected:
        if not exact and row.get("observationIds") and set(row.get("observationIds")).issubset(mirrors):
            continue
        context = row.get("context") or Record()
        if not isinstance(context, Record):
            context = Record()
        label = "Contextual variant" if exact else "Legacy/unattributed coverage — objective/origin attribution not established"
        status = row.get("status")
        wording = COVERAGE_WORDING.get(status, "Unknown coverage status; no conclusion.")
        identity = "; ".join(f"{k}: {clean.text(context.get(k))}" for k in
                             ("objective_id", "target_origin", "method", "location", "media_type", "auth_context_ref", "test_case"))
        ep = re.sub(r"^[A-Z]+\s+", "", row.get("endpoint", ""))
        linked = []
        for result in latest_results.values():
            if not _current_admissible(result):
                continue
            projection = result.get("projection")
            if (exact and isinstance(projection, Record) and projection.get("endpoint") == row.get("endpoint") and
                projection.get("param") == row.get("param") and projection.get("vulnClass") == row.get("vulnClass") and
                isinstance(projection.get("context"), Record) and
                all(projection.get("context").get(k) == context.get(k) for k in
                    ("objective_id", "target_origin", "method", "location", "media_type", "auth_context_ref", "test_case"))):
                linked.append(result.get("outcome"))
        linked_text = clean.text(", ".join(sorted(set(linked)))) if linked else "Not recorded for this exact variant"
        output.append((clean.endpoint(ep, target or ""), f"{label}; parameter: {clean.text(row.get('param'))}; "
                       f"class: {clean.text(row.get('vulnClass'))}; {identity}; "
                       f"status: {clean.text(status)} — {wording}; latest canonical outcome: {linked_text}; "
                       f"Recorded observations: {row.get('count') if isinstance(row.get('count'), int) else 'Not recorded'}; "
                       f"first/last observation timestamps (recorded epoch ms): {row.get('firstSeen') if isinstance(row.get('firstSeen'), int) else 'Not recorded'} / "
                       f"{row.get('lastSeen') if isinstance(row.get('lastSeen'), int) else 'Not recorded'}; "
                       f"notes: {clean.text(row.get('notes'), MAX_REASON)}"))
    exact_count = sum("Contextual variant;" in value for _, value in output)
    limitations.append(f"Selected coverage: {exact_count} exact contextual variants; {len(output) - exact_count} legacy/unattributed records. Recorded observations are not HTTP request counts.")
    return tuple(sorted(output))


def build_report(source: SourceSnapshot, resources: Resources) -> ReportDocument:
    if len(source.candidates) + len(source.inputs) > MAX_RECORDS or len(source.results) > MAX_RESULTS:
        raise ReportError("Assessment snapshot exceeds report record limits; reduce recorded resources and retry.")
    if source.coverage is not None and len(source.coverage) > MAX_COVERAGE:
        raise ReportError("Coverage snapshot exceeds report row limit.")
    try:
        exported = datetime.fromisoformat(source.exported_at.replace("Z", "+00:00"))
        if exported.tzinfo is None:
            raise ValueError
        exported_text = exported.astimezone(timezone.utc).isoformat()
    except (ValueError, AttributeError):
        raise ReportError("Report export timestamp unavailable; run /report again.") from None
    target = origin(source.target)
    if not target:
        raise ReportError("no valid active target. Set /target <url> first.")
    objective = source.objective
    owner = objective.get("id")
    if objective.get("target_origin") and origin(objective.get("target_origin")) != target:
        raise ReportError("active objective and target do not match. Export cannot mix their assessment records.")
    clean = Sanitizer()
    limitations = [SEMANTIC_WARNING,
        "Snapshot of recorded KAgent state. Evidence contents and current live exploitability are not independently revalidated.",
        "Export does not record or independently reevaluate a runtime completion event. Workflow closure does not imply an exhaustive assessment.",
        "Regex/key redaction cannot detect every unlabelled secret disguised as ordinary prose. Raw traffic, payloads and session/config containers are excluded."]
    if source.foreign_records:
        limitations.append("Other assessment records were excluded from this snapshot.")
    candidates = {}
    endpoint_conflicts = source.endpoint_conflict_count
    for c in source.candidates:
        selected = (c.get("id") == objective.get("candidate_id") if objective.get("mode") == "candidate_validation"
                    else c.get("objective_id") == owner)
        if owner and selected and owned_origin(c.get("target"), c.get("endpoint"), objective.get("target_origin")) == target:
            if not endpoint_matches_origin(c.get("endpoint"), target):
                endpoint_conflicts += 1
                continue
            candidates[c.get("id")] = c
    results = [r for r in source.results if owner and r.get("objective_id") == owner and r.get("candidate_id") in candidates]
    latest = {r.get("candidate_id"): r for r in results}
    evidence = {e.get("id"): e for e in source.evidence}
    confirmed = {cid for cid, r in latest.items() if r.get("outcome") == "confirmed"}
    persisted_ids = {cid for cid, c in candidates.items() if c.get("persisted")}
    matches, uncertain = _reports(resources, confirmed | persisted_ids) if confirmed or persisted_ids else ({}, False)
    findings = []
    included_ids: set[str] = set()
    unavailable = 0
    for cid in sorted(confirmed | persisted_ids):
        r, c = latest.get(cid), candidates[cid]
        refs = r.get("evidence_refs", ()) if r else ()
        eligible = bool(r and r.get("outcome") == "confirmed" and r.get("coverage_synced") is not False and
                        _current_admissible(r) and
                        c.get("persisted") == r.get("fingerprint") and refs and len(refs) <= MAX_REFS and
                        all(ref in evidence and _valid_evidence(evidence[ref], ref, cid) for ref in refs))
        records = matches.get(cid, [])
        if uncertain or not eligible or r is None or len(records) != 1:
            if c.get("persisted"):
                unavailable += 1
                limitations.append(f"Finding reference {clean.text(cid)} unavailable: missing, ambiguous or inconsistent provenance.")
            continue
        f, raw, legacy = records[0]
        if not _finding_matches(f, c, r, target):
            unavailable += 1
            limitations.append(f"Finding reference {clean.text(cid)} withheld: legacy provenance incomplete or historical binding/identity mismatch.")
            continue
        details = (
            ("URL", clean.url(f.url)), ("Method", clean.text(f.method)), ("Parameter", clean.text(f.parameter)),
            ("Canonical class", clean.text(f.canonical_class)), ("Vulnerability type", clean.text(f.vulnerabilityType)),
            ("CWE", clean.text(", ".join(f.cwe or []))), ("OWASP", clean.text(", ".join(f.owasp or []))),
            ("Classification origin", clean.text(f.classification_origin)),
            ("Classification revision", str(f.classification_revision)),
            ("Saved finding SHA-256", hashlib.sha256(raw).hexdigest()),
            ("Legacy impact (observed/potential distinction not recorded)" if legacy else "Observed impact",
             clean.text(f.observed_impact, MAX_PROSE, proof=True)),
            ("Potential impact", clean.text(f.potential_impact, MAX_PROSE, proof=True)),
            ("Remediation", clean.text(f.remediation, MAX_PROSE, proof=True)),
            ("Finding reported at", timestamp(f.createdAt, clean)),
            ("Validation recorded at", timestamp(r.get("recorded_at"), clean)),
            ("Validation session", clean.text(r.get("session_id"))),
            ("Candidate ID", clean.text(cid)), ("Evidence refs", clean.text(", ".join(f.evidence_refs or []))),
        )
        included_ids.add(cid)
        findings.append(ReportFinding(clean.text(cid), clean.text(f.title, MAX_TITLE), f.severity, details))
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.candidate_id))
    count = len(findings)
    unfinalized = len(confirmed - included_ids)
    omitted = max(0, count - MAX_FINDINGS)
    if omitted:
        limitations.append(f"Report incomplete: {omitted} persisted finding details omitted by the display limit; recorded totals include them.")
    severity_counts = Counter(f.severity for f in findings)
    inputs = []
    for item in source.inputs:
        if owner and item.get("objective_id") == owner and origin(item.get("target_origin")) == target:
            if not endpoint_matches_origin(item.get("endpoint"), target):
                endpoint_conflicts += 1
                continue
            inputs.append(item)
    if endpoint_conflicts:
        limitations.append(f"Report incomplete: {endpoint_conflicts} assessment records with foreign/conflicting endpoints were withheld.")
    goals = objective.get("requested_goals", ())
    phases = [p for p in source.phases if owner and p.get("objective_id") == owner and origin(p.get("target_origin")) == target]
    all_closed = bool(owner and not endpoint_conflicts and all(
        r and _current_admissible(r) and candidates[cid].get("status") in {"validated", "dismissed"} and r.get("outcome") in {"confirmed", "not-confirmed"} and r.get("coverage_synced") is not False and
        r.get("cleanup_state") in {"not-required", "succeeded"} and
        (not r.get("evidence_refs") or all(ref in evidence and _valid_evidence(evidence[ref], ref, cid) for ref in r.get("evidence_refs"))) and
        (r.get("outcome") != "confirmed" or cid in included_ids)
        for cid in candidates for r in (latest.get(cid),)
    ))
    if any(any(cid not in candidates for cid in item.get("candidate_ids", ())) for item in inputs):
        all_closed = False
    for goal in goals:
        linked = [latest.get(cid) for cid in goal.get("candidate_ids", ()) if cid in candidates and candidates[cid].get("candidate_class") == goal.get("candidate_class")]
        expected = {"tested_confirmed": "confirmed", "tested_not_confirmed": "not-confirmed"}.get(goal.get("status"))
        if not expected or not linked or len(linked) != len(goal.get("candidate_ids", ())) or not any(r and _current_admissible(r) and r.get("outcome") == expected for r in linked):
            all_closed = False
    mode = objective.get("mode")
    if mode == "whole_target":
        recorded = {p.get("phase"): p for p in phases}
        all_closed = all_closed and all(phase in recorded and recorded[phase].get("artifact_ref") and
            all(isinstance(recorded[phase].get("coverage"), Record) and recorded[phase].get("coverage").get(dim) and
                recorded[phase].get("coverage").get(dim).get("status") not in {"failed", "cancelled"}
                for dim in PHASE_COVERAGE_DIMENSIONS.get(phase, ()))
            for phase in REQUIRED_WHOLE_TARGET_PHASES)
        all_closed = all_closed and all(i.get("disposition") in {"analyzed", "dropped"} for i in inputs)
        if not inputs and not recorded.get("input_analysis", Record()).get("no_inputs_discovered"):
            all_closed = False
    elif mode == "candidate_validation":
        all_closed = all_closed and objective.get("candidate_id") in latest
    else:
        all_closed = False
    if source.running:
        status = "Assessment in progress — snapshot at export time."
    elif not owner:
        status = "Target snapshot — assessment objective not recorded."
    elif all_closed:
        status = "Recorded workflow prerequisites satisfied (snapshot)."
    elif not results:
        status = "Assessment snapshot — no validation results recorded for this objective."
    else:
        status = "Partial assessment snapshot — recorded work remains outstanding."
    if not all_closed:
        limitations.append("Completion status not recorded; displayed progress is a report projection.")
    invalid_current = {cid for cid, r in latest.items()
                       if r.get("assessment_contract_version", 1) >= 2 and not _current_admissible(r)}
    if invalid_current:
        limitations.append(f"{len(invalid_current)} latest assessments lack current structural admissibility; historical outcomes do not establish current closure or Finding eligibility.")
    if any(r.get("outcome") not in {"confirmed", "not-confirmed"} or r.get("cleanup_state") in {"pending", "failed", "requires-user-action"} for r in latest.values()):
        limitations.append("Partial assessment — unresolved validation or operational limitations recorded.")
    if source.restored:
        limitations.append("Snapshot of restored recorded state.")
    summary = [f"{count} persisted confirmed findings included.", f"{unfinalized} confirmed validation results have no exportable persisted finding.",
               f"{unavailable} recorded finding references could not be reconciled with persisted details.",
               f"Recorded inventory: {len(inputs)} inputs; {len(candidates)} candidates; {len(results)} validation results."]
    summary.extend(f"Latest validation outcome {clean.text(outcome)}: {total}" for outcome, total in sorted(Counter(r.get("outcome") for r in latest.values()).items()))
    summary.extend(f"Input disposition {clean.text(disposition)}: {total}" for disposition, total in sorted(Counter(i.get("disposition") for i in inputs).items()))
    if not count and not confirmed and not persisted_ids and not uncertain:
        summary.append("No confirmed findings recorded in this assessment.")
        summary.append("Recorded testing does not establish that vulnerabilities are absent.")
    evidence_refs = {ref for r in results for ref in r.get("evidence_refs", ())}
    summary.append(f"{len(evidence_refs)} linked evidence references are unavailable or were not checked for content/integrity.")
    evidence_rows = tuple(_evidence_row(evidence[ref], resources, clean) if ref in evidence and
                          evidence[ref].get("candidate_id") in candidates else
                          (clean.text(ref), "Evidence reference unavailable or ownership inconsistent") for ref in sorted(evidence_refs))
    if evidence_rows:
        limitations.append("Linked evidence content was not opened; reproduction and file integrity were not checked by export.")
    inventory = tuple(sorted((clean.text(i.get("id")), f"{clean.text(i.get('method'))} {clean.endpoint(i.get('endpoint'), target)}; "
        f"parameter: {clean.text(i.get('parameter'))}; location: {clean.text(i.get('location'))}; "
        f"media type: {clean.text(i.get('content_type'))}; auth context: {clean.text(i.get('auth_context_ref'))}; "
        f"disposition: {clean.text(i.get('disposition'))}; reason: {clean.text(i.get('disposition_reason'), MAX_REASON)}") for i in inputs))
    validations = tuple(sorted((clean.text(cid), f"Latest outcome: {clean.text(r.get('outcome'))}; assessment source: {clean.text((r.get('assessment_provenance') or {}).get('source') or r.get('assessment_source') or 'legacy/unknown')}; "
        f"current structural admissibility: {'invalid/unavailable' if cid in invalid_current else 'accepted' if r.get('assessment_contract_version', 1) >= 2 else 'historical contract'}; "
        f"skill: {clean.text(r.get('skill_name'))}; techniques: {clean.text(', '.join(r.get('techniques', ())))}; "
        f"reason: {clean.text(r.get('deferred_reason'), MAX_REASON)}; notes: {clean.text(r.get('notes'), MAX_REASON)}; "
        f"cleanup: {clean.text(r.get('cleanup_state'))}; coverage sync: {r.get('coverage_synced')}; "
        f"recorded at: {timestamp(r.get('recorded_at'), clean)}") for cid, r in latest.items()))
    goal_rows = tuple(sorted((clean.text(g.get("candidate_class")), f"Recorded status: {clean.text(g.get('status'))}; "
        f"reason: {clean.text(g.get('reason'), MAX_REASON)}") for g in goals))
    phase_rows = []
    for phase in REQUIRED_WHOLE_TARGET_PHASES if mode == "whole_target" else ():
        marker = next((p for p in phases if p.get("phase") == phase), None)
        coverage = marker.get("coverage") if marker else None
        description = "Recorded completion marker" if marker and marker.get("artifact_ref") else "Not recorded"
        if isinstance(coverage, Record):
            description += "; " + "; ".join(f"{clean.text(k)}: {clean.text(v.get('status'))}; {clean.text(v.get('reason'), MAX_REASON)}" for k, v in coverage.values)
        phase_rows.append((phase, description))
    coverage_rows = _coverage(source, resources, clean, limitations, results)
    metadata = tuple((label, value) for label, value in (
        ("Target", clean.url(source.target)), ("Target name", clean.text(source.target_name)),
        ("Declared scope", clean.text(", ".join(source.scope)) if source.scope else "Declared scope not recorded."),
        ("Objective", clean.text(owner)), ("Mode", clean.text(mode)), ("Session", clean.text(source.session)),
        ("Provider at export", clean.text(source.provider)), ("Backend at export", clean.text(source.backend)),
        ("Model at export", clean.text(source.model)), ("KAgent version", clean.text(source.version)),
        ("Exported at (UTC)", timestamp(exported_text, clean)),
    ))
    if clean.omissions or clean.truncations:
        limitations.append(f"Report incomplete: {clean.omissions} oversize text values omitted; {clean.truncations} displayed values truncated after redaction.")
    doc = ReportDocument(metadata, status, tuple(summary), tuple(findings[:MAX_FINDINGS]), evidence_rows,
                         inventory, validations, coverage_rows, goal_rows, tuple(phase_rows), tuple(dict.fromkeys(limitations)),
                         tuple((s, severity_counts[s]) for s in SEVERITIES), count, unfinalized, unavailable, omitted)
    if sum(len(t.encode("utf-8")) for t in doc.text_values()) > MAX_DOCUMENT:
        raise ReportError("Sanitized report exceeds document size limit; reduce recorded resources and retry.")
    return doc
