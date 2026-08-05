from __future__ import annotations
 
import contextlib
import dataclasses
import json
import logging
import os
import re
import secrets
 
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Literal, Optional
 
logger = logging.getLogger("intelligence_store")
 
try:
    import filelock  # type: ignore
 
    _HAS_FILELOCK = True
except ImportError:  # pragma: no cover - optional dependency
    filelock = None  # type: ignore
    _HAS_FILELOCK = False
 
 
# =====================================================
# Constants (match TS exactly)
# =====================================================
 
MAX_SCENARIOS_PER_FILE = 5000
RECENCY_BOOST = 0.25
RECENCY_HALF_LIFE_MS = 14 * 24 * 60 * 60 * 1000
 
IntelligenceScope = Literal["project", "personal", "builtin"]
 
# Maps dataclass field name -> JSONL/wire key, identical to the TS
# camelCase field names, so files are byte-for-byte interchangeable.
_FIELD_TO_WIRE: dict[str, str] = {
    "id": "id",
    "title": "title",
    "category": "category",
    "triggers": "triggers",
    "technologies": "technologies",
    "lesson": "lesson",
    "recommended_checks": "recommendedChecks",
    "avoid_missing": "avoidMissing",
    "source": "source",
    "source_session_id": "sourceSessionId",
    "created_at": "createdAt",
    "updated_at": "updatedAt",
    "confidence": "confidence",
    "scope": "scope",
}
_WIRE_TO_FIELD: dict[str, str] = {v: k for k, v in _FIELD_TO_WIRE.items()}
_KNOWN_PY_FIELDS = set(_FIELD_TO_WIRE.keys())
_KNOWN_WIRE_OR_PY_KEYS = set(_FIELD_TO_WIRE.values()) | set(_FIELD_TO_WIRE.keys())
 
# Default redaction rule — identical to the TS store's redact() output.
DEFAULT_REDACT_PATTERNS: list[tuple[str, str]] = [
    (r"(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+", r"\1=[REDACTED]"),
]
 
 
# =====================================================
# Data Model
# =====================================================
 
@dataclass
class IntelligenceScenario:
    """A single knowledge item in the Pentest Agent's intelligence store.
 
    All fields have defaults so a malformed/partial JSONL record can
    always be constructed (never raises); normalize_scenario() is what
    actually fills in sensible values, matching TS's tolerance for a
    `Partial<IntelligenceScenario>` input.
    """
 
    id: str = ""
    title: str = ""
    category: str = ""
    triggers: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    lesson: str = ""
    recommended_checks: list[str] = field(default_factory=list)
    avoid_missing: list[str] = field(default_factory=list)
    source: str = "local"
    source_session_id: Optional[str] = None
    created_at: str = ""
    updated_at: Optional[str] = None
    confidence: float = 0.7
    scope: IntelligenceScope = "project"
 
    def to_wire(self) -> dict[str, Any]:
        """Serialize using the same camelCase keys as the TS store.
        None-valued fields are omitted, matching JSON.stringify's
        behavior of dropping `undefined` properties."""
        out: dict[str, Any] = {}
        for py_field, wire_key in _FIELD_TO_WIRE.items():
            value = getattr(self, py_field)
            if value is None:
                continue
            out[wire_key] = value
        return out
 
    @staticmethod
    def from_wire(data: dict[str, Any]) -> "IntelligenceScenario":
        """Parse either TS-style camelCase or legacy snake_case JSON.
        Unknown keys are silently dropped — matches TS, which only
        reads the specific properties it knows about off the parsed
        object and ignores everything else rather than erroring."""
        kwargs: dict[str, Any] = {}
        for key, value in data.items():
            py_field = _WIRE_TO_FIELD.get(key, key)
            if py_field in _KNOWN_PY_FIELDS:
                kwargs[py_field] = value
        return IntelligenceScenario(**kwargs)
 
 
# =====================================================
# Builtin Pentest Knowledge — verbatim port of TS BUILTIN_SCENARIOS.
# Do not add scenarios here that aren't in the TS source.
# =====================================================
 
BUILTIN_SCENARIOS: list[IntelligenceScenario] = [
    IntelligenceScenario(
        id="builtin-node-pm2-source-exposure",
        title="Node source exposure should check PM2 deployment files",
        category="recon-gap",
        triggers=[
            "server.js",
            "package.json",
            "node",
            "express",
            "source leak",
            "deployment",
            "nginx",
        ],
        technologies=["Node.js", "Express", "PM2", "Nginx"],
        lesson=(
            "When Node.js application source files or metadata are exposed, "
            "investigate deployment configuration files because they may reveal "
            "environment information, paths, services, or sensitive configuration."
        ),
        recommended_checks=[
            "ecosystem.config.js",
            "ecosystem.config.cjs",
            "ecosystem.config.mjs",
            "pm2.json",
            "process.json",
            "app.js",
            "index.js",
            "server.js~",
            "package-lock.json",
            "backup/archive variants",
        ],
        avoid_missing=[
            "PM2 ecosystem files",
            "process manager JSON files",
            "Node backup files",
        ],
        source="builtin pentest knowledge",
        source_session_id="c7e9e2a4-085b-43fe-af39-c016341a2f61",
        created_at="2026-01-01T00:00:00.000Z",
        confidence=0.95,
        scope="builtin",
    ),
    IntelligenceScenario(
        id="builtin-web-recon",
        title="Web reconnaissance should identify attack surface",
        category="recon",
        triggers=["domain", "website", "web", "service", "port", "technology"],
        technologies=["Web"],
        lesson=(
            "Before exploitation, perform reconnaissance to understand "
            "technologies, exposed services and possible attack surfaces."
        ),
        recommended_checks=[
            "nmap service detection",
            "technology fingerprinting",
            "directory enumeration",
            "subdomain discovery",
            "endpoint discovery",
        ],
        avoid_missing=["hidden services", "backup files", "unmapped endpoints"],
        source="builtin pentest knowledge",
        created_at="2026-01-01T00:00:00.000Z",
        confidence=0.95,
        scope="builtin",
    ),
    IntelligenceScenario(
        id="builtin-sqli-testing-pattern",
        title="SQL injection testing pattern",
        category="vulnerability",
        triggers=["sql", "sqli", "parameter", "id", "login", "database"],
        technologies=["SQL", "Database", "Web"],
        lesson=(
            "User-controlled parameters should be tested for SQL injection "
            "using manual validation and automated tools."
        ),
        recommended_checks=[
            "single quote testing",
            "boolean based SQL injection",
            "time based SQL injection",
            "union based SQL injection",
            "sqlmap verification",
        ],
        avoid_missing=["blind SQL injection", "hidden parameters", "API endpoints"],
        source="builtin pentest knowledge",
        created_at="2026-01-01T00:00:00.000Z",
        confidence=0.95,
        scope="builtin",
    ),
    IntelligenceScenario(
        id="builtin-xss-testing-pattern",
        title="Cross Site Scripting testing pattern",
        category="vulnerability",
        triggers=["xss", "input", "html", "javascript", "search", "comment"],
        technologies=["Web"],
        lesson=(
            "User input should be tested for reflected, stored and DOM-based "
            "XSS depending on execution context."
        ),
        recommended_checks=[
            "reflection testing",
            "HTML context analysis",
            "JavaScript context analysis",
            "DOM sink analysis",
        ],
        avoid_missing=["stored XSS", "DOM XSS", "client side sinks"],
        source="builtin pentest knowledge",
        created_at="2026-01-01T00:00:00.000Z",
        confidence=0.95,
        scope="builtin",
    ),
    IntelligenceScenario(
        id="builtin-auth-testing",
        title="Authentication and authorization testing",
        category="authentication",
        triggers=["login", "session", "jwt", "cookie", "token", "authorization"],
        technologies=["Web", "API"],
        lesson=(
            "Authentication mechanisms should be tested for weak tokens, "
            "session issues and broken access control."
        ),
        recommended_checks=[
            "JWT validation",
            "session management",
            "cookie security",
            "authorization testing",
            "privilege escalation",
        ],
        avoid_missing=[
            "broken access control",
            "session fixation",
            "token leakage",
        ],
        source="builtin pentest knowledge",
        created_at="2026-01-01T00:00:00.000Z",
        confidence=0.90,
        scope="builtin",
    ),
]
 
 
# =====================================================
# Cross-process file locking (Priority 2 — optional, additive)
# =====================================================
 
@contextlib.contextmanager
def _cross_process_lock(path: Path):
    """Best-effort cross-process guard around a scope file's
    read-check-write section. No-op if `filelock` isn't installed, so
    behavior for the common single-process case is unchanged; a lock
    timeout is logged and the operation proceeds without the lock
    rather than raising a new failure mode TS doesn't have."""
    if not _HAS_FILELOCK:
        yield
        return
    assert filelock is not None
    lock = filelock.FileLock(str(path) + ".lock", timeout=10)
    try:
        with lock:
            yield
    except filelock.Timeout:
        logger.warning(
            "Timed out waiting for cross-process lock on %s; proceeding without it", path
        )
        yield
 
 
# =====================================================
# Intelligence Store
# =====================================================
 
class IntelligenceStore:
 
    def __init__(
        self,
        cwd: str | Path | None = None,
        home: str | Path | None = None,
    ):
        cwd_path = Path(cwd).resolve() if cwd else Path.cwd().resolve()
        home_path = Path(home) if home else Path.home()
 
        self.project_path = (
            cwd_path / ".pentesterflow" / "intelligence" / "scenarios.jsonl"
        )
        self.personal_path = (
            home_path / ".pentesterflow" / "intelligence" / "scenarios.jsonl"
        )
 
        # Per-file parsed-scenario cache keyed on (mtime, size). search()/
        # list() run on the hot path; caching collapses repeated reads to a
        # single parse until the file changes on disk.
        self.file_cache: dict[str, dict[str, Any]] = {}
        self.write_lock = Lock()
 
    # -------------------------------------------------
    # List all intelligence
    # -------------------------------------------------
 
    def list(self) -> list[IntelligenceScenario]:
        return dedupe_scenarios(
            self.read_scenarios(self.project_path, "project")
            + self.read_scenarios(self.personal_path, "personal")
            + BUILTIN_SCENARIOS
        )
 
    # -------------------------------------------------
    # Read JSONL with cache
    # -------------------------------------------------
 
    def read_scenarios(
        self, path: Path, scope: IntelligenceScope
    ) -> list[IntelligenceScenario]:
        if not path.exists():
            return []
 
        try:
            stat = path.stat()
        except OSError:
            logger.exception("Failed to stat %s", path)
            return []
 
        key = str(path)
        cached = self.file_cache.get(key)
        if (
            cached
            and cached["mtime"] == stat.st_mtime
            and cached["size"] == stat.st_size
        ):
            return cached["data"]
 
        data = read_jsonl(path, scope)
        self.file_cache[key] = {
            "mtime": stat.st_mtime,
            "size": stat.st_size,
            "data": data,
        }
        return data
 
    def invalidate(self, path: Path) -> None:
        self.file_cache.pop(str(path), None)
 
    # -------------------------------------------------
    # Search intelligence
    # -------------------------------------------------
 
    def search(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        tokens = tokenize(query)
        if not tokens:
            return []
 
        scenarios = self.list()
 
        # Reference point for the recency boost: the freshest scenario,
        # keeping the ranking deterministic regardless of wall-clock time.
        ref_ms = 0.0
        for scenario in scenarios:
            t = scenario_time_ms(scenario)
            if t > ref_ms:
                ref_ms = t
 
        results = []
        for scenario in scenarios:
            score, matched = score_scenario(scenario, tokens)
            if score <= 0:
                continue
 
            score *= recency_multiplier(scenario_time_ms(scenario), ref_ms)
            results.append({"scenario": scenario, "score": score, "matched": matched})
 
        results.sort(
            key=lambda x: (x["score"], x["scenario"].confidence),
            reverse=True,
        )
 
        return results[: max(1, int(limit))]
 
    # -------------------------------------------------
    # Append a single scenario (project or personal scope)
    # -------------------------------------------------
 
    async def append(self, scenario: IntelligenceScenario) -> Optional[IntelligenceScenario]:
        """Mirrors TS `append`: defaults a falsy/omitted scope to
        'project' (`input.scope ?? 'project'`). No runtime validation
        against 'builtin' — TS relies on its type system for that, not
        a runtime check, so this doesn't raise either."""
        scope = scenario.scope or "project"
        saved = self.append_batch([scenario], scope)  # type: ignore[arg-type]
        return saved[0] if saved else None
 
    # -------------------------------------------------
    # Batch append — single read/append/prune pass per scope.
    # -------------------------------------------------
 
    def append_batch(
        self,
        scenarios: list[IntelligenceScenario],
        scope: Literal["project", "personal"] = "project",
    ) -> list[IntelligenceScenario]:
        """Read-check-append-prune scoped scenarios in one locked pass.
 
        Mirrors TS `appendBatch`: builds a *new* normalized scenario per
        candidate (dataclasses.replace + normalize_scenario, matching
        TS's object-spread approach) instead of mutating the caller's
        objects, dedupes against both on-disk records and earlier
        candidates in this same batch, then does a single append + prune
        per scope file.
        """
        with self.write_lock:
            path = self.personal_path if scope == "personal" else self.project_path
 
            with _cross_process_lock(path):
                existing = self.read_scenarios(path, scope)
                seen_ids = {s.id for s in existing}
                seen_keys = {duplicate_key(s.title, s.category) for s in existing}
 
                fresh: list[IntelligenceScenario] = []
                for candidate in scenarios:
                    normalized = normalize_scenario(dataclasses.replace(candidate, scope=scope))
                    key = duplicate_key(normalized.title, normalized.category)
                    if normalized.id in seen_ids or key in seen_keys:
                        continue
                    seen_ids.add(normalized.id)
                    seen_keys.add(key)
                    fresh.append(normalized)
 
                if not fresh:
                    return []
 
                # mkdir/append are allowed to raise, same as TS (which does
                # not wrap mkdirSync/appendFile in a try/catch — only the
                # trailing chmod call is best-effort there).
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
 
                with open(path, "a", encoding="utf-8") as f:
                    for item in fresh:
                        f.write(json.dumps(item.to_wire(), ensure_ascii=False) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
 
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    logger.warning("Could not chmod %s to 0600 after append", path, exc_info=True)
 
                self.invalidate(path)
                self.prune_if_too_long(path, scope)
                return fresh
 
    # -------------------------------------------------
    # Limit JSONL size
    # -------------------------------------------------
 
    def prune_if_too_long(self, path: Path, scope: IntelligenceScope) -> None:
        """Cap the JSONL at MAX_SCENARIOS_PER_FILE, keeping the most
        recent entries. Best-effort like TS: any failure here is logged
        but never raised, since a prune failure must not break learning."""
        try:
            scenarios = self.read_scenarios(path, scope)
            if len(scenarios) <= MAX_SCENARIOS_PER_FILE:
                return
 
            kept = scenarios[-MAX_SCENARIOS_PER_FILE:]
            tmp = Path(f"{path}.tmp.{secrets.token_hex(3)}")
 
            with open(tmp, "w", encoding="utf-8") as f:
                for item in kept:
                    f.write(json.dumps(item.to_wire(), ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
 
            os.replace(tmp, path)  # atomic on POSIX
            self.invalidate(path)
        except Exception:
            logger.exception(
                "Failed to prune %s (scope=%s) to %d scenarios", path, scope, MAX_SCENARIOS_PER_FILE
            )
 
    # -------------------------------------------------
    # Clear memory
    # -------------------------------------------------
 
    async def clear(self, scope: Literal["project", "personal", "all"] = "all") -> None:
        """Truncate the given scope's JSONL file(s). Best-effort, like TS.
 
        Note: this does NOT force file permissions to 0600 on an
        already-existing file — matching TS's `writeFileSync(p, '',
        {mode: 0o600})`, whose `mode` option only takes effect when the
        file is newly created, not when truncating an existing one.
        """
        targets = []
        if scope in ("project", "all"):
            targets.append(self.project_path)
        if scope in ("personal", "all"):
            targets.append(self.personal_path)
 
        for path in targets:
            try:
                if path.exists():
                    path.write_text("", encoding="utf-8")
                self.invalidate(path)
            except Exception:
                logger.exception("Failed to clear intelligence file %s", path)
 
    # -------------------------------------------------
    # Statistics
    # -------------------------------------------------
 
    def get_stats(self) -> dict[str, int]:
        return {
            "project": len(self.read_scenarios(self.project_path, "project")),
            "personal": len(self.read_scenarios(self.personal_path, "personal")),
        }
 
    # -------------------------------------------------
    # Learning entry point — writes to BOTH project and personal
    # scopes, matching TS learnFromText().
    # -------------------------------------------------
 
    async def learn_from_text(
        self, text: str, source_session_id: str | None = None
    ) -> list[IntelligenceScenario]:
        cleaned = redact(text)
        candidates = extract_scenarios(cleaned, source_session_id)
        if not candidates:
            return []
 
        # Same candidate list passed to both calls, exactly like TS —
        # safe because append_batch never mutates its input (see
        # normalize_scenario / dataclasses.replace above).
        project_saved = self.append_batch(candidates, "project")
        personal_saved = self.append_batch(candidates, "personal")
        return project_saved + personal_saved
 
 
# =====================================================
# Context formatter for LLM
# =====================================================
 
def format_intelligence_context(results: list[dict[str, Any]]) -> str:
    if not results:
        return ""
 
    out = [
        "# Local PentestAgent Intelligence",
        "",
        "The following local intelligence scenarios matched this turn. "
        "Use them as scan-coverage guidance only; verify all claims with "
        "live evidence before reporting findings.",
    ]
 
    for result in results[:5]:
        s: IntelligenceScenario = result["scenario"]
        matched = result["matched"]
        out.append("")
        out.append(f"## {s.title}")
        out.append(f"Category: {s.category} · Confidence: {s.confidence}")
        out.append("Matched: " + (", ".join(matched[:8]) or "context"))
        out.append("Lesson: " + s.lesson)
 
        if s.recommended_checks:
            out.append("Recommended checks: " + ", ".join(s.recommended_checks[:12]))
        if s.avoid_missing:
            out.append("Avoid missing: " + ", ".join(s.avoid_missing[:8]))
 
    return "\n".join(out)
 
 
# =====================================================
# Learning Engine & Scenario Extraction
# =====================================================
 
def extract_scenarios(
    text: str, source_session_id: str | None = None
) -> list[IntelligenceScenario]:
    """All 9 extraction groups from the TS source, in the same order:
    node-source-exposure, preferences, decisions, proven-workflow,
    lesson-learned, tool-config, next-step, finding-pattern,
    coverage-gap."""
    result: list[IntelligenceScenario] = []
    technologies = detect_technologies(text)
    context_triggers = extract_triggers(text)[:20]
    lower = text.lower()
    now = datetime.now(timezone.utc).isoformat()
 
    # -------------------------------------------------
    # Node/PM2 source exposure
    # -------------------------------------------------
    if ("server.js" in lower or "package.json" in lower) and (
        "node" in lower or "express" in lower or "source" in lower
    ):
        result.append(
            IntelligenceScenario(
                id="learned-node-pm2-source-exposure",
                title="Node source exposure should check PM2 deployment files",
                category="recon-gap",
                triggers=[
                    "server.js", "package.json", "node", "express",
                    "source leak", "deployment", "nginx",
                ],
                technologies=["Node.js", "Express", "PM2"],
                lesson=(
                    "When Node source files or package metadata appear during "
                    "recon, include PM2 and process-manager deployment files "
                    "in the next enumeration pass."
                ),
                recommended_checks=[
                    "ecosystem.config.js", "ecosystem.config.cjs",
                    "ecosystem.config.mjs", "pm2.json", "process.json",
                    "app.js", "index.js", "server.js~", "package-lock.json",
                ],
                avoid_missing=["ecosystem.config.js", "PM2 deployment files"],
                source="automatic compaction learning",
                source_session_id=source_session_id,
                updated_at=now,
                confidence=0.9,
                scope="project",
            )
        )
 
    sections = split_markdown_sections(text)
 
    # -------------------------------------------------
    # Preferences
    # -------------------------------------------------
    preference_items = merge_strings(
        section_items(
            sections,
            ["user preferences and working style", "user preferences", "working style"],
        ),
        explicit_preference_items(text),
    )
    for item in preference_items[:12]:
        title = title_from_item("User preference", item)
        result.append(
            IntelligenceScenario(
                id=stable_scenario_id("user-preference", title),
                title=title,
                category="user-preference",
                triggers=merge_strings(context_triggers, extract_triggers(item)),
                technologies=technologies,
                lesson=(
                    "Adapt future responses and workflows to this user "
                    "preference: " + trim_sentence(item, 500)
                ),
                recommended_checks=[
                    "apply this preference when relevant before choosing "
                    "response style or workflow"
                ],
                avoid_missing=[trim_sentence(item, 160)],
                source="continuous learning",
                source_session_id=source_session_id,
                updated_at=now,
                confidence=0.82,
                scope="project",
            )
        )
 
    # -------------------------------------------------
    # Decisions
    # -------------------------------------------------
    for item in section_items(
        sections, ["decisions and assumptions", "important decisions"]
    )[:10]:
        title = title_from_item("Decision memory", item)
        result.append(
            IntelligenceScenario(
                id=stable_scenario_id("decision", title),
                title=title,
                category="decision",
                triggers=merge_strings(context_triggers, extract_triggers(item)),
                technologies=technologies,
                lesson=(
                    "Carry this prior decision forward when the same project "
                    "or pattern recurs: " + trim_sentence(item, 500)
                ),
                recommended_checks=["reuse this decision unless new evidence invalidates it"],
                avoid_missing=[trim_sentence(item, 160)],
                source="continuous learning",
                source_session_id=source_session_id,
                updated_at=now,
                confidence=0.74,
                scope="project",
            )
        )
 
    # -------------------------------------------------
    # Proven workflows
    # -------------------------------------------------
    for item in [
        i
        for i in section_items(
            sections,
            [
                "what worked well", "successful solutions",
                "proven workflows", "workflow optimization", "task outcome",
            ],
        )
        if is_workflow_like_item(i)
    ][:10]:
        title = title_from_item("Proven workflow", item)
        result.append(
            IntelligenceScenario(
                id=stable_scenario_id("proven-workflow", title),
                title=title,
                category="proven-workflow",
                triggers=merge_strings(context_triggers, extract_triggers(item)),
                technologies=technologies,
                lesson=(
                    "This approach has worked before and should be "
                    "considered again in similar tasks: " + trim_sentence(item, 500)
                ),
                recommended_checks=recommended_checks_from_item(item),
                avoid_missing=["reuse proven workflow when context matches"],
                source="continuous learning",
                source_session_id=source_session_id,
                updated_at=now,
                confidence=0.76,
                scope="project",
            )
        )
 
    # -------------------------------------------------
    # Lessons learned / failures
    # -------------------------------------------------
    failure_items = (
        section_items(sections, ["what failed and why", "past mistakes", "lessons learned"])
        + [i for i in bullet_items(text) if is_failure_like_item(i)]
    )
    for item in failure_items[:12]:
        title = title_from_item("Lesson learned", item)
        result.append(
            IntelligenceScenario(
                id=stable_scenario_id("lesson-learned", title),
                title=title,
                category="lesson-learned",
                triggers=merge_strings(context_triggers, extract_triggers(item)),
                technologies=technologies,
                lesson="Avoid repeating this mistake or failed path: " + trim_sentence(item, 500),
                recommended_checks=["choose a better strategy before repeating this action"],
                avoid_missing=[trim_sentence(item, 160)],
                source="continuous learning",
                source_session_id=source_session_id,
                updated_at=now,
                confidence=0.8,
                scope="project",
            )
        )
 
    # -------------------------------------------------
    # Tool / config memory
    # -------------------------------------------------
    for item in [
        i
        for i in section_items(
            sections,
            [
                "frequently used tools commands and configurations",
                "frequently used tools", "files and commands", "tools and commands",
            ],
        )
        if is_tool_config_like_item(i)
    ][:12]:
        title = title_from_item("Tool/config memory", item)
        result.append(
            IntelligenceScenario(
                id=stable_scenario_id("tool-config", title),
                title=title,
                category="tool-config",
                triggers=merge_strings(context_triggers, extract_triggers(item)),
                technologies=technologies,
                lesson=(
                    "Remember this useful tool, command, or configuration "
                    "pattern: " + trim_sentence(item, 500)
                ),
                recommended_checks=recommended_checks_from_item(item),
                avoid_missing=["reuse known working tool/config pattern when applicable"],
                source="continuous learning",
                source_session_id=source_session_id,
                updated_at=now,
                confidence=0.73,
                scope="project",
            )
        )
 
    # -------------------------------------------------
    # Next scan steps
    # -------------------------------------------------
    for item in (
        section_items(sections, ["open todos"]) + section_items(sections, ["next best actions"])
    )[:10]:
        title = title_from_item("Next scan step", item)
        result.append(
            IntelligenceScenario(
                id=stable_scenario_id("next-step", title),
                title=title,
                category="next-step",
                triggers=merge_strings(context_triggers, extract_triggers(item)),
                technologies=technologies,
                lesson="In similar scan context, include this follow-up: " + trim_sentence(item, 500),
                recommended_checks=recommended_checks_from_item(item),
                avoid_missing=[trim_sentence(item, 160)],
                source="automatic compaction learning",
                source_session_id=source_session_id,
                updated_at=now,
                confidence=0.72,
                scope="project",
            )
        )
 
    # -------------------------------------------------
    # Finding validation patterns
    # -------------------------------------------------
    for item in section_items(sections, ["findings and evidence", "confirmed findings"])[:10]:
        title = title_from_item("Finding validation pattern", item)
        result.append(
            IntelligenceScenario(
                id=stable_scenario_id("finding-pattern", title),
                title=title,
                category="finding-pattern",
                triggers=merge_strings(context_triggers, extract_triggers(item)),
                technologies=technologies,
                lesson=(
                    "When this behavior appears, validate it with "
                    "reproducible evidence before reporting: " + trim_sentence(item, 500)
                ),
                recommended_checks=recommended_checks_from_item(item),
                avoid_missing=["evidence-backed validation", "copy-pasteable reproduction request"],
                source="automatic compaction learning",
                source_session_id=source_session_id,
                updated_at=now,
                confidence=0.78,
                scope="project",
            )
        )
 
    # -------------------------------------------------
    # Coverage gaps (no slice in TS — unbounded within this group)
    # -------------------------------------------------
    for item in [
        i
        for i in section_items(sections, ["tested surface", "decisions and assumptions"])
        if is_gap_like_item(i)
    ]:
        title = title_from_item("Coverage gap", item)
        result.append(
            IntelligenceScenario(
                id=stable_scenario_id("coverage-gap", title),
                title=title,
                category="coverage-gap",
                triggers=merge_strings(context_triggers, extract_triggers(item)),
                technologies=technologies,
                lesson=(
                    "Do not treat this as complete coverage in future scans "
                    "without a follow-up check: " + trim_sentence(item, 500)
                ),
                recommended_checks=recommended_checks_from_item(item),
                avoid_missing=[trim_sentence(item, 160)],
                source="automatic compaction learning",
                source_session_id=source_session_id,
                updated_at=now,
                confidence=0.7,
                scope="project",
            )
        )
 
    return dedupe_scenario_inputs(result)[:25]
 
 
# =====================================================
# Markdown parser
# =====================================================
 
def split_markdown_sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = "summary"
    sections[current] = []
 
    for line in text.splitlines():
        match = re.match(r"^#{1,3}\s+(.+?)\s*$", line)
        if match:
            current = normalize_heading(match.group(1))
            sections.setdefault(current, [])
            continue
        sections[current].append(line)
 
    return sections
 
 
def section_items(sections: dict[str, list[str]], names: list[str]) -> list[str]:
    result: list[str] = []
    for name in names:
        key = normalize_heading(name)
        result.extend(bullet_items("\n".join(sections.get(key, []))))
    return [x for x in result if len(x) >= 12][:40]
 
 
def bullet_items(text: str) -> list[str]:
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        line = re.sub(r"^[-*]\s+", "", line)
        line = re.sub(r"^\d+\.\s+", "", line)
        line = re.sub(r"^\[[ xX]\]\s+", "", line)
        line = line.strip()
        if line and not re.match(r"^[-|:]+$", line):
            result.append(line)
    return result
 
 
def normalize_heading(text: str) -> str:
    text = re.sub(r"[*_`]", "", text.lower())
    return re.sub(r"\s+", " ", text).strip()
 
 
# =====================================================
# Preference parser
# =====================================================
 
def explicit_preference_items(text: str) -> list[str]:
    pattern = re.compile(
        r"\b(?:i prefer|prefer to|always use|always keep|do not|don't|dont|"
        r"avoid|keep responses|without commands|no commands|use .* instead of)\b",
        re.I,
    )
    return [item for item in bullet_items(text) if pattern.search(item)]
 
 
# =====================================================
# Detect technologies
# =====================================================
 
def detect_technologies(text: str) -> list[str]:
    checks = [
        (r"\bnode(?:\.js)?\b", "Node.js"),
        (r"\bexpress\b", "Express"),
        (r"\bpm2\b|ecosystem\.config", "PM2"),
        (r"\bnginx\b", "nginx"),
        (r"\bpostgres(?:ql)?\b|\bpg\b", "PostgreSQL"),
        (r"\bgraphql\b", "GraphQL"),
        (r"\bwordpress\b|\bwp-admin\b", "WordPress"),
        (r"\bsupabase\b", "Supabase"),
        (r"\baws\b|\bs3\b|\bcognito\b", "AWS"),
    ]
    return [name for regex, name in checks if re.search(regex, text, re.I)]
 
 
# =====================================================
# Extract trigger keywords
# =====================================================
 
def extract_triggers(text: str) -> list[str]:
    raw: list[str] = []
    raw += re.findall(
        r"[a-z0-9_.-]+\.(?:js|json|env|yml|yaml|php|py|rb|go|ts|tsx|jsx|html)",
        text, re.I,
    )
    raw += re.findall(r"/[a-z0-9_./?=&%-]{2,}", text, re.I)
    raw += re.findall(
        r"\b(?:idor|ssrf|xss|sqli|csrf|cors|rate-limit|source leak|admin|"
        r"token|jwt|graphql|supabase|pm2|nginx|postgres|express|node)\b",
        text, re.I,
    )
    return merge_strings([], raw)[:30]
 
 
# =====================================================
# Recommendation helpers
# =====================================================
 
def recommended_checks_from_item(item: str) -> list[str]:
    checks = extract_triggers(item)
    return checks if checks else [trim_sentence(item, 160)]
 
 
def is_workflow_like_item(item: str) -> bool:
    return bool(re.search(
        r"\b(?:worked|successful|proven|use|run|command|workflow|approach|"
        r"strategy|implemented|fixed|verified|passed)\b", item, re.I,
    ))
 
 
def is_failure_like_item(item: str) -> bool:
    return bool(re.search(
        r"\b(?:failed|failure|mistake|wrong|avoid repeating|did not work|"
        r"doesn't work|blocked|error|regression|hallucination|missed)\b",
        item, re.I,
    ))
 
 
def is_tool_config_like_item(item: str) -> bool:
    return bool(re.search(
        r"`[^`]+`|\b(?:curl|npm|git|rg|python|node|tsx|vitest|biome|tsc|"
        r"ffuf|nuclei|sqlmap|burp|grep|jq|awk|sed)\b|(?:^|\s)--[a-z0-9-]+",
        item, re.I,
    ))
 
 
def is_gap_like_item(item: str) -> bool:
    return bool(re.search(
        r"\b(?:not tested|needs?|todo|check|verify|retest|miss(?:ed|ing)|"
        r"failed|blocked|403|404|unknown|inaccessible|fallback)\b",
        item, re.I,
    ))
 
 
# =====================================================
# String utilities
# =====================================================
 
def title_from_item(prefix: str, item: str) -> str:
    return f"{prefix}: {trim_sentence(item, 90)}"
 
 
def trim_sentence(text: str, max_len: int) -> str:
    text = text.replace("**", "").replace("`", "")
    text = re.sub(r"^\d+\.\s+", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        return text[: max_len - 1] + "…"
    return text
 
 
def merge_strings(a: list[str], b: list[str]) -> list[str]:
    seen = set()
    result = []
    for item in a + b:
        s = item.strip()
        if not s:
            continue
        key = s.lower()
        if key not in seen:
            seen.add(key)
            result.append(s)
    return result[:40]
 
 
def dedupe_scenario_inputs(items: list[IntelligenceScenario]) -> list[IntelligenceScenario]:
    seen = set()
    out = []
    for item in items:
        key = f"{normalize_key(item.category)}\n{normalize_key(item.title)}"
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out
 
 
def stable_scenario_id(category: str, title: str) -> str:
    """FNV-1a 32-bit hash — matches TS's stableScenarioID bit for bit,
    so the same (category, title) yields the same id in both languages.
    (XOR/multiply-mod-2^32 give the same bit pattern whether the value
    is interpreted as signed, as in JS's Math.imul, or kept unsigned via
    `& 0xFFFFFFFF` as here — only the final formatting differs, and both
    sides format via the unsigned interpretation before hex encoding.)"""
    value = f"{category}:{title}"
    h = 2166136261
    for ch in value:
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    return f"learned-{category}-{h:x}"
 
 
def new_scenario_id() -> str:
    return f"scn_{secrets.token_hex(8)}"
 
 
def duplicate_key(title: str, category: str) -> str:
    return f"{normalize_key(category)}\n{normalize_key(title)}"
 
 
def normalize_key(s: str) -> str:
    s = s.lower().replace("**", "")
    s = re.sub(r"\bnext scan step:\s*\d+\.\s*", "next scan step: ", s)
    s = re.sub(r"^\d+\.\s*", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s
 
 
def safe_string(v: Any) -> str:
    """Mirrors TS `safeString`: returns v unchanged if it's already a
    string, else ''. Used before redact()/length-limiting so malformed
    wire data (wrong JSON types) can't crash normalization."""
    return v if isinstance(v, str) else ""
 
 
# =====================================================
# JSONL Reader (Priority 2: validated, logged, never crashes)
# =====================================================
 
def read_jsonl(path: Path, scope: IntelligenceScope) -> list[IntelligenceScenario]:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError:
        logger.exception("Failed to read intelligence file %s", path)
        return []
 
    result: list[IntelligenceScenario] = []
    for line_no, line in enumerate(raw_text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
 
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("Skipping corrupt JSONL line %d in %s (invalid JSON)", line_no, path)
            continue
 
        if not isinstance(data, dict):
            logger.warning("Skipping JSONL line %d in %s (not a JSON object)", line_no, path)
            continue
 
        unknown = [k for k in data if k not in _KNOWN_WIRE_OR_PY_KEYS]
        if unknown:
            logger.debug(
                "Line %d in %s has unrecognized field(s) %s (ignored)", line_no, path, unknown
            )
 
        # The file's own scope always wins over whatever is stored in the
        # record, exactly like TS's `{ ...JSON.parse(trimmed), scope: fallbackScope }`.
        data["scope"] = scope
 
        try:
            result.append(normalize_scenario(IntelligenceScenario.from_wire(data)))
        except Exception:
            logger.warning("Skipping unparsable JSONL line %d in %s", line_no, path, exc_info=True)
 
    return result
 
 
# =====================================================
# Normalize — pure function, mirrors TS normalizeScenario exactly.
# Never mutates its input; always returns a new IntelligenceScenario.
# =====================================================
 
def normalize_scenario(raw: IntelligenceScenario) -> IntelligenceScenario:
    source_session_id = redact(safe_string(raw.source_session_id))[:120]
 
    return IntelligenceScenario(
        id=safe_string(raw.id) or new_scenario_id(),
        title=redact(safe_string(raw.title))[:160] or "Untitled intelligence scenario",
        category=redact(safe_string(raw.category))[:80] or "general",
        triggers=normalize_list(raw.triggers),
        technologies=normalize_list(raw.technologies),
        lesson=redact(safe_string(raw.lesson))[:1200],
        recommended_checks=normalize_list(raw.recommended_checks),
        avoid_missing=normalize_list(raw.avoid_missing),
        source=redact(safe_string(raw.source))[:200] or "local",
        source_session_id=source_session_id or None,
        created_at=safe_string(raw.created_at) or datetime.now(timezone.utc).isoformat(),
        updated_at=safe_string(raw.updated_at) or None,
        confidence=clamp_confidence(raw.confidence),
        scope=raw.scope if raw.scope in ("personal", "builtin") else "project",
    )
 
 
def normalize_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    result = []
    seen = set()
    for item in values:
        s = redact(safe_string(item)).strip()
        if not s:
            continue
        key = s.lower()
        if key not in seen:
            seen.add(key)
            result.append(s[:160])
    return result[:40]
 
 
def clamp_confidence(v: Any) -> float:
    try:
        v = float(v)
    except Exception:
        v = 0.7
    return max(0.0, min(1.0, v))
 
 
# =====================================================
# Search scoring
# =====================================================
 
def score_scenario(s: IntelligenceScenario, tokens: list[str]) -> tuple[float, list[str]]:
    fields = [
        (s.title.lower(), 7, "title"),
        (s.category.lower(), 5, "category"),
        (" ".join(s.triggers).lower(), 8, "triggers"),
        (" ".join(s.technologies).lower(), 6, "technology"),
        (" ".join(s.recommended_checks).lower(), 5, "recommendedChecks"),
        (" ".join(s.avoid_missing).lower(), 4, "avoidMissing"),
        (s.lesson.lower(), 2, "lesson"),
    ]
 
    score = 0.0
    matched: list[str] = []
    matched_seen: set[str] = set()
 
    for token in tokens:
        for text, weight, label in fields:
            if token_matches_lower(text, token):
                score += weight
                tag = f"{label}:{token}"
                if tag not in matched_seen:
                    matched_seen.add(tag)
                    matched.append(tag)
 
    if score:
        score += s.confidence
 
    return score, matched
 
 
def token_matches_lower(text: str, token: str) -> bool:
    if token in text:
        return True
    if "." in token:
        return token.replace(".", " ") in text
    return False
 
 
# =====================================================
# Tokenize / Ranking
# =====================================================
 
def tokenize(text: str) -> list[str]:
    tokens = []
    seen = set()
    for raw_token in re.findall(r"[a-z0-9_.-]{2,}", text.lower()):
        token = raw_token.strip("._-")
        if len(token) < 2 or token in seen:
            continue
        seen.add(token)
        tokens.append(token)
    return tokens[:300]
 
 
def scenario_time_ms(s: IntelligenceScenario) -> float:
    raw = s.updated_at or s.created_at
    if not raw:
        return 0
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.timestamp() * 1000
    except Exception:
        return 0
 
 
def recency_multiplier(time_ms: float, ref_ms: float) -> float:
    if time_ms <= 0 or ref_ms <= 0:
        return 1.0
    age = max(0.0, ref_ms - time_ms)
    return 1 + RECENCY_BOOST * 2 ** (-age / RECENCY_HALF_LIFE_MS)
 
 
def dedupe_scenarios(items: list[IntelligenceScenario]) -> list[IntelligenceScenario]:
    result = []
    seen = set()
    for item in items:
        key = duplicate_key(item.title, item.category)
        if item.id in seen or key in seen:
            continue
        seen.add(item.id)
        seen.add(key)
        result.append(item)
    return result
 
 
# =====================================================
# Redaction (Priority 2: configurable, same default as TS)
# =====================================================
 
def redact(text: Optional[str], patterns: Optional[list[tuple[str, str]]] = None) -> str:
    """Redact obvious secret-looking substrings.
 
    `patterns` is a list of (regex, replacement) pairs, defaulting to
    DEFAULT_REDACT_PATTERNS — the exact same single rule the TS store's
    redact module applies. Passing a custom list only affects that call
    site; default behavior for existing callers is unchanged.
    """
    if not text:
        return ""
    for pattern, replacement in (patterns if patterns is not None else DEFAULT_REDACT_PATTERNS):
        text = re.sub(pattern, replacement, text, flags=re.I)
    return text
 
