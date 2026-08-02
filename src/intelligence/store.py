"""
Intelligence Store

Long-term memory for AI Pentest Agent.

Port từ Pentestagent TypeScript IntelligenceStore.

Chức năng:
- Project intelligence
- Personal intelligence
- Builtin knowledge
- Search context cho LLM
- Append learning scenarios
"""

from __future__ import annotations

import json
import os
import re
import time
import hashlib
import secrets

from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import datetime, timezone
from threading import Lock
from typing import Optional, Literal


# =====================================================
# Constants
# =====================================================

MAX_SCENARIOS_PER_FILE = 5000
RECENCY_BOOST = 0.25
RECENCY_HALF_LIFE_MS = 14 * 24 * 60 * 60 * 1000

IntelligenceScope = Literal["project", "personal", "builtin"]


# =====================================================
# Data Model
# =====================================================

@dataclass
class IntelligenceScenario:
    """
    Một knowledge item của Pentest Agent
    """
    id: str
    title: str
    category: str
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


# =====================================================
# Builtin Pentest Knowledge
#
# Kiến thức có sẵn khi agent khởi tạo
# =====================================================

BUILTIN_SCENARIOS = [
    IntelligenceScenario(
        id="builtin-web-recon",
        title="Web reconnaissance checklist",
        category="recon",
        triggers=[
            "domain",
            "website",
            "web",
            "technology",
            "port",
            "service"
        ],
        technologies=[
            "Web"
        ],
        lesson=(
            "Before exploitation, perform reconnaissance "
            "to identify technologies, services, "
            "and attack surface."
        ),
        recommended_checks=[
            "nmap service discovery",
            "technology fingerprinting",
            "directory enumeration",
            "endpoint discovery"
        ],
        avoid_missing=[
            "hidden services",
            "backup files",
            "exposed endpoints"
        ],
        source="builtin pentest knowledge",
        created_at="2026-01-01T00:00:00Z",
        confidence=0.95,
        scope="builtin"
    ),
    IntelligenceScenario(
        id="builtin-sqli-pattern",
        title="SQL injection testing pattern",
        category="vulnerability",
        triggers=[
            "sql",
            "sqli",
            "parameter",
            "login",
            "id"
        ],
        technologies=[
            "Database",
            "Web"
        ],
        lesson=(
            "User controlled parameters should be tested "
            "for SQL injection using manual payloads "
            "and automated verification."
        ),
        recommended_checks=[
            "single quote test",
            "boolean based SQL injection",
            "time based SQL injection",
            "sqlmap verification"
        ],
        avoid_missing=[
            "blind SQL injection",
            "hidden parameters"
        ],
        source="builtin pentest knowledge",
        created_at="2026-01-01T00:00:00Z",
        confidence=0.95,
        scope="builtin"
    ),
    IntelligenceScenario(
        id="builtin-xss-pattern",
        title="Cross site scripting testing pattern",
        category="vulnerability",
        triggers=[
            "xss",
            "input",
            "search",
            "comment",
            "html"
        ],
        technologies=[
            "Web"
        ],
        lesson=(
            "User supplied input should be tested "
            "for reflected, stored and DOM XSS "
            "based on execution context."
        ),
        recommended_checks=[
            "reflection testing",
            "HTML context analysis",
            "JavaScript context analysis",
            "DOM sink analysis"
        ],
        avoid_missing=[
            "stored XSS",
            "DOM XSS"
        ],
        source="builtin pentest knowledge",
        created_at="2026-01-01T00:00:00Z",
        confidence=0.95,
        scope="builtin"
    ),
    IntelligenceScenario(
        id="builtin-auth-testing",
        title="Authentication security testing",
        category="authentication",
        triggers=[
            "login",
            "session",
            "jwt",
            "cookie"
        ],
        technologies=[
            "Web"
        ],
        lesson=(
            "Authentication mechanisms should be "
            "checked for weak sessions, token issues "
            "and access control weaknesses."
        ),
        recommended_checks=[
            "JWT validation",
            "session management",
            "authorization testing"
        ],
        avoid_missing=[
            "privilege escalation",
            "broken access control"
        ],
        source="builtin pentest knowledge",
        created_at="2026-01-01T00:00:00Z",
        confidence=0.9,
        scope="builtin"
    )
]


# =====================================================
# Intelligence Store
# =====================================================

class IntelligenceStore:

    def __init__(
        self,
        cwd: str | Path | None = None,
        home: str | Path | None = None
    ):

        cwd_path = Path(cwd) if cwd else Path.cwd()

        home_path = Path(home) if home else Path.home()


        self.project_path = (
            cwd_path
            / ".pentestagent"
            / "intelligence"
            / "scenarios.jsonl"
        )


        self.personal_path = (
            home_path
            / ".pentestagent"
            / "intelligence"
            / "scenarios.jsonl"
        )
        self.file_cache = {}

        self.write_lock = Lock()
    # -------------------------------------------------
    # List all intelligence
    # -------------------------------------------------

    def list(self):
        return dedupe_scenarios(
            self.read_scenarios(self.project_path, "project")
            + self.read_scenarios(self.personal_path, "personal")
            + BUILTIN_SCENARIOS
        )

    # -------------------------------------------------
    # Read JSONL with cache
    # -------------------------------------------------

    def read_scenarios(
        self,
        path: Path,
        scope: IntelligenceScope
    ):
        if not path.exists():
            return []

        stat = path.stat()
        key = str(path)
        cached = self.file_cache.get(key)

        if cached:
            if (
                cached["mtime"] == stat.st_mtime
                and cached["size"] == stat.st_size
            ):
                return cached["data"]

        data = read_jsonl(path, scope)
        self.file_cache[key] = {
            "mtime": stat.st_mtime,
            "size": stat.st_size,
            "data": data
        }
        return data

    # -------------------------------------------------
    # Search intelligence
    # -------------------------------------------------

    def search(
        self,
        query: str,
        limit: int = 5
    ):
        tokens = tokenize(query)
        if not tokens:
            return []

        scenarios = self.list()

        # reference time cho recency boost
        ref_ms = 0
        for scenario in scenarios:
            t = scenario_time_ms(scenario)
            if t > ref_ms:
                ref_ms = t

        results = []
        for scenario in scenarios:
            score, matched = score_scenario(scenario, tokens)
            if score <= 0:
                continue

            score *= recency_multiplier(
                scenario_time_ms(scenario),
                ref_ms
            )

            results.append({
                "scenario": scenario,
                "score": score,
                "matched": matched
            })

        results.sort(
            key=lambda x: (
                x["score"],
                x["scenario"].confidence
            ),
            reverse=True
        )

        return results[:max(1, int(limit))]

    # -------------------------------------------------
    # Append intelligence
    # -------------------------------------------------

    def append(
        self,
        scenario: IntelligenceScenario
    ):
        scope = scenario.scope
        if scope == "builtin":
            raise ValueError("Cannot append builtin memory")

        with self.write_lock:
            path = (
                self.personal_path
                if scope == "personal"
                else self.project_path
            )

            existing = self.read_scenarios(path, scope)
            key = duplicate_key(scenario.title, scenario.category)

            for item in existing:
                if duplicate_key(item.title, item.category) == key:
                    return False

            scenario = normalize_scenario(scenario)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

            with open(path, "a", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        asdict(scenario),
                        ensure_ascii=False
                    ) + "\n"
                )

            os.chmod(path, 0o600)
            self.invalidate(path)
            self.prune_if_too_long(path, scope)
            return True

    # -------------------------------------------------
    # Batch append
    # -------------------------------------------------

    def append_batch(
        self,
        scenarios: list[IntelligenceScenario],
        scope: IntelligenceScope = "project"
    ):
        saved = []

        with self.write_lock:
            path = (
                self.personal_path
                if scope == "personal"
                else self.project_path
            )

            existing = self.read_scenarios(path, scope)
            keys = set(
                duplicate_key(x.title, x.category)
                for x in existing
            )

            fresh = []
            for item in scenarios:
                item.scope = scope
                item = normalize_scenario(item)
                key = duplicate_key(item.title, item.category)

                if key in keys:
                    continue

                keys.add(key)
                fresh.append(item)

            if not fresh:
                return []

            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

            with open(path, "a", encoding="utf-8") as f:
                for item in fresh:
                    f.write(
                        json.dumps(
                            asdict(item),
                            ensure_ascii=False
                        ) + "\n"
                    )

            os.chmod(path, 0o600)
            saved.extend(fresh)
            self.invalidate(path)
            self.prune_if_too_long(path, scope)

        return saved

    # -------------------------------------------------
    # Cache invalidate
    # -------------------------------------------------

    def invalidate(self, path: Path):
        self.file_cache.pop(str(path), None)

    # -------------------------------------------------
    # Limit JSONL size
    # -------------------------------------------------

    def prune_if_too_long(
        self,
        path: Path,
        scope
    ):
        try:
            scenarios = self.read_scenarios(path, scope)

            if len(scenarios) <= MAX_SCENARIOS_PER_FILE:
                return

            scenarios = scenarios[-MAX_SCENARIOS_PER_FILE:]
            tmp = str(path) + ".tmp"

            with open(tmp, "w", encoding="utf-8") as f:
                for item in scenarios:
                    f.write(
                        json.dumps(
                            asdict(item),
                            ensure_ascii=False
                        ) + "\n"
                    )

            os.replace(tmp, path)
            self.invalidate(path)
        except Exception:
            pass

    # -------------------------------------------------
    # Clear memory
    # -------------------------------------------------

    async def clear(self, scope="all"):
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
                pass

    # -------------------------------------------------
    # Statistics
    # -------------------------------------------------

    def get_stats(self):
        return {
            "project": len(
                self.read_scenarios(self.project_path, "project")
            ),
            "personal": len(
                self.read_scenarios(self.personal_path, "personal")
            )
        }

    # -------------------------------------------------
    # Method learn_from_text gắn trực tiếp trong Class
    # -------------------------------------------------

    async def learn_from_text(
        self,
        text: str,
        source_session_id: str | None = None
    ):
        """
        Phân tích output pentest / session summary
        và tạo intelligence memory mới.
        """
        cleaned = redact(text)
        candidates = extract_scenarios(cleaned, source_session_id)

        if not candidates:
            return []

        saved = []

        for candidate in candidates:
            if self.append(candidate):
                saved.append(candidate)

        return saved
    

# =====================================================
# Context formatter for LLM
# =====================================================

def format_intelligence_context(results):
    if not results:
        return ""

    out = [
        "# Local Pentestagent Intelligence",
        "",
        "Use these local intelligence scenarios as guidance only. "
        "Verify findings with real evidence before reporting."
    ]

    for result in results[:5]:
        s = result["scenario"]
        out.append("")
        out.append(f"## {s.title}")
        out.append(f"Category: {s.category} Confidence: {s.confidence}")
        out.append("Matched: " + ", ".join(result["matched"][:8]))
        out.append("Lesson: " + s.lesson)

        if s.recommended_checks:
            out.append(
                "Recommended checks: " + ", ".join(s.recommended_checks[:12])
            )

        if s.avoid_missing:
            out.append("Avoid missing: " + ", ".join(s.avoid_missing[:8]))

    return "\n".join(out)


# =====================================================
# Learning Engine & Scenario Extraction
# =====================================================

def learn_from_text(
    store: IntelligenceStore,
    text: str,
    source_session_id: str | None = None
):
    cleaned = redact(text)
    candidates = extract_scenarios(cleaned, source_session_id)

    if not candidates:
        return []

    return store.append_batch(candidates, "project")


def extract_scenarios(
    text: str,
    source_session_id=None
):
    result = []
    technologies = detect_technologies(text)
    triggers = extract_triggers(text)
    lower = text.lower()

    # -------------------------------------------------
    # Node source exposure example
    # -------------------------------------------------
    if (
        ("server.js" in lower or "package.json" in lower)
        and ("node" in lower or "express" in lower)
    ):
        result.append(
            IntelligenceScenario(
                id="learned-node-source",
                title="Node source exposure should check deployment files",
                category="recon-gap",
                triggers=[
                    "server.js",
                    "package.json",
                    "node",
                    "express"
                ],
                technologies=[
                    "Node.js",
                    "Express"
                ],
                lesson=(
                    "When Node source files or metadata "
                    "are exposed, check deployment "
                    "configuration files."
                ),
                recommended_checks=[
                    "ecosystem.config.js",
                    "pm2.json",
                    "package-lock.json"
                ],
                avoid_missing=[
                    "deployment secrets",
                    "backup files"
                ],
                source="automatic learning",
                source_session_id=source_session_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                confidence=0.9
            )
        )

    # -------------------------------------------------
    # Preferences
    # -------------------------------------------------
    sections = split_markdown_sections(text)
    preferences = merge_strings(
        section_items(
            sections,
            [
                "user preferences",
                "working style",
            ],
        ),
        explicit_preference_items(text),
    )

    for item in preferences[:10]:
        title = title_from_item("User preference", item)
        result.append(
            IntelligenceScenario(
                id=stable_scenario_id("preference", title),
                title=title,
                category="user-preference",
                triggers=merge_strings(triggers, extract_triggers(item)),
                technologies=technologies,
                lesson=(
                    "Adapt future workflow based on preference: "
                    + trim_sentence(item, 500)
                ),
                recommended_checks=[
                    "apply preference when relevant"
                ],
                avoid_missing=[
                    trim_sentence(item, 160)
                ],
                source="continuous learning",
                source_session_id=source_session_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                confidence=0.82
            )
        )

    # -------------------------------------------------
    # Decisions
    # -------------------------------------------------
    decisions = section_items(
        sections,
        [
            "decisions and assumptions",
            "important decisions"
        ]
    )

    for item in decisions[:10]:
        title = title_from_item("Decision memory", item)
        result.append(
            IntelligenceScenario(
                id=stable_scenario_id("decision", title),
                title=title,
                category="decision",
                triggers=triggers,
                technologies=technologies,
                lesson=(
                    "Carry previous decision forward when context matches: "
                    + trim_sentence(item, 500)
                ),
                recommended_checks=[
                    "reuse decision unless evidence changes"
                ],
                avoid_missing=[
                    trim_sentence(item, 160)
                ],
                source="continuous learning",
                source_session_id=source_session_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                confidence=0.74
            )
        )

    # -------------------------------------------------
    # Successful workflow
    # -------------------------------------------------
    workflows = section_items(
        sections,
        [
            "what worked well",
            "successful solutions",
            "proven workflows"
        ]
    )

    for item in workflows[:10]:
        if not is_workflow_like_item(item):
            continue

        title = title_from_item("Proven workflow", item)
        result.append(
            IntelligenceScenario(
                id=stable_scenario_id("workflow", title),
                title=title,
                category="proven-workflow",
                triggers=triggers,
                technologies=technologies,
                lesson=(
                    "Reuse this workflow in similar situations: "
                    + trim_sentence(item, 500)
                ),
                recommended_checks=recommended_checks_from_item(item),
                avoid_missing=[
                    "reuse proven workflow"
                ],
                source="continuous learning",
                source_session_id=source_session_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                confidence=0.76
            )
        )

    # -------------------------------------------------
    # Failure / lessons learned
    # -------------------------------------------------
    failures = section_items(
        sections,
        [
            "what failed and why",
            "past mistakes",
            "lessons learned"
        ]
    )

    for item in failures[:10]:
        if not is_failure_like_item(item):
            continue

        title = title_from_item("Lesson learned", item)
        result.append(
            IntelligenceScenario(
                id=stable_scenario_id("lesson", title),
                title=title,
                category="lesson-learned",
                triggers=triggers,
                technologies=technologies,
                lesson=(
                    "Avoid repeating this mistake: "
                    + trim_sentence(item, 500)
                ),
                recommended_checks=[
                    "choose better strategy"
                ],
                avoid_missing=[
                    trim_sentence(item, 160)
                ],
                source="continuous learning",
                source_session_id=source_session_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                confidence=0.8
            )
        )

    return dedupe_scenario_inputs(result)[:25]


# =====================================================
# Markdown parser
# =====================================================

def split_markdown_sections(text):
    sections = {}
    current = "summary"
    sections[current] = []

    for line in text.splitlines():
        match = re.match(r"^#{1,3}\s+(.+)", line)
        if match:
            current = normalize_heading(match.group(1))
            sections.setdefault(current, [])
            continue

        sections[current].append(line)

    return sections


def section_items(sections, names):
    result = []
    for name in names:
        key = normalize_heading(name)
        result.extend(
            bullet_items("\n".join(sections.get(key, [])))
        )

    return [x for x in result if len(x) >= 12]


def bullet_items(text):
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        line = re.sub(r"^[-*]\s+", "", line)
        line = re.sub(r"^\d+\.\s+", "", line)

        if line:
            result.append(line)

    return result


def normalize_heading(text):
    return re.sub(r"\s+", " ", text.lower().strip())


# =====================================================
# Preference parser
# =====================================================

def explicit_preference_items(text):
    return [
        item
        for item in bullet_items(text)
        if re.search(
            r"\b("
            r"prefer|always use|always keep|do not|don't|avoid|"
            r"keep responses|without commands|use .* instead of"
            r")\b",
            item,
            re.I
        )
    ]


# =====================================================
# Detect technologies
# =====================================================

def detect_technologies(text):
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
        (r"\bmysql\b", "MySQL"),
        (r"\bphp\b", "PHP"),
    ]

    return [
        name
        for regex, name in checks
        if re.search(regex, text, re.I)
    ]


# =====================================================
# Extract trigger keywords
# =====================================================

def extract_triggers(text):
    result = []

    result += re.findall(
        r"[a-z0-9_.-]+\.(?:js|json|env|yml|yaml|php|py|rb|go|ts|html)",
        text,
        re.I
    )

    result += re.findall(
        r"/[a-z0-9_./?=&%-]{2,}",
        text,
        re.I
    )

    result += re.findall(
        r"\b("
        r"idor|ssrf|xss|sqli|csrf|cors|"
        r"admin|jwt|token|graphql|"
        r"sqlmap|burp|nmap|"
        r"pm2|nginx|express|node"
        r")\b",
        text,
        re.I
    )

    return merge_strings([], result)[:30]


# =====================================================
# Recommendation helpers
# =====================================================

def recommended_checks_from_item(item):
    checks = extract_triggers(item)

    if checks:
        return checks

    return [
        trim_sentence(item, 160)
    ]


def is_workflow_like_item(item):
    return bool(
        re.search(
            r"\b("
            r"worked|successful|proven|"
            r"use|run|command|workflow|"
            r"implemented|fixed|verified"
            r")\b",
            item,
            re.I
        )
    )


def is_failure_like_item(item):
    return bool(
        re.search(
            r"\b("
            r"failed|failure|mistake|wrong|"
            r"avoid|blocked|error|"
            r"missed|hallucination"
            r")\b",
            item,
            re.I
        )
    )


def is_tool_config_like_item(item):
    return bool(
        re.search(
            r"`[^`]+`|"
            r"\b("
            r"curl|npm|git|python|node|"
            r"ffuf|nuclei|sqlmap|burp|grep"
            r")\b",
            item,
            re.I
        )
    )


def is_gap_like_item(item):
    return bool(
        re.search(
            r"\b("
            r"not tested|todo|check|verify|"
            r"retest|missing|failed|403|404|"
            r"unknown"
            r")\b",
            item,
            re.I
        )
    )


# =====================================================
# String utilities
# =====================================================

def title_from_item(prefix, item):
    return (
        prefix
        + ": "
        + trim_sentence(item, 90)
    )


def trim_sentence(text, max_len):
    text = (
        text
        .replace("**", "")
        .replace("`", "")
    )

    text = re.sub(
        r"\s+",
        " ",
        text
    ).strip()

    if len(text) > max_len:
        return text[:max_len - 1] + "…"

    return text


def merge_strings(a, b):
    seen = set()
    result = []

    for item in a + b:
        key = item.lower().strip()

        if key and key not in seen:
            seen.add(key)
            result.append(item.strip())

    return result[:40]


def stable_scenario_id(category, title):
    value = f"{category}:{title}"

    hash_value = hashlib.sha256(
        value.encode()
    ).hexdigest()[:8]

    return f"learned-{category}-{hash_value}"


def duplicate_key(title, category):
    return (
        category.lower().strip()
        + "\n"
        + title.lower().strip()
    )


# =====================================================
# JSONL Reader
# =====================================================

def read_jsonl(path, scope):
    result = []

    try:
        with open(
            path,
            encoding="utf-8"
        ) as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue

                try:
                    data = json.loads(line)
                    data["scope"] = scope

                    result.append(
                        normalize_scenario(
                            IntelligenceScenario(**data)
                        )
                    )
                except Exception:
                    continue
    except Exception:
        pass

    return result


# =====================================================
# Normalize
# =====================================================

def normalize_scenario(s):
    s.title = redact(s.title)[:160]
    s.category = redact(s.category)[:80]
    s.lesson = redact(s.lesson)[:1200]

    s.source = redact(s.source)[:200]

    s.confidence = clamp_confidence(
        s.confidence
    )

    s.triggers = normalize_list(
        s.triggers
    )

    s.technologies = normalize_list(
        s.technologies
    )

    s.recommended_checks = normalize_list(
        s.recommended_checks
    )

    s.avoid_missing = normalize_list(
        s.avoid_missing
    )

    if not s.created_at:
        s.created_at = datetime.now(
            timezone.utc
        ).isoformat()

    return s


def normalize_list(values):
    result = []
    seen = set()

    for x in values:
        x = redact(str(x)).strip()

        if not x:
            continue

        key = x.lower()

        if key not in seen:
            seen.add(key)
            result.append(
                x[:160]
            )

    return result[:40]


def clamp_confidence(v):
    try:
        v = float(v)
    except Exception:
        v = 0.7

    return max(
        0,
        min(
            1,
            v
        )
    )


# =====================================================
# Search scoring
# =====================================================

def score_scenario(
    s,
    tokens
):
    fields = [
        (s.title.lower(), 7, "title"),
        (s.category.lower(), 5, "category"),
        (" ".join(s.triggers).lower(), 8, "triggers"),
        (" ".join(s.technologies).lower(), 6, "technology"),
        (" ".join(s.recommended_checks).lower(), 5, "recommendedChecks"),
        (" ".join(s.avoid_missing).lower(), 4, "avoidMissing"),
        (s.lesson.lower(), 2, "lesson")
    ]

    score = 0
    matched = []

    for token in tokens:
        for text, weight, label in fields:
            if token_matches_lower(
                text,
                token
            ):
                score += weight
                matched.append(
                    f"{label}:{token}"
                )

    if score:
        score += s.confidence

    return score, matched


def token_matches_lower(
    text,
    token
):
    if token in text:
        return True

    if "." in token:
        return token.replace(
            ".",
            " "
        ) in text

    return False


# =====================================================
# Tokenize / Ranking
# =====================================================

def tokenize(text):
    tokens = []
    seen = set()

    for token in re.findall(
        r"[a-z0-9_.-]{2,}",
        text.lower()
    ):
        token = token.strip(
            "._-"
        )

        if token not in seen:
            seen.add(token)
            tokens.append(token)

    return tokens[:300]


def scenario_time_ms(s):
    try:
        dt = datetime.fromisoformat(
            s.updated_at
            or
            s.created_at
            .replace(
                "Z",
                "+00:00"
            )
        )

        return (
            dt.timestamp()
            *
            1000
        )
    except Exception:
        return 0


def recency_multiplier(
    time_ms,
    ref_ms
):
    if not time_ms or not ref_ms:
        return 1

    age = max(
        0,
        ref_ms - time_ms
    )

    return (
        1
        +
        RECENCY_BOOST
        *
        2 ** (
            -age /
            RECENCY_HALF_LIFE_MS
        )
    )


def dedupe_scenarios(items):
    result = []
    seen = set()

    for item in items:
        key = duplicate_key(
            item.title,
            item.category
        )

        if (
            item.id in seen
            or
            key in seen
        ):
            continue

        seen.add(item.id)
        seen.add(key)

        result.append(item)

    return result


def dedupe_scenario_inputs(items):
    return dedupe_scenarios(items)


# =====================================================
# Simple Redaction
# =====================================================

def redact(text):
    if not text:
        return ""

    text = re.sub(
        r"(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+",
        r"\1=[REDACTED]",
        text,
        flags=re.I
    )

    return text