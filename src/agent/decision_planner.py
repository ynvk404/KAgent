from dataclasses import dataclass
import ipaddress
import re
from typing import List, Optional, TypedDict

from src.skills.registry import (
    CANDIDATE_CLASS_ALIASES,
    Skill,
    normalize_candidate_class,
)
from src.target.target import Target


@dataclass
class DecisionPlan:
    recommended_skill: Optional[str]
    reason: str
    risk: str
    checklist: List[str]
    guidance: str
    candidate_id: Optional[str] = None


@dataclass(frozen=True)
class PlannerCandidate:
    id: str
    candidate_class: str
    status: str
    endpoint: str | None = None
    priority: str | None = None
    latest_outcome: str | None = None
    deferred_reason: str | None = None
    evidence_count: int = 0
    coverage_synced: bool | None = None


@dataclass(frozen=True)
class PlannerContext:
    active_skills: frozenset[str] = frozenset()
    candidate_classes: frozenset[str] = frozenset()
    completed_skills: frozenset[str] = frozenset()
    candidates: tuple[PlannerCandidate, ...] = ()


class SkillRecommendation(TypedDict):
    name: str
    reason: str


class IntentScore(TypedDict):
    skill_name: str
    score: int
    strong_count: int
    explicit_count: int
    candidate_count: int
    prerequisite_count: int
    hits: List[str]


STRONG_KEYWORD_WEIGHT = 5
WEAK_KEYWORD_WEIGHT = 1
EXPLICIT_SKILL_WEIGHT = 20
CANDIDATE_CLASS_WEIGHT = 10
PREREQUISITE_WEIGHT = 2
STAGE_WEIGHT = 1
MIN_RECOMMEND_SCORE = 5

GENERIC_TRIGGER_TERMS = frozenset(
    {
        "candidate",
        "candidates",
        "check",
        "endpoint",
        "endpoints",
        "route",
        "routes",
        "scan",
        "test",
    }
)

_HOST_TOKEN_RE = re.compile(
    r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b",
    re.IGNORECASE,
)
_HOST_LABEL_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
    re.IGNORECASE,
)
_FILE_SUFFIXES = {
    "cjs",
    "conf",
    "config",
    "css",
    "go",
    "html",
    "ini",
    "java",
    "js",
    "json",
    "jsx",
    "md",
    "mjs",
    "php",
    "rb",
    "sql",
    "toml",
    "ts",
    "tsx",
    "txt",
    "xml",
    "yaml",
    "yml",
}

HIGH_RISK_TERMS = [
    "exploit",
    "rce",
    "sqlmap",
    "nuclei",
    "ffuf",
    "masscan",
    "bruteforce",
    "brute force",
    "delete",
    "dos",
    "ddos",
    "fuzz",
]

WORKFLOW_TERMS = [
    "next",
    "test",
    "scan",
    "recon",
    "enumerate",
    "hunt",
    "check",
    "verify",
    "exploit",
    "poc",
    "bug",
    "vuln",
    "vulnerability",
    "endpoint",
    "api",
    "auth",
    "authorization",
    "finding",
]

INFORMATIONAL_PATTERNS = (
    re.compile(r"^(?:what is|what are|define|explain|meaning of)\b"),
    re.compile(r"^(?:what(?:'s| is) the )?difference between\b"),
    re.compile(r"^how (?:does|do|is|are|can)\b"),
)

OPERATIONAL_ACTION_TERMS = (
    "analyze",
    "check",
    "enumerate",
    "exploit",
    "inspect",
    "probe",
    "recon",
    "scan",
    "test",
    "validate",
    "verify",
)


def build_decision_plan(
    user_msg: str,
    skills: List[Skill],
    target: Target,
    context: PlannerContext | None = None,
) -> Optional[DecisionPlan]:
    text = user_msg.strip()

    if not text:
        return None

    normalized = normalize(text)
    if is_purely_informational(normalized):
        return None

    recommended = recommend_skill(normalized, skills, context)
    recommended_skill = next(
        (skill for skill in skills if recommended and skill.name == recommended["name"]),
        None,
    )
    selected = select_candidate(
        text, context.candidates if context else (), recommended,
        frozenset(recommended_skill.candidate_classes) if recommended_skill else frozenset(),
    )
    if selected is not None and recommended is None:
        matching = [
            skill for skill in skills
            if not skill.disable_model_invocation
            and selected.candidate_class in skill.candidate_classes
        ]
        if len(matching) == 1:
            recommended = {
                "name": matching[0].name,
                "reason": f"candidate {selected.id} has class {selected.candidate_class}",
            }

    risk = (
        "high"
        if includes_any(normalized, HIGH_RISK_TERMS)
        else "normal"
    )

    target_known = (not target.empty()) or has_host_like_text(text)

    if (
        recommended is None
        and risk == "normal"
        and not target_known
        and not includes_any(normalized, WORKFLOW_TERMS)
    ):
        return None

    checklist = build_checklist(
        recommended["name"] if recommended else None,
        target_known,
        risk,
    )

    if recommended:
        reason = recommended["reason"]
    else:
        reason = "no specialized intent detected with sufficient confidence"

    return DecisionPlan(
        recommended_skill=recommended["name"] if recommended else None,
        reason=reason,
        risk=risk,
        checklist=checklist,
        guidance=render_guidance(
            recommended["name"] if recommended else None,
            reason,
            risk,
            checklist,
            selected,
            context.candidates if context else (),
        ),
        candidate_id=selected.id if selected else None,
    )


def select_candidate(
    user_text: str,
    candidates: tuple[PlannerCandidate, ...],
    recommended: SkillRecommendation | None,
    recommended_classes: frozenset[str] = frozenset(),
) -> PlannerCandidate | None:
    if not candidates:
        return None
    explicitly_named = [item for item in candidates if item.id in user_text]
    if explicitly_named:
        return sorted(explicitly_named, key=lambda item: item.id)[0]
    actionable = [item for item in candidates if item.status in {"new", "queued", "validating"}]
    if recommended:
        matched = [item for item in actionable if item.candidate_class in recommended_classes]
        if matched:
            actionable = matched
        else:
            return None
    if not actionable:
        return None
    status_order = {"validating": 0, "queued": 1, "new": 2}
    priority_order = {"high": 0, "medium": 1, "low": 2}
    return min(
        actionable,
        key=lambda item: (
            status_order.get(item.status, 3),
            priority_order.get(item.priority or "", 3),
            -item.evidence_count,
            item.id,
        ),
    )


def recommend_skill(
    normalized: str,
    skills: List[Skill],
    context: PlannerContext | None = None,
) -> Optional[SkillRecommendation]:
    if is_purely_informational(normalized):
        return None

    scores = detect_intent(normalized, skills, context)
    best = confidence_check(scores)

    if best is None:
        return None

    top_hits = ", ".join(best["hits"][:4])

    return {
        "name": best["skill_name"],
        "reason": f"matched {best['skill_name']} signals: {top_hits}",
    }


def is_purely_informational(normalized: str) -> bool:
    """Return true for explanation requests with no testing action.

    Candidate and skill names remain metadata-driven.  This only classifies
    the requested mode of work, so future vulnerability classes need no
    planner changes.
    """
    informational = any(pattern.search(normalized) for pattern in INFORMATIONAL_PATTERNS)
    operational = any(
        contains_keyword(normalized, term)
        for term in OPERATIONAL_ACTION_TERMS
    )
    return informational and not operational


def detect_intent(
    normalized: str,
    skills: List[Skill],
    context: PlannerContext | None = None,
) -> List[IntentScore]:
    planner_context = context or PlannerContext()
    completed_or_active_skills = {
        normalize_metadata_skill_name(name)
        for name in (
            planner_context.active_skills
            | planner_context.completed_skills
        )
    }
    contextual_classes = {
        normalize_candidate_class(name)
        for name in planner_context.candidate_classes
    }
    scores: list[IntentScore] = []

    for skill in skills:
        if skill.disable_model_invocation:
            continue

        explicit_skill_hits = (
            [skill.name]
            if contains_keyword(normalized, skill.name)
            else []
        )

        candidate_hits = matching_candidate_classes(
            normalized,
            skill.candidate_classes,
        )
        # A canonical candidate class and any of its unambiguous aliases are
        # equally explicit references.  Avoid counting the canonical form a
        # second time merely because it is also the skill name.
        if candidate_hits and normalize_candidate_class(skill.name) in candidate_hits:
            explicit_skill_hits = []
        contextual_candidate_hits = sorted(
            set(skill.candidate_classes) & contextual_classes
        )

        strong_hits = matching_keywords(
            normalized,
            skill.triggers.strong,
        )
        weak_hits = matching_keywords(
            normalized,
            skill.triggers.weak,
        )

        if candidate_hits:
            explicit_candidate_terms = {
                normalize(term)
                for candidate_class in candidate_hits
                for term in candidate_class_terms(candidate_class)
            }

            def duplicates_explicit_candidate(hit: str) -> bool:
                normalized_hit = normalize(hit)
                return any(
                    normalized_hit == term or normalized_hit in term.split()
                    for term in explicit_candidate_terms
                )

            strong_hits = [
                hit for hit in strong_hits if not duplicates_explicit_candidate(hit)
            ]
            weak_hits = [
                hit for hit in weak_hits if not duplicates_explicit_candidate(hit)
            ]

        generic_strong_hits = [
            hit
            for hit in strong_hits
            if normalize(hit) in GENERIC_TRIGGER_TERMS
        ]
        strong_hits = [
            hit
            for hit in strong_hits
            if normalize(hit) not in GENERIC_TRIGGER_TERMS
        ]
        weak_hits.extend(generic_strong_hits)

        stage_hits = (
            [skill.stage]
            if skill.stage is not None
            and contains_keyword(normalized, skill.stage)
            else []
        )

        primary_signal = bool(
            explicit_skill_hits
            or candidate_hits
            or contextual_candidate_hits
            or strong_hits
            or weak_hits
            or stage_hits
        )
        prerequisite_hits = (
            sorted(set(skill.requires) & completed_or_active_skills)
            if primary_signal
            else []
        )

        score = (
            (len(explicit_skill_hits) + len(candidate_hits))
            * EXPLICIT_SKILL_WEIGHT
            + len(contextual_candidate_hits) * CANDIDATE_CLASS_WEIGHT
            + len(strong_hits) * STRONG_KEYWORD_WEIGHT
            + len(weak_hits) * WEAK_KEYWORD_WEIGHT
            + len(prerequisite_hits) * PREREQUISITE_WEIGHT
            + len(stage_hits) * STAGE_WEIGHT
        )
        strong_count = (
            len(explicit_skill_hits)
            + len(candidate_hits)
            + len(contextual_candidate_hits)
            + len(strong_hits)
        )

        if score == 0:
            continue

        hits = (
            [f"skill:{hit}" for hit in explicit_skill_hits]
            + [f"candidate:{hit}" for hit in candidate_hits]
            + [f"context-candidate:{hit}" for hit in contextual_candidate_hits]
            + strong_hits
            + weak_hits
            + [f"stage:{hit}" for hit in stage_hits]
            + [f"requires:{hit}" for hit in prerequisite_hits]
        )
        scores.append(
            {
                "skill_name": skill.name,
                "score": score,
                "strong_count": strong_count,
                "explicit_count": len(explicit_skill_hits) + len(candidate_hits),
                "candidate_count": (
                    len(candidate_hits) + len(contextual_candidate_hits)
                ),
                "prerequisite_count": len(prerequisite_hits),
                "hits": sorted(set(hits)),
            },
        )

    return scores


def confidence_check(scores: List[IntentScore]) -> Optional[IntentScore]:
    candidates = [
        score
        for score in scores
        if score["strong_count"] > 0
        and score["score"] >= MIN_RECOMMEND_SCORE
    ]

    if not candidates:
        return None

    ordered = sorted(
        candidates,
        key=lambda item: (
            -item["score"],
            -item["strong_count"],
            -item["explicit_count"],
            -item["candidate_count"],
            -item["prerequisite_count"],
            item["skill_name"],
        ),
    )

    best = ordered[0]
    semantic_rank = (
        best["score"],
        best["strong_count"],
        best["explicit_count"],
        best["candidate_count"],
        best["prerequisite_count"],
    )
    tied = [
        candidate
        for candidate in ordered
        if (
            candidate["score"],
            candidate["strong_count"],
            candidate["explicit_count"],
            candidate["candidate_count"],
            candidate["prerequisite_count"],
        ) == semantic_rank
    ]

    if len(tied) > 1:
        return None

    return best


def matching_candidate_classes(
    normalized: str,
    candidate_classes: List[str],
) -> List[str]:
    hits: list[str] = []

    for candidate_class in candidate_classes:
        terms = candidate_class_terms(candidate_class)
        if any(contains_keyword(normalized, term) for term in terms):
            hits.append(candidate_class)

    return hits


def candidate_class_terms(candidate_class: str) -> set[str]:
    return {
        candidate_class,
        *(
            alias
            for alias, canonical in CANDIDATE_CLASS_ALIASES.items()
            if canonical == candidate_class
        ),
    }


def normalize_metadata_skill_name(name: str) -> str:
    return re.sub(r"[\s_]+", "-", name.strip().lower())


def matching_keywords(
    normalized: str,
    keywords: List[str],
) -> List[str]:
    return [
        keyword
        for keyword in keywords
        if contains_keyword(normalized, keyword)
    ]


def contains_keyword(normalized: str, keyword: str) -> bool:
    normalized_keyword = normalize(keyword)
    pattern = (
        r"(?<!\w)"
        + re.escape(normalized_keyword)
        + r"(?!\w)"
    )

    return re.search(pattern, normalized) is not None


def build_checklist(
    skill_name: Optional[str],
    target_known: bool,
    risk: str,
) -> List[str]:
    out = []

    if not target_known:
        out.append(
            "clarify the exact in-scope target before active testing"
        )

    if skill_name:
        out.append(
            f"load the {skill_name} skill before running other tools"
        )
    else:
        out.append(
            "choose the narrowest applicable workflow before acting"
        )

    out.append(
        "use coverage to avoid repeating endpoint/parameter/vulnerability tests"
    )

    out.append(
        "verify with reproducible evidence before confirming a finding"
    )

    if risk == "high":
        out.append(
            "ask before scanner-like, destructive, or high-volume actions"
        )

    return out


def render_guidance(
    skill_name: Optional[str],
    reason: str,
    risk: str,
    checklist: List[str],
    candidate: PlannerCandidate | None = None,
    candidates: tuple[PlannerCandidate, ...] = (),
) -> str:
    if skill_name:
        skill_line = (
            f"Recommended skill: {skill_name} ({reason})."
        )
    else:
        skill_line = (
            f"Recommended skill: none ({reason})."
        )

    lines = [
        "Decision planner guidance for this turn:",
        f"- {skill_line}",
        f"- Risk level: {risk}.",
        "- If the recommended skill is present and not already active, call load_skill before other tools.",
        "- If scope, authorization, credentials, or testing depth is ambiguous, ask one concise question before active testing.",
        "- Use coverage(action='untested') when endpoint/parameter candidates are known, then coverage(action='mark') after meaningful tests.",
        "- Call confirm_finding only for a workflow Candidate whose latest result is confirmed and whose registered evidence remains valid; observed_impact states what that evidence demonstrates and potential_impact keeps untested consequences conditional.",
        "- Checklist:",
    ]

    if candidate is not None:
        lines.insert(1, (
            f"- Candidate to consider: {candidate.id}, class={candidate.candidate_class}, "
            f"status={candidate.status}, priority={candidate.priority or 'unspecified'}, "
            f"endpoint={candidate.endpoint or 'unspecified'}, "
            f"latest={candidate.latest_outcome or 'none'}, "
            f"blocker={candidate.deferred_reason or 'none'}, "
            f"evidence_refs={candidate.evidence_count}, "
            f"coverage_sync={candidate.coverage_synced}. "
            "This is guidance, not dispatch."
        ))
        if skill_name is None:
            lines.insert(2, "- No enabled validator matches this candidate; keep it deferred or choose a justified manual path.")
    elif candidates:
        blocked = [item for item in candidates if item.status == "deferred"]
        if blocked:
            reasons = "; ".join(
                f"{item.id}: {item.latest_outcome or 'deferred'}"
                f" ({item.deferred_reason or 'condition not recorded'})"
                for item in sorted(blocked, key=lambda item: item.id)[:3]
            )
            lines.insert(1, f"- No actionable candidate; revisit only if a blocker changes: {reasons}.")
        else:
            lines.insert(1, "- No actionable candidate; gather a targeted endpoint/input inventory or stop if scope is complete.")
    else:
        lines.insert(1, "- No structured candidate is available; use a concrete direct request or gather a targeted inventory.")

    lines.extend(
        f"  - {item}"
        for item in checklist
    )

    return "\n".join(lines)


def normalize(s: str) -> str:
    return re.sub(
        r"\s+",
        " ",
        s.lower().replace("_", " ").replace("-", " "),
    ).strip()


def includes_any(s: str, needles: List[str]) -> bool:
    return any(
        needle in s
        for needle in needles
    )


def has_host_like_text(s: str) -> bool:
    if re.search(r"https?://[^\s]+", s, re.I):
        return True

    for match in _HOST_TOKEN_RE.finditer(s):
        candidate = match.group(0)

        try:
            return ipaddress.ip_address(candidate).version == 4
        except ValueError:
            pass

        labels = candidate.split(".")

        if (
            labels[-1].lower() in _FILE_SUFFIXES
            or all(label.isdecimal() for label in labels)
        ):
            continue

        if all(_HOST_LABEL_RE.fullmatch(label) for label in labels):
            return True

    return False
