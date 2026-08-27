from dataclasses import dataclass
import re
from typing import List, Optional, TypedDict

from src.skills.registry import Skill
from src.target.target import Target


@dataclass
class DecisionPlan:
    recommended_skill: Optional[str]
    reason: str
    risk: str
    checklist: List[str]
    guidance: str


class SkillRecommendation(TypedDict):
    name: str
    reason: str


class IntentScore(TypedDict):
    skill_name: str
    score: int
    strong_count: int
    hits: List[str]


STRONG_KEYWORD_WEIGHT = 5
WEAK_KEYWORD_WEIGHT = 1
MIN_RECOMMEND_SCORE = 5

# NOTE: only intents for currently-active, fully rolled-out skills belong
# here. When a new vulnerability-specific skill (finding-validation, ...)
# completes its full rollout checklist, add its intent + keywords here at
# that point. Do not pre-register intents for skills that haven't finished
# rollout — an unmapped INTENT_TO_SKILL entry is silently dropped by
# detect_intent() via the available_skill_names check, which would hide
# the fact that the mapping is stale rather than surfacing it.
#
# recon, web-enumeration, web-input-analysis, sql-injection,
# cross-site-scripting, access-control, authentication, ssrf, csrf, and
# ssti have completed their rollout checklists and are registered below.
#
# ssrf is registered as validation-only: its keywords route to the
# confirm/characterize workflow in skills/ssrf/SKILL.md, which stops at
# SSRF-1..4 and hands off deeper impact work to a separate, not-yet-
# registered ssrf-impact skill. Do not broaden these keywords to also
# imply impact/exploitation intent without registering that skill too.
#
# csrf is likewise validation-only: it stops at CSRF-1..3 (candidate ->
# suspected -> confirmed) and hands off account-takeover/destructive
# follow-up to a separate, not-yet-registered workflow. Its keywords
# should stay scoped to CSRF terminology — do not let generic terms like
# "token" or "session" bleed in, since those already belong to
# authentication and access_control.
#
# ssti is registered as a single, fully self-contained skill (unlike
# ssrf/csrf): skills/ssti/SKILL.md gates its own impact work internally —
# Phase 3 (command execution / sensitive-read probes) only runs after
# SSTI-2 is confirmed AND the user explicitly authorizes via ask_user.
# There is no separate ssti-impact skill to register later, so these
# keywords may route straight to detection+validation without needing a
# parallel "impact-only" split.
INTENT_TO_SKILL: dict[str, str] = {
    "recon": "recon",
    "web_enumeration": "web-enumeration",
    "web_input_analysis": "web-input-analysis",
    "sql_injection": "sql-injection",
    "cross_site_scripting": "cross-site-scripting",
    "access_control": "access-control",
    "authentication": "authentication",
    "ssrf": "ssrf",
    "csrf": "csrf",
    "ssti": "ssti",
}

INTENT_KEYWORDS: dict[str, dict[str, List[str]]] = {
    "recon": {
        "strong": [
            "recon",
            "reconnaissance",
            "subdomain",
            "subdomains",
            "crt",
            "certificate transparency",
            "liveness",
            "fingerprint",
            "fingerprinting",
            "apex",
            "new target",
        ],
        "weak": [
            "attack surface",
            "technology stack",
            "reachable",
        ],
    },
    "web_enumeration": {
        "strong": [
            "endpoint",
            "endpoints",
            "route",
            "routes",
            "map attack surface",
            "enumerate web application",
            "web enumeration",
            "content discovery",
            "directory discovery",
            "api entry point",
            "api entry points",
            "swagger",
            "openapi",
        ],
        "weak": [
            "parameter",
            "parameters",
            "form",
            "forms",
            "graphql endpoint",
            "inventory",
            "static resources",
            "javascript resources",
        ],
    },
    "web_input_analysis": {
        "strong": [
            "candidate",
            "candidates",
            "input analysis",
            "web input analysis",
            "triage input",
            "triage endpoint",
            "suspected vulnerability class",
            "prioritize testing",
        ],
        "weak": [
            "context",
            "signal",
            "reflected",
            "object identifier",
            "which parameter",
            "which endpoint",
        ],
    },
    "sql_injection": {
        "strong": [
            "sql injection",
            "sqli",
            "union select",
            "boolean based",
            "time based",
            "error based",
            "database error",
        ],
        "weak": [
            "database",
            "injection",
            "syntax sensitive",
        ],
    },
    "cross_site_scripting": {
        "strong": [
            "xss",
            "cross site scripting",
            "script injection",
            "reflected xss",
            "stored xss",
            "dom xss",
            "dom based xss",
            "html injection",
        ],
        "weak": [
            "script tag",
            "innerhtml",
            "document.write",
            "postmessage",
            "sanitize input",
            "escape output",
            "content security policy",
        ],
    },
    "access_control": {
        "strong": [
            "access control",
            "idor",
            "bola",
            "horizontal privilege escalation",
            "vertical privilege escalation",
            "missing authorization",
            "authorization bypass",
            "function level authorization",
        ],
        "weak": [
            "object identifier",
            "object ownership",
            "owner vs non-owner",
            "admin endpoint",
            "authorization check",
            "unauthorized access",
            "cross-user access",
        ],
    },
    "authentication": {
        "strong": [
            "session fixation",
            "session invalidation",
            "login bypass",
            "login flow bypass",
            "mfa bypass",
            "2fa bypass",
            "otp bypass",
            "password reset flow",
            "password reset bypass",
            "reset token",
            "logout invalidation",
            "user enumeration",
            "account enumeration",
        ],
        "weak": [
            "login flow",
            "logout",
            "session cookie",
            "mfa",
            "2fa",
            "otp",
            "password reset",
            "forgot password",
            "remember me",
            "session token",
            "account lockout",
            "rate limiting login",
        ],
    },
    "ssrf": {
        "strong": [
            "ssrf",
            "server-side request forgery",
            "server side request forgery",
        ],
        "weak": [
            "url fetch",
            "webhook",
            "callback url",
            "image url",
            "remote url",
            "redirect url",
        ],
    },
    "csrf": {
        "strong": [
            "csrf",
            "cross-site request forgery",
            "cross site request forgery",
        ],
        "weak": [
            "csrf token",
            "anti-csrf",
            "state-changing request",
            "samesite",
            "double-submit cookie",
            "forged request",
        ],
    },
    "ssti": {
        "strong": [
            "ssti",
            "server-side template injection",
            "server side template injection",
            "template injection",
            "template engine injection",
        ],
        "weak": [
            "jinja2",
            "twig template",
            "velocity template",
            "freemarker",
            "smarty template",
            "erb template",
            "template engine",
            "template expression",
            "expression evaluation",
            "sandbox escape",
        ],
    },
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


def build_decision_plan(
    user_msg: str,
    skills: List[Skill],
    target: Target,
) -> Optional[DecisionPlan]:
    text = user_msg.strip()

    if not text:
        return None

    normalized = normalize(text)

    recommended = recommend_skill(normalized, skills)

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
        ),
    )


def recommend_skill(
    normalized: str,
    skills: List[Skill],
) -> Optional[SkillRecommendation]:
    available_skill_names = {
        skill.name
        for skill in skills
    }
    scores = detect_intent(normalized, available_skill_names)
    best = confidence_check(scores)

    if best is None:
        return None

    top_hits = ", ".join(best["hits"][:4])

    return {
        "name": best["skill_name"],
        "reason": f"matched {best['skill_name']} signals: {top_hits}",
    }


def detect_intent(
    normalized: str,
    available_skill_names: set[str],
) -> List[IntentScore]:
    by_skill: dict[str, IntentScore] = {}

    for intent_name, keyword_groups in INTENT_KEYWORDS.items():
        skill_name = INTENT_TO_SKILL.get(intent_name)

        if skill_name not in available_skill_names:
            continue

        strong_hits = matching_keywords(
            normalized,
            keyword_groups["strong"],
        )
        weak_hits = matching_keywords(
            normalized,
            keyword_groups["weak"],
        )

        if not strong_hits and not weak_hits:
            continue

        skill_score = by_skill.setdefault(
            skill_name,
            {
                "skill_name": skill_name,
                "score": 0,
                "strong_count": 0,
                "hits": [],
            },
        )
        skill_score["score"] += (
            len(strong_hits) * STRONG_KEYWORD_WEIGHT
            + len(weak_hits) * WEAK_KEYWORD_WEIGHT
        )
        skill_score["strong_count"] += len(strong_hits)
        skill_score["hits"].extend(strong_hits + weak_hits)

    return [
        {
            **score,
            "hits": sorted(set(score["hits"])),
        }
        for score in by_skill.values()
    ]


def confidence_check(scores: List[IntentScore]) -> Optional[IntentScore]:
    candidates = [
        score
        for score in scores
        if score["strong_count"] > 0
        and score["score"] >= MIN_RECOMMEND_SCORE
    ]

    if not candidates:
        return None

    return sorted(
        candidates,
        key=lambda item: (
            -item["score"],
            -item["strong_count"],
            item["skill_name"],
        ),
    )[0]


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
        "- Do not call confirm_finding for suspected behavior; require reproduced request/response evidence first.",
        "- Checklist:",
    ]

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

    if re.search(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b", s, re.I):
        return True

    return False