"""
decision.py
Port từ decision.ts sang Python
"""

from dataclasses import dataclass
import re
from typing import List, Optional, TypedDict

from ..skills.registry import Skill
from ..target.target import Target

# ==========================
# Decision Plan
# ==========================

@dataclass
class DecisionPlan:
    recommended_skill: Optional[str]
    reason: str
    risk: str               # "normal" | "high"
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


# ==========================
# Intent mapping
# ==========================

STRONG_KEYWORD_WEIGHT = 5
WEAK_KEYWORD_WEIGHT = 1
MIN_RECOMMEND_SCORE = 5

INTENT_TO_SKILL: dict[str, str] = {
    "recon": "recon",
    "graphql": "graphql",
    "ssrf": "ssrf",
    "injection": "webvuln",
    "web_testing": "webvuln",
    "authentication": "jwt",
    "ssti": "ssti",
    "race": "race",
    "takeover": "takeover",
    "supabase": "supabase",
    "deserialize": "deserialize",
}

INTENT_KEYWORDS: dict[str, dict[str, List[str]]] = {
    "recon": {
        "strong": [
            "recon",
            "subdomain",
            "subdomains",
            "enumerate",
            "enumeration",
            "attack surface",
            "crt",
            "liveness",
            "fingerprint",
            "fingerprinting",
            "content discovery",
            "apex",
        ],
        "weak": [],
    },
    "graphql": {
        "strong": [
            "graphql",
            "gql",
            "introspection",
            "mutation",
            "schema",
        ],
        "weak": [
            "resolver",
        ],
    },
    "ssrf": {
        "strong": [
            "ssrf",
            "webhook",
            "callback",
            "metadata",
            "169.254.169.254",
            "imds",
        ],
        "weak": [
            "internal service",
            "cloud metadata",
        ],
    },
    "injection": {
        "strong": [
            "xss",
            "sqli",
            "sql injection",
            "injection",
            "csrf",
        ],
        "weak": [
            "parameter",
            "payload",
        ],
    },
    "web_testing": {
        "strong": [
            "idor",
            "bola",
            "bac",
            "cve",
        ],
        "weak": [
            "web",
            "vuln",
            "vulnerability",
            "authorization",
        ],
    },
    "authentication": {
        "strong": [
            "jwt",
            "token",
            "bearer",
            "jwks",
            "jku",
            "hs256",
            "rs256",
        ],
        "weak": [
            "alg",
            "kid",
        ],
    },
    "ssti": {
        "strong": [
            "ssti",
            "jinja",
            "twig",
            "freemarker",
            "velocity",
            "handlebars",
        ],
        "weak": [
            "template",
        ],
    },
    "race": {
        "strong": [
            "race",
            "concurrent",
            "parallel",
            "double spend",
        ],
        "weak": [
            "coupon",
            "redeem",
            "balance",
        ],
    },
    "takeover": {
        "strong": [
            "takeover",
            "dangling",
            "cname",
            "nxdomain",
            "subdomain takeover",
        ],
        "weak": [],
    },
    "supabase": {
        "strong": [
            "supabase",
            "rls",
            "anon key",
            "postgrest",
            "storage bucket",
        ],
        "weak": [],
    },
    "deserialize": {
        "strong": [
            "deserialize",
            "deserialization",
            "pickle",
            "unserialize",
            "binaryformatter",
        ],
        "weak": [
            "yaml",
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


# ==========================================================
# Hàm chính
# ==========================================================

def build_decision_plan(
    user_msg: str,
    skills: List[Skill],
    target: Target,
) -> Optional[DecisionPlan]:
    """
    Sinh DecisionPlan từ câu hỏi người dùng.
    """

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


# ==========================================================
# Skill recommendation
# ==========================================================

def recommend_skill(
    normalized: str,
    skills: List[Skill],
) -> Optional[SkillRecommendation]:
    """
    Recommend an available skill from curated intent keywords only.
    """

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
    """
    Score curated intent keywords and aggregate by routable skill.
    """

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


# ==========================================================
# Checklist
# ==========================================================

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


# ==========================================================
# Guidance
# ==========================================================

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


# ==========================================================
# Helpers
# ==========================================================

def normalize(s: str) -> str:
    """
    Chuẩn hóa chuỗi.
    """

    return (
        s.lower()
        .replace("_", " ")
        .replace("-", " ")
    )


def includes_any(s: str, needles: List[str]) -> bool:
    """
    Kiểm tra chuỗi có chứa bất kỳ keyword nào.
    """

    return any(
        needle in s
        for needle in needles
    )


def has_host_like_text(s: str) -> bool:
    """
    Kiểm tra chuỗi có chứa URL hoặc domain.
    """

    if re.search(r"https?://[^\s]+", s, re.I):
        return True

    if re.search(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b", s, re.I):
        return True

    return False
