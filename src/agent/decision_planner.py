"""
decision.py
Port từ decision.ts sang Python
"""

from dataclasses import dataclass
from typing import List, Optional

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


# ==========================
# Keyword mapping
# ==========================

SKILL_KEYWORDS = {
    "recon": [
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
        "domain",
    ],
    "webvuln": [
        "web",
        "vuln",
        "vulnerability",
        "hunt",
        "idor",
        "bola",
        "bac",
        "xss",
        "sqli",
        "injection",
        "auth",
        "authorization",
        "ssrf",
        "cve",
        "api",
        "endpoint",
    ],
    "jwt": [
        "jwt",
        "token",
        "bearer",
        "alg",
        "kid",
        "jku",
        "jwks",
        "hs256",
        "rs256",
    ],
    "ssrf": [
        "ssrf",
        "webhook",
        "callback",
        "url",
        "metadata",
        "169.254.169.254",
        "imds",
    ],
    "ssti": [
        "ssti",
        "template",
        "jinja",
        "twig",
        "freemarker",
        "velocity",
        "handlebars",
    ],
    "graphql": [
        "graphql",
        "gql",
        "introspection",
        "query",
        "mutation",
        "alias",
        "schema",
    ],
    "race": [
        "race",
        "concurrent",
        "parallel",
        "coupon",
        "redeem",
        "balance",
        "double spend",
    ],
    "takeover": [
        "takeover",
        "dangling",
        "cname",
        "nxdomain",
        "subdomain takeover",
    ],
    "supabase": [
        "supabase",
        "rls",
        "anon key",
        "postgrest",
        "storage bucket",
    ],
    "deserialize": [
        "deserialize",
        "deserialization",
        "pickle",
        "unserialize",
        "binaryformatter",
        "yaml",
    ],
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
        reason = (
            "no specialized skill matched strongly; "
            "use the general web testing workflow "
            "and ask only for missing scope or credentials"
        )

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

def recommend_skill(normalized: str, skills: List[Skill]):
    """
    Chọn skill có số keyword khớp nhiều nhất.
    """

    best = None

    for skill in skills:

        hits = score_skill(normalized, skill)
        score = len(hits)

        if score == 0:
            continue

        if best is None or score > best["score"]:
            best = {
                "skill": skill,
                "score": score,
                "hits": hits,
            }

    if best is None:
        return None

    top_hits = ", ".join(best["hits"][:4])

    return {
        "name": best["skill"].name,
        "reason": f"matched {best['skill'].name} signals: {top_hits}",
    }


def score_skill(normalized: str, skill: Skill) -> List[str]:
    """
    Đếm số keyword khớp của skill.
    """

    hits = set()

    keywords = SKILL_KEYWORDS.get(skill.name, []) + [skill.name]

    for keyword in keywords:
        if normalize(keyword) in normalized:
            hits.add(keyword)

    desc_tokens = [
        t
        for t in normalize(skill.description).split()
        if len(t) >= 5
    ]

    for token in desc_tokens:
        if token in normalized:
            hits.add(token)

    return list(hits)


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

    import re

    if re.search(r"https?://[^\s]+", s, re.I):
        return True

    if re.search(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b", s, re.I):
        return True

    return False