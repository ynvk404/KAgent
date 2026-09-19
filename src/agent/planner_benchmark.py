from __future__ import annotations

import json
import sys
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from src.agent.decision_planner import (
    MIN_RECOMMEND_SCORE,
    PlannerContext,
    build_decision_plan,
    detect_intent,
    is_purely_informational,
    normalize,
)
from src.skills.registry import Registry, Skill
from src.target.target import Target

ExpectedOutcome = Literal["none", "ambiguity"] | str


@dataclass(frozen=True, slots=True)
class PlannerBenchmarkCase:
    prompt: str
    expected: ExpectedOutcome
    candidate_classes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannerBenchmarkMetrics:
    total: int
    correct: int
    incorrect: int
    expected_ambiguity_matched: int
    expected_no_recommendation_matched: int
    exact_match_rate: float


def observed_outcome(case: PlannerBenchmarkCase, skills: list[Skill]) -> str:
    context = PlannerContext(candidate_classes=frozenset(case.candidate_classes))
    plan = build_decision_plan(case.prompt, skills, Target(), context)
    if plan is not None and plan.recommended_skill is not None:
        return plan.recommended_skill

    normalized = normalize(case.prompt)
    if is_purely_informational(normalized):
        return "none"

    eligible = [
        score
        for score in detect_intent(normalized, skills, context)
        if score["strong_count"] > 0 and score["score"] >= MIN_RECOMMEND_SCORE
    ]
    if not eligible:
        return "none"

    rank = lambda item: (
        item["score"],
        item["strong_count"],
        item["explicit_count"],
        item["candidate_count"],
        item["prerequisite_count"],
    )
    best_rank = max(rank(item) for item in eligible)
    return "ambiguity" if sum(rank(item) == best_rank for item in eligible) > 1 else "none"


def run_benchmark(
    cases: list[PlannerBenchmarkCase],
    skills: list[Skill],
) -> tuple[PlannerBenchmarkMetrics, list[dict[str, str]]]:
    failures: list[dict[str, str]] = []
    ambiguity_matched = 0
    none_matched = 0
    for case in cases:
        observed = observed_outcome(case, skills)
        if observed == case.expected:
            if case.expected == "ambiguity":
                ambiguity_matched += 1
            elif case.expected == "none":
                none_matched += 1
        else:
            failures.append(
                {"prompt": case.prompt, "expected": case.expected, "observed": observed}
            )

    correct = len(cases) - len(failures)
    metrics = PlannerBenchmarkMetrics(
        total=len(cases),
        correct=correct,
        incorrect=len(failures),
        expected_ambiguity_matched=ambiguity_matched,
        expected_no_recommendation_matched=none_matched,
        exact_match_rate=(correct / len(cases) if cases else 0.0),
    )
    return metrics, failures


def load_cases(path: str | Path) -> list[PlannerBenchmarkCase]:
    raw: Any = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("planner benchmark must be a JSON list")
    cases: list[PlannerBenchmarkCase] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("planner benchmark entries must be objects")
        prompt = item.get("prompt")
        expected = item.get("expected")
        candidate_classes = item.get("candidate_classes", [])
        if (
            not isinstance(prompt, str)
            or not isinstance(expected, str)
            or not isinstance(candidate_classes, list)
            or not all(isinstance(value, str) for value in candidate_classes)
        ):
            raise ValueError("invalid planner benchmark entry")
        cases.append(PlannerBenchmarkCase(prompt, expected, tuple(candidate_classes)))
    return cases


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    cases_path = Path(args[0]) if args else Path("benchmarks/planner_cases.json")
    skills_path = Path(args[1]) if len(args) > 1 else Path("skills")
    registry = Registry()
    registry.load_dir(skills_path)
    metrics, failures = run_benchmark(load_cases(cases_path), registry.list_enabled())
    print(json.dumps({"metrics": asdict(metrics), "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
