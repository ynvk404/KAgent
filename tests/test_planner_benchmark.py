from pathlib import Path

from src.agent.planner_benchmark import load_cases, run_benchmark
from src.skills.registry import Registry


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_offline_planner_benchmark_matches_expected_outcomes():
    registry = Registry()
    registry.load_dir(REPO_ROOT / "skills")
    cases = load_cases(REPO_ROOT / "benchmarks" / "planner_cases.json")

    metrics, failures = run_benchmark(cases, registry.list_enabled())

    assert 50 <= metrics.total <= 100
    assert failures == []
    assert metrics.correct == metrics.total
    assert metrics.incorrect == 0
    assert metrics.expected_ambiguity_matched >= 5
    assert metrics.expected_no_recommendation_matched >= 10
    assert metrics.exact_match_rate == 1.0
