from dataclasses import replace

import pytest

from src.agent.reasoning_benchmark import build_run, load_request_metrics, same_reasoning_configuration
from src.llm.metrics import MetricsCollector, RequestMetrics, TokenUsage


def _row(request_id="one", usage=None, purpose="agent_turn"):
    return RequestMetrics(
        request_id=request_id, started_at="2026-01-01T00:00:00+00:00",
        duration_ms=25.0, provider="deepseek", model="deepseek-flash",
        purpose=purpose, policy_id="reasoning-baseline-v1",
        requested_reasoning_level="low", effective_reasoning_level="low",
        status="success", usage=usage, tool_call_count=1, retry_count=0,
    )


def test_export_and_aggregation_preserve_unknown_usage(tmp_path):
    collector = MetricsCollector(max_records=2)
    collector.add(_row("old"))
    collector.add(_row("one", TokenUsage(100, 20, 30, 10, 130, True)))
    collector.add(_row("two"))
    path = tmp_path / "metrics.jsonl"
    collector.export_jsonl(path)
    assert path.stat().st_mode & 0o777 == 0o600
    rows = load_request_metrics(path)
    assert [row.request_id for row in rows] == ["one", "two"]
    run = build_run(rows, run_id="run-1", scenario_id="case-1",
                    target_ref="lab-1", scope_ref="scope-1")
    assert run.request_count == 2 and run.tool_call_count == 2
    assert run.total_tokens.value == 130 and run.total_tokens.missing_requests == 1
    assert run.reasoning_tokens.value == 10
    assert run.output_tokens.value == 30  # reasoning is already included
    assert same_reasoning_configuration(run, replace(run, policy_id="legacy"))
    with pytest.raises(ValueError):
        build_run(rows, run_id="run-1", scenario_id="case-1",
                  target_ref="https://lab.example/?token=secret", scope_ref="scope-1")


def test_unknown_effective_level_survives_export_and_benchmark(tmp_path):
    collector = MetricsCollector()
    collector.add(replace(_row(), requested_reasoning_level="off", effective_reasoning_level=None))
    path = tmp_path / "unknown.jsonl"
    collector.export_jsonl(path)
    rows = load_request_metrics(path)
    run = build_run(rows, run_id="run-1", scenario_id="case-1",
                    target_ref="lab-1", scope_ref="scope-1")
    assert run.policy_id == "reasoning-baseline-v1"
    assert run.reasoning_configuration == (("agent_turn", "off", None),)
