from src.llm.metrics import MetricsCollector, RequestMetrics, gemini_usage, openai_chat_usage


def test_provider_usage_shapes_keep_reasoning_and_cache_as_subsets():
    openai = openai_chat_usage({
        "prompt_tokens": 100, "completion_tokens": 30, "total_tokens": 130,
        "prompt_tokens_details": {"cached_tokens": 20},
        "completion_tokens_details": {"reasoning_tokens": 10},
    })
    assert openai is not None
    assert (openai.input_tokens, openai.cached_input_tokens, openai.output_tokens,
            openai.reasoning_tokens, openai.total_tokens) == (100, 20, 30, 10, 130)
    assert openai.output_includes_reasoning is True
    gemini = gemini_usage({
        "promptTokenCount": 100, "candidatesTokenCount": 20,
        "thoughtsTokenCount": 10, "totalTokenCount": 130,
    })
    assert gemini is not None and gemini.output_includes_reasoning is False
    assert gemini.reasoning_tokens == 10 and gemini.output_tokens == 20
    assert openai_chat_usage(None) is None
    empty_gemini = gemini_usage({})
    assert empty_gemini is not None and empty_gemini.reasoning_tokens is None


def test_skipped_compaction_does_not_attach_time_to_previous_request():
    collector = MetricsCollector()
    previous = RequestMetrics(
        request_id="earlier", started_at="2026-01-01T00:00:00+00:00",
        duration_ms=10.0, provider="fake", model="fake", purpose="compaction",
        policy_id="reasoning-baseline-v1", requested_reasoning_level="off",
        effective_reasoning_level=None, status="success",
    )
    collector.add(previous)
    collector.set_latest_compaction_total(20.0, after_request_id="earlier")
    assert collector.records[0].compact_total_duration_ms is None

    collector.add(RequestMetrics(
        request_id="current", started_at="2026-01-01T00:01:00+00:00",
        duration_ms=11.0, provider="fake", model="fake", purpose="compaction",
        policy_id="reasoning-baseline-v1", requested_reasoning_level="off",
        effective_reasoning_level=None, status="success",
    ))
    collector.set_latest_compaction_total(25.0, after_request_id="earlier")
    assert collector.records[0].compact_total_duration_ms is None
    assert collector.records[1].compact_total_duration_ms == 25.0
