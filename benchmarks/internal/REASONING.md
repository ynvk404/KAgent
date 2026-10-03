# Reasoning-policy measurements

Production policy `reasoning-baseline-v1` requests OFF when `/thinking` is off,
LOW when it is on, and OFF for manual or automatic compaction. It does not
automatically select MEDIUM or HIGH. The effective level is recorded only when
the provider/model capability mapping is known; otherwise it is `null`.
Compaction can therefore request OFF while the model uses a known LOW fallback
or an unknown level.

KAgent keeps a bounded in-memory record for each LLM request at
`agent.request_metrics.records`. An experiment harness can explicitly export
metadata-only JSONL with:

```python
agent.request_metrics.export_jsonl(".kagent/reasoning-run-01.jsonl")
```

The export is created with mode `0600` and fails if the destination already
exists. It contains no prompts, responses, tool traffic, reasoning text, or
Gemini signatures. Treat provider/model names and timestamps as experiment
metadata and choose a private destination.

To summarize a run:

```bash
python -m src.agent.reasoning_benchmark .kagent/reasoning-run-01.jsonl \
  --run-id run-01 --scenario-id case-01 --target-ref lab-01 --scope-ref scope-01
```

Add `--compare-metrics-jsonl <second-file>` to summarize a second run of the
same scenario and flag when their observed reasoning configurations are
equivalent. Reference fields accept opaque IDs only; do not pass URLs or
credentials.

Usage values come from provider responses. Missing values remain unknown and
are counted separately. OpenAI/DeepSeek completion tokens include reasoning
tokens, whereas Gemini reports candidate and thought tokens separately; do
not sum the fields into a bill. Request duration includes retries and waits.
Compact total duration includes local processing and persistence; compact LLM
duration is its individual request duration. Failed attempts can have
unobserved provider usage. No pricing or model-quality outcome is inferred.

Compare detection quality only with a fixed authorized lab scenario, identical
target/scope, versioned policy, and ground-truth labels. Historical behavior
requires historical measurements; current settings that produce identical
requests are not distinct experimental profiles.
