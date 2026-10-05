# Verified token accounting implementation

Implemented against `4f7417e` on `main`, with committed Phase A (`4c4bb63`)
and Phase B (`4f7417e`). The supplied independent verification report remains
unchanged as historical evidence. Its characterization tests and the original
audit tests now assert the corrected behavior.

## Behavior

- `src/agent/context_estimate.py` provides a deterministic breakdown of system,
  represented history, expanded pending input, injected observations, actual
  request schemas, eligible private replay, and framing. Nonempty components
  round up. UTF-8 byte costs reserve more for Unicode; message/call framing
  reserves four tokens. These are documented heuristic allowances, not exact
  tokenizer counts. Opaque signatures receive a character-length reservation
  without decoding or logging their contents.
- Turn preparation expands file input once, snapshots recall/intelligence,
  catalog/workflow/continuation context and actual schemas, and emits recall
  and planner events once. Pure projections reuse those inputs. Raw user input
  stays in persisted history; expanded input is used only in the working
  request. Memory observations are rendered anew after accepted compaction.
- Compaction acceptance compares equivalent projected requests, including old
  versus new memory observations, and requires savings of at least 64 tokens
  and 10% of the old projected request. History-only statistics remain separate.
  Ineffective summaries and failed summary responses preserve active state.
- Every turn, malformed retry, final synthesis, synthesis retry and compaction
  dispatch checks its assembled request. Tools-free requests pay zero schema
  cost. Late guidance is included before measurement and reduction. Agent-loop
  tool retention waits for that assembled request; standalone tool APIs retain
  their admission boundary. Newly published references are saved before turn
  dispatch. Phase A reductions pay the UTF-8 cost of their own rendered markers
  with at most two bounded corrections.
- The existing minimum-history ratio, three-failure compaction breaker, Groq
  5500 soft policy (including zero/explicit settings), and Kimi default-derived
  versus explicit threshold semantics are retained. A fixed-floor/soft-trigger
  mismatch is reported, without claiming model overflow.
- `src/llm/runtime/context_budget.py` derives optional hard input admission from
  the existing Kimi context metadata, reserves configured generation output
  (2048 for an unset direct Kimi adapter), and reserves 5%/minimum 128 tokens for
  heuristic uncertainty. A compatible adapter may receive an explicit
  input-only `gen_opts["input_token_limit"]`; output is not subtracted twice.
  This override is bound to the runtime client, with no new saved configuration
  field, CLI setting, session migration or provider transaction. Budget lookup
  follows the active client, so supported switches and rollback recompute it.
  Unknown identities/models retain compatibility. Known overflow emits
  `context_capacity` without calling the provider or entering its retry loop.
- Gemini accounting uses the real message encoder, including ordered replay
  replacement, signed-part filtering and model provenance. DeepSeek/Kimi
  estimation and encoding share `reasoning_replay_eligible`. DeepSeek currently
  replays eligible reasoning even when thinking is disabled; the implementation
  deliberately preserves this existing encoder rule instead of assuming a
  different request-mode rule.
- Anthropic usage is parsed by the real response path. Effective input equals
  uncached input plus cache reads plus cache creation. Cache creation is appended
  to `TokenUsage` to preserve existing positional constructors and is exported
  by existing JSONL serialization. Lifetime cache-creation breakdowns are not
  added twice; missing/malformed supplied values remain unknown. No reasoning
  counts or streaming implementation are invented. Usage stays telemetry only.
  Semantics were checked against [Anthropic's prompt-caching documentation](https://platform.claude.com/docs/en/build-with-claude/prompt-caching).
- Schema-cache hardening uses a content digest, which detects arbitrary
  in-place description/schema edits. Registry permission gates are untouched.
  Idle UI estimates include carried observations/catalog/workflow and default
  schemas, and label threshold pressure as `soft`. The stale transcript-length
  cache was removed; idle estimation performs no recall/intelligence searches.

## Scope and limitations

No structured handoff, auto-continue, provider catalog redesign, tokenizer,
package installation, inference call, live-target benchmark, permission change,
artifact reader/security change, or session/config format migration was added.

Heuristics and safety reservations cannot guarantee provider fit. Hard metadata
is intentionally limited to the existing Kimi map; other providers/models are
unknown unless an adapter supplies an explicit input limit. The explicit
compatible-adapter override is programmatic, not a new persisted UI/CLI option.
The existing bounded compaction input is independently admitted and can be
rejected on a sufficiently small budget. No authoritative request content is
arbitrarily truncated to force admission. Search results are fixed within a
preparation attempt rather than searched again with the new summary as a query.

The existing post-acceptance learn/save/snapshot lifecycle remains unchanged;
this task does not add a new rollback transaction for late session persistence
failures. Rejections and failed summary requests occur before publishing the
candidate history and memory.

## Verification

All commands used the existing `venv-linux`; no packages were installed.

The pre-change audit baseline passed 17 tests. During implementation, obsolete
character-count assertions were replaced with pressure/floor/preservation
boundaries, the audit tool fixture gained its required protocol methods, and UI
mocks gained the new estimate API. No unrelated baseline failures were found.

The first full run had 4010 passed, 10 failed and 1 skipped: nine UI fixtures
omitted the new estimate method, and the new malformed-retry fixture used a
single markup example that correctly did not trigger the existing multi-tag
detector. The corrected fixtures passed their focused reruns; no test was
excluded, skipped or marked xfail to conceal a regression.

Final regression bundle: **416 passed** (`52.87s`):

```bash
venv-linux/bin/pytest -q \
  tests/agent/test_context_estimate.py \
  tests/agent/test_token_accounting_audit.py \
  tests/agent/test_token_accounting_independent_verify.py \
  tests/agent/test_agent.py \
  tests/agent/test_output_pipeline.py \
  tests/agent/test_tool_result_offloading.py \
  tests/agent/test_phase_b_audit_regressions.py \
  tests/state/test_phase_b_store_audit_regressions.py \
  tests/agent/test_resume_after_compaction.py \
  tests/agent/test_post_compaction.py
```

Provider/runtime/UI responsibility run: **391 passed** (`43.73s`):

```bash
venv-linux/bin/pytest -q \
  tests/agent/test_post_compaction.py \
  tests/agent/test_resume_after_compaction.py \
  tests/agent/test_tool_result_offloading.py \
  tests/agent/test_phase_b_audit_regressions.py \
  tests/state/test_phase_b_store_audit_regressions.py \
  tests/agent/test_reasoning_policy.py \
  tests/agent/test_reasoning_benchmark.py \
  tests/llm/test_reasoning_continuity.py \
  tests/llm/test_reasoning.py tests/llm/test_models.py tests/llm/test_metrics.py \
  tests/llm/test_anthropic.py tests/llm/test_gemini.py \
  tests/integration/test_tool_schema_budget.py \
  tests/runtime/test_provider_runtime.py \
  tests/ui/test_provider_picker.py tests/ui/test_model_picker.py \
  tests/ui/test_custom_provider_ui.py tests/ui/test_config_provider_adapter.py \
  tests/ui/test_status_bar.py tests/ui/test_app.py
```

Final UI run: **133 passed** (`24.92s`):

```bash
venv-linux/bin/pytest -q tests/ui/test_overview.py tests/ui/test_startup_splash.py \
  tests/ui/test_app.py tests/ui/test_status_bar.py
```

Final `venv-linux/bin/pyright`: **0 errors, 0 warnings, 0 informations**. The
checker printed an informational newer-version notice; it was not installed.

Final `venv-linux/bin/pytest -q`: **4021 passed, 1 skipped, 2 warnings**
(`359.52s`). The two warnings come from the existing malformed-custom-config
sanitization test (invalid key ID ignored and invalid active ID cleared).
Existing skip semantics and configured collection exclusions were retained.

Final `git diff --check`: **passed**. The complete diff and `git status --short`
were reviewed. Only the 20 deliverable files below are included in the task
commit; no permission, reader security, provider replay protocol, session-format,
or unrelated configuration transaction change was introduced.

## Deliverable files

Production:

- `src/agent/agent.py`
- `src/agent/context_estimate.py` (new)
- `src/agent/tool_results.py`
- `src/llm/providers/anthropic.py`
- `src/llm/providers/openai.py`
- `src/llm/runtime/context_budget.py` (new)
- `src/llm/runtime/metrics.py`
- `src/ui/core/app.py`
- `src/ui/widgets/status_bar.py`

Regression tests and related fixtures:

- `tests/agent/test_agent.py`
- `tests/agent/test_context_estimate.py` (new, 40 parameterized cases)
- `tests/agent/test_output_pipeline.py`
- `tests/agent/test_token_accounting_audit.py`
- `tests/agent/test_token_accounting_independent_verify.py` (supplied audit,
  converted to behavioral regressions)
- `tests/ui/test_app.py`
- `tests/ui/test_overview.py` (mock API only)
- `tests/ui/test_startup_splash.py` (mock API only)
- `tests/ui/test_status_bar.py`

Documentation:

- `docs/token-accounting-implementation.md` (this report)
- `docs/token-accounting-independent-verification.md` (supplied historical audit,
  preserved unchanged)
