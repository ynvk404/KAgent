# TUI presentation audit

The change is limited to three production files. Ordinary structured progress
already avoids raw receipts, tracking IDs and temporary/state paths. The concrete
defects were a redundant planner suffix and an existing ID replacement in errors
that obscured repair references. Summary prompts also lacked targeted presentation
guidance. No ID/path filter was added.

## Rendering paths and provenance

| Content | Producer and rendering path | Presentation decision |
| --- | --- | --- |
| Runtime events | `src/agent/events.py`; `KAgent.run_agent_turn.handle_event` in `src/ui/core/app.py` logs the original event before dispatch. `runtime_facts` in `src/ui/core/outcomes.py` projects workflow records into immutable `OutcomeFacts`. `src/ui/core/state.py` builds transcript/status entries. `src/ui/widgets/transcript.py` renders them through the existing Rich/Textual writer. | Use structured candidate labels; omit the planner ID suffix unless displayed labels collide. Correlation and deduplication still use original IDs. |
| Tool calls/results | Agent dispatch emits `ToolCallEvent` / `ToolResultEvent`. `call_metadata`, `http_activity`, and `result_issues` in `src/ui/core/admission.py` produce TUI context/issues; the reducer aggregates activity and milestones instead of dumping results. | Keep HTTP method/path/status, warnings, failures and truncation limits. Remove the old unconditional ID replacement from issues so repair references remain exact. |
| Evidence and finding receipts | `runtime_facts` verifies workflow/result bindings; `_evidence_summary` counts usable sources; accepted finding receipts become `Finding saved` milestones with their report paths. | Retain source counts and actionable finding paths. Do not render raw observation/source/attempt IDs or stored payload paths as routine progress. This behavior already existed. |
| LLM streaming | `Agent.chat` uses the existing `ThinkingStreamFilter`, then emits `AssistantDeltaEvent` or buffers chunks for synthesis. `_emit_buffered_response_text` replays buffered chunks. The reducer keeps `stream_chunks`, finishes the assistant entry at a boundary, and the transcript renderer uses the existing sanitization/Markdown path. | No changes to streaming, buffering, thinking/secret/control safeguards, or model text. ID prefixes split across chunks remain intact. |
| Summaries | `_whole_target_synthesis` requests model text; `build_system_prompt` in `src/agent/system_prompt.py` supplies both prompt profiles. `_finish_outcome` in the UI reducer separately creates the runtime turn summary from structured facts. | Add one short narration guideline to both prompt profiles, including final synthesis. Preserve generated answers and all existing workflow/evidence context. Runtime outcome counters, blockers and incomplete states remain intact. |
| Runtime assistant text | `_direct_partial_summary`, closure/recovery messages, malformed-summary fallback and stop notices in `src/agent/agent.py` can also produce assistant text. Some response paths combine runtime warnings with model text. Restored recaps enter through `build_resume_summary` and `Append`. | These are not all model-generated. Their untyped text remains intact; no prefix-based inference or filtering. Partial summaries can therefore still show internal references. |
| Errors | `ErrorEvent` goes to `_present_issue`; tool errors use `result_issues`, grouping and recovery tracking. Done summaries retain unresolved issues and workflow stall/blocker reasons. | Keep sanitized debugging details, exact repair IDs and relevant internal paths. A failure never becomes a success because of this change. |
| Permission review | Registry/permission gates publish `BridgedPermissionRequest` through `src/ui/bridges/perm_bridge.py`; `PermissionModal` and the app overlay render the review and resolve its decision. | No changes to review contents, paths, callbacks, scope, cache or execution. |
| Headless and diagnostics | `src/cli/headless.py:run_headless.emit` serializes original events to `EventSink` JSONL and session debug. `src/logger/session_debug.py` retains its existing redaction/transient-context policy. `src/cli/runtime.py:emit` is a separate legacy console formatter. | All these serializers/formatters remain unchanged. Existing `--debug-session` / `--debug-session-path` provide traceability; no new configuration. |

The only intentional LLM-input addition is the presentation paragraph. Tool
arguments/results, carried context, workflow/evidence records, generated messages
and session persistence are not rewritten by presentation. The guideline is shared
by both frontends; headless serialization is unchanged, but future model wording
can naturally respond to the new guidance.

## Before and after

For an unambiguous candidate:

```text
Before: Planner recommended · sql-injection · GET /search · input q · sql-injection · 34d40d6a
After:  Planner recommended · sql-injection · GET /search · input q · sql-injection
```

When displayed candidate labels collide, the short suffix remains. IDs embedded
in endpoint/business labels are preserved.

For a troubleshooting reference:

```text
Before: workflow: Cannot read obs_0123456789abcdef for [reference] [reference]
After:  workflow: Cannot read obs_0123456789abcdef for cand_0123456789abcdef attempt_0123456789abcdef
```

Existing useful presentation stays visible:

```text
HTTP activity (observations only): 1 response · http · GET /orders/ORDER-42 · 403.
Turn ended · work remains; 1 incomplete validation; validation incomplete.
Finding saved · Example finding
  artifacts/findings/example.md
```

No deterministic before/after claim is made for LLM summaries. The prompt asks for
concise phase/endpoint/status/findings/coverage/errors/limitations, tracking IDs only
for actionable references or troubleshooting, and useful report/finding paths.

## Changed files

- `src/ui/core/state.py`: condition the planner suffix on displayed-label ambiguity.
- `src/ui/core/admission.py`: preserve exact sanitized references in issues.
- `src/agent/system_prompt.py`: short presentation guidance shared by both profiles.
- `tests/ui/test_progress_milestones.py`: update the real workflow regression to require omission of redundant suffixes while retaining deduplication/state checks.
- `tests/ui/test_runtime_presentation.py`: 17 offline cases covering structured progress/outcomes, ambiguous labels, IDs/business IDs, errors, permission details, split chunks, ordinary/final-synthesis prompt delivery, fake streaming clients, sessions, debug logs and headless JSONL.
- `tests/agent/test_agent.py`: explicitly disable automatic compaction in the manual-compaction memory test and assert the ordinary-turn/manual-compaction request sequence. All original memory assertions remain.
- `docs/tui-presentation-audit.md`: this audit and verification record.

## Verification

Before the production edits, the focused run reproduced four expected failures:
redundant suffix, masked error references, and absent guidance in each prompt
profile (10 other cases passed). After editing, all 56 then-current focused cases
passed. The expanded 17-case boundary file also passed under
`-p tests.scenarios.offline_checkpoint`, which blocks real network/process effects
and confines durable data to pytest scratch space.

The first broader run passed 1,784 cases and failed the manual-compaction memory
test. An in-memory baseline using the unchanged HEAD prompt builder passed that
test. Diagnostics showed that the added guidance crossed the fixture's implicit
automatic-compaction threshold and consumed its scripted response before manual
compaction (`FakeClient: script exhausted`). The guidance was shortened, and the
manual test now disables automatic compaction explicitly, matching nearby manual
tests. No production threshold, compaction behavior or memory assertion was
weakened. The 312-case affected agent/prompt/presentation rerun passed.

The final broader offline run passed all **1,785 tests** in 147.37 seconds.
Full configured Pyright passed with zero errors, warnings or informational
diagnostics. `git diff --check` passed; final diffs and worktree status were
reviewed.

Commands (from the repository root):

```sh
venv-linux/bin/python -m pytest -q -p tests.scenarios.offline_checkpoint tests/ui/test_runtime_presentation.py
venv-linux/bin/python -m pytest -q -p tests.system.offline_suite \
  tests/ui tests/agent/test_systemprompt.py tests/agent/test_output_pipeline.py \
  tests/agent/test_agent.py tests/runtime/test_prompt_file_headless.py \
  tests/runtime/test_session_debug.py tests/runtime/test_logger.py \
  tests/runtime/test_cli_main.py tests/state/test_session_store.py \
  tests/integration/test_scope_event_lifecycle.py \
  tests/integration/test_structured_handoff_hardening.py
venv-linux/bin/python -m pyright
git diff --check
```

The broader command enables the existing offline socket guard; clients and tool
traffic in these regressions use deterministic doubles/local fixtures. The full
repository suite, live provider/target tests and lan-05 were not run. Unrelated
pre-existing worktree changes were left intact.

## Limits

- LLM compliance is advisory. Arbitrary generated text can still include IDs and paths.
- Untyped runtime assistant fallback/recap text remains intact, including diagnostic IDs. Safely projecting all such text would require explicit provenance beyond this change.
- Existing secret/control/thinking safeguards still apply; byte equality checks cover ordinary visible text and ID-split chunks, not removal of those safeguards.
- Report/finding paths, permission paths, business identifiers and error/stall/repair details remain visible when useful. No blanket path suppression.
- No historical experiments, observations or session data were edited. No live LLM/API, live target, lan-05, commit or push was used.
