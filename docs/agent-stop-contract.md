# Agent iteration and stop contract

Direct objectives with requested goals, candidate validation, and Whole-target
objectives continue through the configured `max_steps` while work remains
actionable. Repeated tool argument errors, ordinary tool failures, metadata or
page reads, and intermediate responses without tool calls do not stop a run,
defer a requested goal, or set `probing_stopped` merely because they repeat.
There is no no-progress threshold or per-phase exploration allowance.

The existing outer-iteration accounting is unchanged. A malformed-call retry
belongs to its current iteration; tool-free final synthesis and its single
summary retry retain their separate call accounting. No additional probing or
model iteration is granted for terminal validation closure. Ordinary Direct
work can still end with a valid final response. Runtime completion, real
blockers, cancellation, scope, permission, timeout and resource limits continue
to apply independently.

At `max_steps`, the existing terminal finalizer submits eligible owned active
attempts through normal Workflow admission and checkpoints reconciled goals.
Closure does not infer a tested negative, confirmed vulnerability, mutation
absence, cleanup success, coverage or Finding from budget exhaustion. Missing
admissible proof remains `insufficient-evidence`; a real refusal retains its
existing blocker semantics. Registered proof is not automatically attached.
Closure failures are reported and preserve incomplete state.

Evidence Recovery keeps its existing attempt budget, exhaustion algorithm,
continuation rules and persistence. Its closure reason is `workflow_blocked`;
that label supplies no blocker and does not change the assessment outcome.
A valid pending repair window remains resumable at an invocation budget stop.
Pending permission and cancellation do not become forced terminal closures.
The stored `probing_stopped` field and its admission checks remain supported:
continuing an old stopped attempt never restores probing rights.

Workflow telemetry retains outer-iteration limits, status/actionability,
completed phases, phase readiness, frontier counts, validation rejections and
evidence-repair budgets. Canonical records, fingerprints used for identity,
deduplication, ownership, evidence integrity and assessment/Finding bindings
remain authoritative. The removed novelty projection has no persistence schema.
`workflow_stalled` has no producer or dedicated mapping in current runtime,
UI, headless or benchmark execution. Historical logs and experiment artifacts
are unchanged. Benchmark budget exhaustion continues to be reported as
budget exhaustion under the existing scoring contract.
