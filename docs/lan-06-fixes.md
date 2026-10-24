# lan-06 fixes and lan-07 readiness

This change addresses the verified causes in `docs/lan-06-audit.md`. It does
not alter the historical run or assert that its candidates are confirmed.
All execution and verification in this task are offline.

## Production trace before editing

The saved session, native observations, retained discovery result, readable
artifacts and the six candidate-registration calls were inspected. Before
editing, all 226 runtime hashes in the lan-06 profile matched this checkout.
The saved state has four deferred candidates, three completed discovery/analysis
phases, and no attempts or validation results.

The dispatch path inspected was Agent request preparation -> ActionView schema
projection -> skill capability checks -> Registry permission/receipt gates ->
WorkflowTool -> state admission. `read_discovery_source` is already available
under the HTTP capability during Whole-target Input Analysis; no new reader,
permission exception or tool capability was necessary.

The evidence confirms separate causes: an unreasoned deferred status prevented
handoff; concrete/template mismatches caused correct source-binding rejection;
dropping input identity admitted disconnected records; and incomplete/misread
discovery output and contradictory triage wording contributed to unsupported
inventory/candidate claims. Target error responses are not KAgent exceptions.

## Exact changes

| File | Change |
| --- | --- |
| `src/tools/workflow/workflow_tool.py` | Normalize an available expert's unreasoned, unstarted deferral to queued on creation and enrichment. Preserve declared dependencies and existing assessed/active work. Advertise the deferral and input contracts in the real schema; report exact allowed action fields on argument errors. Recover input-path errors with canonical get_input guidance, preserving identity and source provenance. |
| `src/workflow/state.py` | Add optional, redacted Candidate deferred_reason session metadata; hydrate old sessions without migration. Surface declared dependency reasons in blockers. Prevent a declared dependency from becoming generic actionable work. |
| `src/workflow/assessment.py` | Exclude the bookkeeping annotation from request-binding hashes, preserving historical observation/proof ownership bindings. The optional key is omitted when absent, preserving existing serialization/snapshot vectors. |
| `src/agent/agent.py` | Include declared reasons in planner context; keep declared dependencies out of generic-startable work. |
| `src/agent/action_guidance.py` | Supply phase-specific reader/namespace/recovery instructions, native-versus-Shell guidance, canonical input handoff, and evidence-grounded inventory/triage/coverage summaries. |
| `skills/web-enumeration/SKILL.md` | Explain retained-result row reconciliation, actual versus inferred status/method/auth, visible JS field construction, consistent counting, and why omitted JS content is not a Shell HTTP exception. |
| `skills/web-input-analysis/SKILL.md` | Remove the claim that any response-shape change merits a SQLi handoff. Distinguish ordinary search, reflection, empty results and sibling behavior from class-specific evidence; document readers, deferrals and autonomous validator handoff after phase completion. |

No HTTP/registry permission gate, private-host handling, resource cap, allowed-tools
list, target scope, finding threshold, evidence recovery budget or native adapter
was changed. No provider/config changes or new target-specific logic were added.

### Lifecycle behavior

- Available expert, no result, no declared dependency: omit status or use queued.
  An unreasoned deferred proposal also becomes queued consistently; this alone
  does not admit validation, execute HTTP or produce a result.
- An intentional dependency uses status=deferred plus deferred_reason. Default,
  queued or unreasoned-deferred enrichment preserves it, including after session
  reload. start_validation returns a dependency error.
- Once that dependency is actually resolved, explicitly re-record with
  status=queued and deferred_reason=null before any recorded result. This clears
  bookkeeping only; current scope, capability, phase/input admission, permissions
  and all other runtime gates still apply.
- Registration cannot use this field to defer an active or already assessed
  candidate. Existing unresolved/terminal results retain their recovery/retest
  contract and are not requeued by registration.
- Unsupported, ambiguous or unavailable validators keep their existing routing
  and admission semantics. Generic capability is not created by a status change.

### Input identity and compatibility

Use the returned input_id and inherit its canonical endpoint/method/source_ref.
An input's source_ref cannot be cleared or replaced to bypass provenance checks.
Concrete paths are not silently converted to templates.

For backward compatibility, complete request geometry without input_id can link
to a single compatible canonical input using the existing compatibility check.
No template expansion, fuzzy path matching, new observation ownership, baseline
creation or authorization is inferred. Ambiguous variants are rejected. A
declared analysis handoff without a compatible input is rejected with recovery
instructions. Independently recorded early hypotheses remain possible under
the prior contract; validation still requires their compatible analyzed linkage.

Direct/candidate-validation paths do not acquire Whole-target-only prerequisites.
Existing linked enrichment retains its context and cannot erase source data.

### Evidence and tool selection

Discovery bodies use exact ds_ references with read_discovery_source; owned
attempt bodies use obs_ references with read_http_observation; retained sanitized
tool results use published tr_ references with read_tool_result under the original
producer capability. Metadata lookup is not body access. Rejected reads do not
justify refetching, inventing IDs or creating ownership.

Enumeration guidance distinguishes JSON, unauthorized responses, handler errors,
calibrated wildcard responses and partial bodies row by row. Input Analysis
retains exact baseline/status/size/content, including empty/adverse evidence.
Parser errors support a hypothesis without proving SQL construction, controlled
evaluation or impact. Runtime still validates evidence integrity and ownership;
the Agent still assesses vulnerability semantics.

## Regressions and verification

New files:

- `tests/integration/test_lan06_handoff.py`: 13 cases through production schemas,
  dispatch and Workflow state, including an autonomous scripted Agent loop.
- `tests/skills/test_lan06_grounding.py`: 3 loaded-playbook instruction contracts.

Red-before stages were recorded before the corresponding fixes: five failing
production handoff/reader/schema cases and three failing grounding contracts.
A further failing compatibility regression caught the new annotation changing
legacy request-binding hashes; the fix excludes it without changing old vectors.
Existing security tests also caught the default optional key changing a review
snapshot; omitting absent metadata preserves that existing assertion.

The autonomous script completes Input Analysis, loads SQLi, opens an owned
validation attempt, and then records an honest deferred outcome. It does not send
new target probes, adopt discovery traffic as terminal evidence, register proof
or force a finding. A separate assertion verifies the real planner recommends
SQLi after phase completion. Dependency, active-attempt, evidence-recovery,
unsupported/generic, ownership and permission regressions remain intact.

Final verification from the repository root:

```bash
venv-linux/bin/python -m pytest -q \
  tests/agent tests/security tests/tools tests/state tests/skills \
  tests/integration tests/llm --tb=short
# 5524 passed, 1 skipped in 475.42s

venv-linux/bin/pyright
# 0 errors, 0 warnings, 0 informations

git diff --check
# clean
```

The 16 new cases are included in that passing run. No existing test assertions
or live-test skip conditions were weakened. Other repository responsibility
groups and live/external-model tests were not run. Final diff/status and new-file
whitespace were inspected. The original audit hash is unchanged. A full
24-file run-tree hash check detected that the existing lan-06 process is still
writing periodic context snapshots and appending context_snapshot log events.
It is PID 103082, started before this task; the snapshot explicitly reports
"Reason: periodic 5 minute snapshot". Saved session/observations/artifacts and
skill snapshots retain their original timestamps and outcomes. This task did
not edit, restore or stop that run, and does not claim the actively written
bundle is frozen.

## Remaining limitations and readiness

Grounding and tool-selection changes are prompt/playbook contracts. They do not
constitute a SQLi semantic verifier, arbitrary-Shell network enforcement or a
guarantee that a live model will follow guidance. Native gates, source ownership,
caps and finding evidence requirements remain authoritative.

Historical unsupported or unreasoned deferrals are not bulk-migrated on load;
the normalization applies through registration/enrichment. Existing result-based
deferrals are preserved. Missing captures, credentials or genuinely truncated
content remain real limitations.

A fresh, separately requested lan-07 is ready to evaluate the changed behavior
under normal runtime gates: the offline checks above pass. No lan-07 launch,
model/provider API request, live-target access, new experiment, package install,
commit or push is part of this change.
