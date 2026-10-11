# Offline scenario harness: accepted M1 and M2 safety/recovery

M1 is accepted by the operator (15 scenarios; supplied offline checkpoint:
2944 pass, 0 fail, 1 deselected). The historical report below predates the
accepted schema-description changes and is not the current acceptance verdict.

**M2 COMPLETE:** all 16 required families map to 20 passing new tests; the
15 M1 cases and the guarded 406-test responsibility checkpoint pass. M2 made
no production changes. See the observed verification record below.

## M2 implementation audit / coordination gaps

| Family | Existing responsibility coverage | Coordination gap / new assertion |
| --- | --- | --- |
| S01 | agent_assessment active conflict | Agent rejection, honest closure, B ownership and saved obligations |
| S02 | state/context enrichment | repeated start identity, annotation merge, binding rejection and restart |
| S03 | assessment ownership | scripted wrong IDs, protected ledger, corrected references |
| S04 | observation_grounding partial source | native cap, immutable rejected snapshot, repair without more HTTP |
| S05 | execution_policy and happy gates | sticky revoke model retries, explicit operator reopening, YOLO variants |
| S06 | generic_fallback await guards | event-controlled production pre-send await and Agent continuation |
| S07 | checkpoint_artifacts cancellation | unpatched Agent HTTP cancellation, actual saved interrupted history, fresh continuation |
| S08 | assessment eviction/restore | fresh runtime old source rejection and Generic controller rebind |
| S09 | finding store write tests | confirmed commit versus exact canonical filesystem failure, retry identity |
| S10 | runtime_validation_completion export | actual derivative filesystem failure, Agent retry without probes |
| S11 | checkpoint_artifacts coverage | exact replace failure, immediate memory/disk difference, real sync and row count |
| S12 | checkpoint cancellation | exact session replace failure, last saved versus live state and explicit save |
| S13 | requested_goal_lifecycle | native terminal proof for one class leaves second honest unresolved |
| S14 | completion gates | real persisted proof/discovery removal and repair, no fabricated obligations |
| S15 | candidate_validation_recovery malformed JSON | shared model emits raw JSON/unknown names and reserved args to Agent |
| S16 | Agent evidence repair budget | repeated real rejected submissions, runtime closure, exact probe bound |

Only tests/helpers, tests/scenarios and harness documentation may change for M2.

## M2 scenario mapping

Files changed relative to the starting M1 worktree:

| File | M2 responsibility |
| --- | --- |
| `tests/helpers/agent_fakes.py` | Raw malformed calls, unknown names, distinct feedback IDs, declared production stop feedback |
| `tests/helpers/scenarios.py` | Exact optional request schedules, observation before extra checkpoint, reuse prepared/fresh runtime, real continuation, same resumed tools/budgets/client |
| `tests/helpers/scenario_oracle.py` | Captured historical identity, current obligations, proof availability, quiescent resources, compact result/failure traces |
| `tests/scenarios/conftest.py` | Independent guard patch ownership and explicit enclosing scratch container for legacy checkpoint fixtures |
| `tests/scenarios/test_safety.py` | Full-Agent attempt, ownership, permission, goal and malformed-call recovery plus guard-cleanup regression |
| `tests/scenarios/test_recovery.py` | Native truncation, bounded closure, filesystem commits/retries, await revoke, cancellation and fresh-runtime continuation |
| `tests/scenarios/offline_checkpoint.py` | Reuse the fail-closed guard on audited existing tests, keeping per-test durable-store isolation |
| `tests/scenarios/offline_regressions.txt` | Explicit 12-file responsibility checkpoint selection |
| `tests/scenarios/README.md` | Audit gaps, final mapping, evidence limits and verification record |

`tests/helpers/burp_selection.py`, the 15 M1 cases and all starting production
schema/description changes are preserved. No files were staged, committed,
pushed, restored or deleted; no dependencies were installed.

The two new modules contain 19 scenario cases plus one isolation regression.
S03/S15 share two dedicated-class variants; S04/S16 share repair/stop variants;
S07/S08 share expert/Generic interruption variants. Every recovery action runs
through production Agent dispatch unless explicitly identified as a controller
action below. No registry-only case substitutes for an Agent path.

| Family / test name fragment | Mode / failure and guard | Recovery and durable outcome |
| --- | --- | --- |
| S01 `conflict_honest_closure` | Direct SQLi; B start conflicts with active A, protected ledger unchanged | A honestly insufficient, B owns distinct attempt/sources; one finding/coverage row, A remains saved outstanding |
| S02 `same_binding_repeat` | Direct SQLi; repeated start preserves ID, annotations merge, request-template enrichment rejected while active | Honest close, legitimate enrichment/start; captured old binding remains historical, new proof/report persisted |
| S03/S15 `wrong_ids_raw_json` | SQLi query and SSTI form; wrong Candidate/attempt/observation/evidence, malformed JSON, unknown tool, reserved fields | Corrected native calls complete class-specific proof; one SQLi finding, no SSTI finding; exact error kinds and IDs |
| S04 `native_truncation` repair | Direct SQLi; actual 3-byte HTTP cap yields unusable primary terminal source | New derived artifact from six complete sources already captured; original immutable snapshot unchanged; seven HTTP sends total |
| S05 `sticky_revoke`, `session_denial` | Direct; sticky revoke (YOLO OFF/ON) and session denial prevent two model retries | Traced trusted operator retry/activate; six authorized native requests, normal proof and persistence |
| S06 `revoke_during_event` | Direct; revoke after authorization while real pre-send scheduler is held by Events | Delegate scheduler rejects invalidated receipt; explicit operator reopening and corrected call progress; zero stale sends |
| S07 `cancel_http_join_restore` | Direct and Generic; cancel first HTTP pre-send after start, join owning operation | Last saved active attempt restores interrupted, Candidate may remain validating; fresh Agent/tools/budgets/rights/start, Generic trusted fixture rebind; six/two new sends |
| S08 `terminal_history`, plus S07 Generic | Direct SSTI; accepted history/retained sources readable, fresh policy/controller authority absent; new attempt cannot borrow old source | Explicit continuation/retest; two intact result histories, disjoint source ownership, one logical disk coverage row/count |
| S09 `filesystem_commit` canonical | Direct SQLi; first exact canonical `os.open` fails | Accepted confirmed result remains; no persistence marker/report, completion pending; same revision retry writes exactly one canonical file with no probes |
| S10 `filesystem_commit` export | Direct SQLi; first exact derivative `os.replace` fails after canonical commit | Finding/result/completion survive; same Candidate retry exports summary, canonical bytes unchanged, one canonical file |
| S11 `coverage_failure_snapshot` | Direct SQLi; first exact coverage `Path.replace` fails | Observe live row/error and empty disk before recovery; bounded 13-step checkpoint remains incomplete; fresh runtime finding guard rejects before real sync, sync retry keeps row/count=1, then finding persists without HTTP |
| S12 `actual_session_replace` | Direct SQLi; exact session replacement fails at admission and finalization | Live committed confirmed result differs from last saved result set; temp files/locks/tasks released; explicit `Agent.save`, fresh runtime finding continuation, no HTTP |
| S13 `one_native_terminal` | Direct requested SQLi and SSTI goals; only SQLi has complete native proof | SSTI honestly insufficient, never negative; one finding does not complete work; saved goal statuses are confirmed/deferred |
| S14 `missing_actual_proof` | Direct; remove a real retained immutable proof, keeping accepted ledger/finding intact | Agent compatibility completion gate rejects; traced fixture controller restores exact backup bytes/hash, real completion gate and fresh resume succeed without probes |
| S16 `native_truncation` budget closure | Direct SQLi; repeated actual inadmissible terminal submissions | Production repair budget closes once with insufficient-evidence/unresolved, no terminal manifest/finding/coverage, exactly seven sends, no third scripted submission |

The shared M2 budget is 40 model steps, 60 execution calls and 30 seconds per
turn. Request schedules are exact: six dedicated-class sends, two Generic
sends, seven for the native-cap cases, and twelve across the two SSTI retest
turns. S11 declares an exact 13-step first turn to preserve pending committed
state for fresh recovery; its max-step diagnostic is asserted. Event waits are
bounded (5 seconds for release, 10 seconds for entry/join). No runtime retry
constants or timeout constants are patched.

Task cancellation at the held pre-send boundary propagates before a native
tool-result event is constructed. Its trace must contain the started HTTP call
and `done=cancelled`, with no result for that call and no transport send. Fresh
Agent history reconciliation supplies the cancelled tool feedback; this is
separate from permission-review cancellation, which can return a cancelled
ToolCallResult. Both interrupted workflow ownership and reconciled feedback are
asserted without manufacturing an observation or terminal result.

`ScriptedModel` emits malformed JSON/unknown names to the production parser,
and uses distinct feedback prefixes for continuations. A declared runtime stop
must match its exact call count and diagnostic, or the production evidence
closure call; assertions/provider/sink errors remain fatal outside Agent.
Expected invalid operations have call-ID/name/status/error-kind/reason checks
and before/after snapshots of attempts, sources, observations, evidence,
findings and sends. No error events are blanket ignored.

`InvariantOracle` captures binding history independently, compares immutable
bytes/hashes and native response bytes/status with the fixture ledger, and
checks current objective obligations separately from old histories. Active
ownership includes epoch, target revision and result position. Restored
interrupted history does not grant execution rights. Proof availability is an
explicit, independently hashed completion fact; a deliberately missing proof
does not erase accepted history. Quiescent receipt/task assertions do not run
inside held awaits. M1 retains its exact terminal save/resume equality and its
original outcome expectations.

Runner observes post-Agent state before any harness checkpoint. M2 disables
the extra M1 harness save/flush and compares live candidates, goals, results,
selected sources, evidence and finding markers with the actual session file.
Failure snapshots precede explicit retries and reopened CoverageStore/report
reads. Fresh resume uses Store.load through Agent.resume_saved, registers the
same tools, verifies client/budgets, and starts with no positive grants,
receipts or Generic controller context.

Filesystem injection selects exact scratch destinations and occurrences;
production save transactions execute normally. The only asynchronous wrapper
holds and delegates the production pre-send scheduler. Operator policy changes,
Generic binding and exact proof-backup restoration are trusted fixture
controller actions, explicitly traced; they are unavailable to the model.
Fault patches use scoped contexts and never undo the isolation owner.

These cases prove selected offline safety/recovery contracts, not vulnerability
accuracy, live network behavior, provider reliability, CLI/TUI lifecycle or an
exhaustive failure matrix. No production schemas/logic, skill methodology,
runtime limits or M1 assertions were changed for M2.

## M2 verification commands

Use Linux/WSL from the repository root. The responsibility manifest is audited
mocked transport coverage, with the isolation plugin installed explicitly for
tests outside this directory:

```sh
venv-linux/bin/python -m pytest tests/scenarios/test_happy_paths.py -q
venv-linux/bin/python -m pytest tests/scenarios/test_safety.py tests/scenarios/test_recovery.py -q --tb=short --durations=10
venv-linux/bin/python -m pytest tests/scenarios -q --tb=short --durations=10
mapfile -t regression_files < <(sed '/^#/d; /^$/d' tests/scenarios/offline_regressions.txt)
venv-linux/bin/python -m pytest -p tests.scenarios.offline_checkpoint "${regression_files[@]}" -q --tb=short --durations=10
venv-linux/bin/pyright tests/helpers/agent_fakes.py tests/helpers/burp_selection.py tests/helpers/scenarios.py tests/helpers/scenario_oracle.py tests/scenarios/conftest.py tests/scenarios/offline_checkpoint.py tests/scenarios/test_safety.py tests/scenarios/test_recovery.py
git diff --check
git status --short
```

The supplied 2944-pass checkpoint has no reusable verified manifest in this
worktree. The old README expanded command includes subprocess/other integration
groups and does not establish offline guarding, so it is not rerun or described
as the accepted offline checkpoint. The explicit M2 responsibility checkpoint
does not include live models/targets, wire replay, MCP/Burp servers, Docker,
workers or real subprocess groups. Existing external ignore/skip semantics stay
intact; no defect is hidden behind a new skip/xfail.

`offline_checkpoint` reuses the exact network/process/file-open guard. Its
filesystem container is this invocation's pytest base temporary directory, so
legacy fixtures may construct an outside-*policy*-root sibling fake secret
while remaining inside scratch. Stores, cwd, KAGENT_PROJECT_ROOT and redirected
user-data paths still use per-test tmp_path. The normal scenario guard remains
restricted to its individual tmp_path; its outside-scratch rejection tests are
unchanged. This avoids excluding the existing symlink/hardlink policy test or
loosening any production path gate. Each guard owns its patches independently
of the legacy tests' monkeypatch fixtures.

## M2 observed verification and handoff

| Run actually executed in this session | Result | Wall-clock |
| --- | --- | --- |
| Pre-edit M1 baseline, `tests/scenarios/test_happy_paths.py -q` | 15 passed | 70.36 s |
| Final standalone M2, `test_safety.py test_recovery.py -q --tb=short --durations=10` | 20 passed | 153.55 s |
| Final full scenario group, `tests/scenarios -q --tb=short --durations=10 --junitxml=/tmp/kagent-m2-final-scenarios.xml` | 35 passed | 215.45 s |
| Guarded responsibility manifest, `-p tests.scenarios.offline_checkpoint` | 406 passed, no skips/deselections | 171.76 s |
| Pyright on all eight M2-related Python files listed above | 0 errors, 0 warnings | not benchmarked |

All measured groups meet their requested budgets. JUnit case-duration totals
within the final full group are 60.79 s for M1 and 151.06 s for M2; these are
case totals, not separate process wall-clock measurements. The standalone M2
wall-clock is reported independently above.

The first responsibility attempt with a per-test filesystem guard produced
405 passes, one failure and one teardown error: a legacy symlink/hardlink
fixture attempted its sibling fake-secret setup outside the per-test scratch
directory. The guard correctly stopped that write. The explicit enclosing
pytest scratch-container plugin fixes this test-infrastructure scope mismatch;
all 406 existing tests then pass with the guard installed. No existing test was
weakened, skipped or edited.

Development scenario failures were diagnosed against production source and
trace. They were harness prerequisites/expectations (semantic fingerprint versus
enrichment, exact diagnostics, pending-checkpoint script lifetime, explicit
objective continuation, and task cancellation versus permission-review result
events). The final assertions follow those contracts and retain rejection,
recovery, persistence and no-extra-effect checks. No verified production defect
remains; no defect regression is hidden behind skip/xfail.

`git diff --check` is clean, including separate whitespace checks for untracked
harness files. The complete diff for `src/`, `skills/` and `integrations/` is
identical to the captured starting diff; `src/` includes the UI/TUI paths.
Existing M1 and Tool Schema Budget work is intact. No installation, stage,
commit, push or M3–M5 implementation occurred.

The supplied 2944-pass / 0-fail / 1-deselected baseline is operator-provided,
not a result run in this session. That exact checkpoint, the full repository
suite and live/external/process/worker groups were not run for the manifest and
isolation reasons above. This limits broader-suite evidence, not the mapped M2
scenario verdict. Stop after M2 for review.

Run from the repository root, using the existing environment:

```sh
venv-linux/bin/python -m pytest tests/scenarios -q --durations=10
```

`ScenarioDefinition` supplies the origin, endpoint, method, input, application,
feedback script, budgets and independent expected outcomes. `ScenarioRunner`
uses the shared `tests/helpers/burp_selection.py` factory and production
`Agent.run`, planner, registry, permission policy, workflow, evidence admission,
coverage, finding and session stores. The default factory remains compatible
with existing callers. The scripted model consumes actual tool feedback and
returned IDs; retries cannot conceal script assertions or exhaustion.

| Scenario | Observations and outcome |
| --- | --- |
| Direct SQLi | Benign baseline, syntax marker, two distinct executed TRUE/FALSE pairs; accepted confirmed result, then canonical finding |
| Direct SSTI, form and IPv6 query variants | Baseline and five Phase 1 arithmetic fingerprints from the playbook; literal reflection, accepted not-confirmed result, no finding |
| Whole-target complete | Landing page recon, HTML/form and API inventory, metadata review, structured input analysis and candidate handoff, SQLi validation, finding, coverage and completion |
| Whole-target deferred | Same bounded discovery and native observations; review is explicitly postponed, the attempt is unresolved, no finding or tested coverage, incomplete goal |
| Generic controller-bound | Zero matching validators; pure fixture controller verifies exact read-only input values and binds the production probe API; native comparison, proof and accepted not-confirmed result |
| Generic CLI-equivalent | No controller context; start is rejected as context-needed, no HTTP, insufficient-evidence result and deferred goal |
| Ambiguous mapping | Two validator metadata entries; no arbitrary expert selection, attempt or HTTP probe |

The real registry still reviews file/private-host operations. A session-only
HTTP grant is limited to the exact declared fixture origin and request budget.
The permission test checks denial and scheme/host/port scope changes. Fresh
Agent/policy/store instances resume through `Agent.resume_saved()` and reopen
disk coverage and canonical reports; old grants, receipts, observations and
Generic controller contexts are absent. Historical evidence cannot execute new
HTTP calls.

The oracle checks committed boundaries and final saved state independently of
`accepted_result()`: registration versus execution, one active attempt,
candidate/attempt/source ownership, native bytes and hashes, immutable read-only
proof, terminal source eligibility (including optional metadata exceptions),
finding persistence, cleanup, coverage, goals and completion. Trace diagnostics
are redacted and saved in each test's scratch directory, even on failures.

Only LLM and HTTP transport are scripted. HTTP uses `httpx.MockTransport`, an
exact request ledger, and a pure deterministic application. The application
does not run a real SQL database or template engine. These tests prove offline
runtime contracts, not live vulnerability accuracy, browser behavior, model
quality or CLI startup integration. `bind_probe_context()` currently has no
production caller outside its definition; M1 adds no CLI binder. The controller
fixture is explicitly identified in the positive Generic test.

The local autouse isolation fixture blocks IPv4/IPv6 including loopback, DNS,
socket connect/bind, process launches, old durable-store reads and writes outside
scratch. Its tests attempt these operations and verify denial; Unix socketpair
remains available for asyncio. Neither HOME nor CODEX_HOME changes. Existing
tests outside this group retain their own isolation semantics.

M1 contained no fault/cancellation matrix, stateful generation,
metamorphic testing, live evaluation, skill edits or production refactors.

## Historical M1 verification at HEAD 3787d35 (superseded by acceptance)

- Final M1 run: **15 passed in 69.52 seconds**, below the 120-second target.
- Focused factory callers: **88 passed in 69.66 seconds**.
- Expanded responsibility run: **2960 passed, 2 failed in 382.49 seconds**.
  One failure was the plugin test's `python` child process not being on PATH;
  activating `venv-linux` resolves it (**3 plugin tests passed in the targeted
  recheck**). The remaining default-schema budget failure is described below.
- Pyright on the six changed/added Python files: **0 errors, 0 warnings**.
- `git diff --check`: clean. Production and skill files remain unchanged.

Commands below run in Linux/WSL from the repository root. The expanded run
originally used the explicit `venv-linux/bin/python`; activate the environment
for tests that invoke `python` child processes.

```sh
source venv-linux/bin/activate
python -m pytest tests/scenarios -q --tb=short --durations=10

python -m pytest \
  tests/integration/test_candidate_validation_recovery.py \
  tests/integration/test_burp_selection.py tests/agent/test_capture_selection.py \
  tests/ui/test_burp_commands.py -q --tb=short --durations=5

python -m pytest tests/agent tests/integration tests/state tests/tools \
  tests/security/test_execution_policy.py tests/security/test_generic_validation.py \
  tests/security/test_agent_assessment.py tests/security/test_generic_fallback_audit.py \
  tests/security/test_bounded_probe_contract.py tests/security/test_evidence_reads.py \
  tests/security/test_phase_coverage_attestation.py tests/security/test_captured_http_replay.py \
  tests/security/test_assessment_review_fixes.py tests/security/test_session_authorization.py \
  tests/security/test_yolo_results_resume.py tests/security/test_yolo_memory_transport.py \
  tests/security/test_http_invocation_lifecycle.py tests/security/test_observation_grounding.py \
  tests/ui/test_burp_commands.py tests/ui/test_candidate_recovery_contract.py \
  tests/ui/test_report_handler.py tests/ui/test_permission_review.py \
  tests/ui/test_presentation_equivalence.py tests/ui/test_slash_handler.py \
  tests/runtime/test_cli_main.py tests/runtime/test_cli_exit_diagnostics.py \
  tests/llm/test_runtime_tool_schema_interop.py \
  --ignore=tests/integration/test_http_wire_replay.py \
  --ignore=tests/integration/test_mcp_integration.py -q --tb=short --durations=10

python -m pytest tests/tools/test_plugin.py tests/integration/test_tool_schema_budget.py \
  -q --tb=short --durations=5

venv-linux/bin/pyright tests/helpers/agent_fakes.py tests/helpers/burp_selection.py \
  tests/helpers/scenarios.py tests/helpers/scenario_oracle.py \
  tests/scenarios/conftest.py tests/scenarios/test_happy_paths.py
git diff --check
git status --short
```

### Historical remaining regression and review verdict (superseded)

`test_default_tool_schema_budget_is_measured_and_bounded` measures **29,016**
characters against the existing **<28,000** cap. A separate `git archive HEAD`
snapshot in `/tmp/kagent-m1-head.WvajRT`, using the same `venv-linux` interpreter,
reproduces the identical failure (**1 failed in 7.42 seconds**). That snapshot
contains the original helpers without M1 additions and no new scenarios. The
schema regression is therefore present at the starting commit, independently
of this patch.

Proposed minimal follow-up: remove at least **1,017 characters** of redundant
tool/schema descriptions while preserving action fields, admission guidance,
permission gates and the existing character/token caps, then rerun the schema
budget regression and provider schema interop tests. No production fix or test
threshold change is included here.

**Historical M1 PARTIAL verdict (superseded):** the implementation and scenario group were
complete; the expanded existing responsibility group is not entirely green due
to the reproduced HEAD schema-budget failure. Stop here for review.

The full repository suite, real localhost wire tests, MCP integration tests,
live providers/targets, Burp, MCP servers and Docker were not run. The existing
pytest configuration also excludes `test_kagent_burp.py`; its skip/ignore
semantics were preserved. No packages were installed and nothing was staged,
committed or pushed.
