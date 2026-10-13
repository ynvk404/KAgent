# BenchmarkJava runtime changes: final review

## Scope and conclusion

This review reads the current source diff, the three added regression files, `BENCHMARK_RUNTIME_IMPLEMENTATION.md`, and the recorded verification logs. The worktree contains **7 modified source files, 3 new test files, and 1 implementation report**. This review adds this document only.

The worktree also contains untracked `kagent-changes.diff` (dated 2026-10-13). I read it and verified it is byte-for-byte identical to the current tracked-source `git diff`; it is a diff copy, not another source or test change. I leave it untouched.

The changes address four runtime causes found in the 40 case audit: useful skill pages were being reduced before the model could use them; Direct validation could spend its remaining steps on calls without meaningful progress; captured HTTP bodies could not be retrieved through the sanitized tool-result store; and an accepted result could leave cleanup unresolved while the agent continued without an actionable step. Serialization stability and explicit proof-source references were also tightened.

Offline regressions cover the implemented mechanisms. They do not prove that the LLM will find the right payload or reach a finding in BenchmarkJava. The final full suite has no new failing node IDs compared with baseline, but it still has 12 failures. Several concern workflow recovery, grounding guidance and context/schema limits, so the suite and the experiment are not ready for an unqualified pass. The separate implementation report records the full audit disposition; this document reviews the implementation and verification evidence.

## Changed files

| File | Architectural role and reviewed change | Regression evidence |
|---|---|---|
| [`src/agent/agent.py`](src/agent/agent.py) | Agent orchestration, context admission, Direct and Whole-target progress, workflow actionability, and HTTP evidence admission. Adds bounded Direct batch accounting, preserves/elides skill pages by age, admits a session-owned HTTP reader, and treats operator cleanup as a blocker while keeping finding/coverage work actionable. | `tests/agent/test_bounded_validation_regressions.py`; `tests/security/test_cleanup_actionability.py`; `tests/security/test_http_observation_reader.py`; existing Direct lifecycle and safety scenarios. |
| [`src/tools/common/tool_result.py`](src/tools/common/tool_result.py) | Bounded retained tool-result readers. Adds `ReadHTTPObservation`, a distinct reader for existing `obs_` HTTP observations; it does not reinterpret `tr_` results as HTTP evidence. | `tests/security/test_http_observation_reader.py`. |
| [`src/tools/skills/paths.py`](src/tools/skills/paths.py) | Safe skill-file path resolution and bounded Unicode paging. Every page now emits stable source identity/range/EOF metadata, including a complete first page. | `tests/agent/test_bounded_validation_regressions.py`; existing payload/skill reader tests. |
| [`src/tools/skills/payloads.py`](src/tools/skills/payloads.py) | Reads bounded payload catalogs. Marks reader output `preserve` so generic adaptive truncation does not split the page. | `tests/agent/test_bounded_validation_regressions.py`; existing payload reader tests. |
| [`src/tools/skills/skill_file.py`](src/tools/skills/skill_file.py) | Reads bounded skill documents. Applies the same `preserve` policy as payload pages. | `tests/agent/test_bounded_validation_regressions.py`; existing skill reader tests. |
| [`src/workflow/evidence.py`](src/workflow/evidence.py) | Validates explicit proof references against declared primary observations. Also checks `obs_...` handles in request headings and table rows inside the selected candidate proof. | `tests/agent/test_bounded_validation_regressions.py`; existing evidence/workflow tests. |
| [`src/workflow/state.py`](src/workflow/state.py) | Canonical workflow serialization and hydration. Makes bounded/redacted text stable when re-normalized, without changing the schema. | `tests/agent/test_bounded_validation_regressions.py`; cleanup/save-load binding tests. |

### `src/agent/agent.py`

`WholeTargetStallTracker` at lines 760–893 is shared with Whole-target mode. The new `record_validation_batch` is invoked only for requested-goal Direct runs at lines 4651–4689. Before this change, a Direct tool batch could continue to consume steps because the counter was advanced on tool-free turns; observation handles or changed arguments could look like activity despite returning the same response. The new code compares actual reader ranges by source digest, fingerprints HTTP response state rather than observation IDs/request arguments, allows finite novel exploration and a bounded verification repeat, and counts different controller diagnostic codes as limited correction opportunities. It records a stall as `workflow_stalled`; it does not manufacture a negative result or close an attempt.

The distinction between exploration and progress matters: new response content may earn a finite exploration step, while only workflow state changes count as structured facts. Pagination over unseen ranges prevents a false stall, but pagination does not reset the HTTP exploration allowance. Existing `WholeTargetStallTracker.record_iteration` remains the Whole-target mechanism; the Direct call site uses the new batch method.

The same file changes `_has_actionable_requested_goal` at lines 2661–2688. An accepted result with `requires-user-action` or failed cleanup no longer invites more probes once the only remaining work requires an operator. If coverage synchronization or confirmed-finding persistence is still possible, the goal remains actionable. Pending cleanup stays actionable. The Direct completion branch at lines 4651–4689 synthesizes a blocked/stalled unresolved status without overwriting the accepted result.

The reader is scoped to this Agent in initialization around lines 1156–1163 and permission dispatch around lines 1678–1685. `_http_analysis_content` at lines 5866–5910 and `_protect_http_context` around lines 5960–5990 validate that the result came from the same reader and still has a usable source binding before allowing it into model context or a resumed turn. Context handling at lines 5137–5245 exempts recent skill-page outputs from adaptive body clipping, keeps at most four recent pages whole, and replaces older pages with a short pointer while retaining the session history. Hard request admission still decides whether the resulting request fits.

The focused tests exercise no-progress Direct batches, HTTP duplicate IDs/arguments, repeated and novel responses, diagnostics, valid paging, hard context rejection, and cleanup obligations. Existing Direct lifecycle and safety scenarios also pass. There remains coupling in one large Agent module: reader registration, context admission, progress accounting and lifecycle decisions are distinct concerns. The implementation reuses existing scope and progress gates, which is smaller than a separate Direct tracker or a new storage path, but parsing serialized reader envelopes for range accounting is a format coupling worth watching.

### `src/tools/common/tool_result.py`

`ReadHTTPObservation` begins at line 121. Previously, the generic `read_tool_result` path handled bounded `tr_` entries but did not retrieve the retained response body for a native `obs_` HTTP capture. The new reader accepts only an exact `obs_<32 hex>` identity and integer character ranges (lines 153–160), returns a bounded envelope with Unicode offsets and a continuation, and does not send a request (lines 212–256).

Before returning bytes, `validate_rights` checks that the controller is the Agent's current policy, a nested receipt is active, the observation is retained and belongs to the current objective/candidate/attempt/session/epoch/target revision, the candidate binding and current origin still match, the attempt is current, scope permits its URL, the skill permits HTTP, and existing `resolve_sources` integrity/ownership checks pass (lines 162–203). Completed observations are readable only for the latest completed result and while there is no active retest for the candidate. Permission is high impact with no session cache and rights are checked again after review. Known controller-managed secrets are checked against the complete retained body before slicing, so multiple allowed ranges cannot reconstruct a secret (lines 204–210).

The positive test proves bounded readback from an existing fixture observation and asserts the network-call count does not change. Negative tests cover invalid identity, integrity, ownership, epoch, scope, revocation, permission denial/revocation during review, internal secrets, and stale attempts. Unicode pagination is exercised after persistence/hydration, and the Agent's outbound context guard is checked. A valid imported-capture path, a source eviction during permission review, and a multi-agent/session isolation race are not separately represented in the new tests. Existing owner and policy gates reduce those risks, but they should be included in future targeted coverage if those modes are used for validation readback.

This design is preferable to broadening `read_tool_result`: `tr_` redaction/retention and native HTTP observation ownership have different provenance. It does add a dedicated tool and schema, so schema-budget tests remain relevant. The observed schema failures predate this diff at the same measured size, but the current full suite still exposes a context/schema budget issue that should be resolved before treating constrained-context behavior as fully verified.

The ordinary bounded lab HTTP response behavior remains on the original HTTP tool path. The new reader reads only bytes already retained by that path, and its envelope preserves the source hash, response completeness/truncation flags and body range. It does not decide whether text is SQL injection or XSS proof; it neither upgrades a parser error nor suppresses reflection evidence by classification. Known internal secrets are an explicit exception and are withheld from model context. That choice can make an entire observation unreadable even if it also contains useful evidence; the tests cover the secret gate, not a selective safe redaction strategy. Offline tests verify this retrieval contract, not the quality of future benchmark evidence.

### `src/tools/skills/paths.py`, `payloads.py`, and `skill_file.py`

`ReadPayloadsTool` and `ReadSkillFileTool` produce bounded pages through `SkillFilePages`. Their new `context_reduction_policy()` methods return `preserve` (`payloads.py:85`, `skill_file.py:87`) because the page already has a producer-owned bound and continuation. Previously the generic reducer could clip the reader output a second time, separating useful body text from its continuation or creating fragments that looked like distinct pages.

`SkillFilePages.preview` in `paths.py:154–188` now assigns/reuses a source reference even when the first page is complete, then always appends digest, Unicode range, source size and EOF metadata. A clipped page also includes an actionable next-page call. Same-content reads reuse identity. This lets progress tracking distinguish a genuinely unseen range from a smaller reread or EOF read without weakening path, symlink or paging bounds.

The Agent guard keeps four most-recent pages whole and replaces older reader messages with a transcript pointer. The test covers both reader types, confirms no more than four full page bodies remain in the working prompt, confirms session history remains intact, and separately proves that a page exceeding the hard context limit still raises `ContextCapacityError`. The complete-first-page test checks stable identity, digest, EOF, and that a smaller reread is not counted as progress.

A simpler change would have been to raise the generic character floor or keep every reader result. That would either preserve malformed fragments or grow context with every page. The current age-based retirement keeps the source paging model and hard capacity gate. One bound to retain in mind is that it keeps the latest four pages, not a semantic selection of the four most relevant pages; the model must reread older content through the source reader.

### `src/workflow/evidence.py`

`check_proof_references` already checked explicit observation/source fields and standalone handles, while intentionally ignoring examples in quotes and fenced code. A proof can also identify its primary request in a Markdown heading or table cell. Before the change, such handles escaped parent validation. Lines 113–115 now scan these explicit locations and reject a handle that is absent from the declared parent set.

The regression test covers both a request heading and a table cell: absent parent rejects, declared parent accepts. This is a narrow structural check and does not infer whether prose is true or whether a source semantically proves the claim. Narrative assertions without structured handles, ambiguous Markdown sections, and claims that overstate an otherwise valid observation remain limitations; expert proof schemas or validators would be needed for that. The implementation is intentionally smaller than a general Markdown claim parser, but headings and all pipe-prefixed lines may still include contextual text beyond direct evidence references.

### `src/workflow/state.py`

`_text` at lines 98–121 normalizes whitespace and redacts sensitive text before applying its length cap. Previously, the cap could end on whitespace or in the middle of a redaction token. Hydration ran normalization again, changing the serialized note and therefore invalidating the binding of an otherwise accepted result. The new loop keeps a bounded prefix stable under the same redactor and normalization. Each adjustment shortens the prefix; it does not add fields or weaken schema validation.

The tests cover trailing ASCII/Unicode whitespace, long values, password/cookie/authorization examples, the redaction marker boundary, and equality of `ValidationResult` plus its assessment binding after JSON save/load. Cleanup tests repeat the binding assertion through `WorkflowState` hydration. Redaction may shorten a note when its cap intersects a masked value; preserving the secret or changing the accepted schema would be worse. No migration or rewrite of existing benchmark artifacts is performed.

## New test files

| Test file | Coverage and denied cases | Gaps to retain |
|---|---|---|
| [`tests/agent/test_bounded_validation_regressions.py`](tests/agent/test_bounded_validation_regressions.py) | 25 collected test instances: stable redacted serialization; preserve/retire pages; proof references in headings/tables; Direct stall without inventing a negative; unseen versus overlapping/EOF reader ranges; repeated HTTP IDs and changed request arguments; legitimate distinct response exploration/repeats; bounded diagnostic correction; hard context capacity; complete-page identity. | No live LLM behavior; these tests exercise tracker/controller mechanics. Multi-turn combinations of reader paging, changing workflow facts and phase changes are not exhaustively modelled. |
| [`tests/security/test_http_observation_reader.py`](tests/security/test_http_observation_reader.py) | 13 instances: successful no-network read, bounded output, malformed or unowned sources, integrity/epoch/scope/revocation gates, permission denial and revocation during review, Unicode pagination after storage/hydration, current outbound guard, whole/partial known-secret blocking, and old-attempt isolation during retest. | Valid imported-capture readback, simultaneous objective/session changes during permission review, body eviction while awaiting permission, and representative secret encoding/redaction variants are not separate cases. |
| [`tests/security/test_cleanup_actionability.py`](tests/security/test_cleanup_actionability.py) | 7 instances: pending cleanup remains actionable; operator-required/failed cleanup blocks futility; confirmed finding persistence remains actionable; accepted result and binding survive save/load for ASCII, Unicode and redacted notes. | Does not exercise the full run loop against a real operator resolving cleanup, nor every interleaving of coverage sync, finding persistence and cleanup changes. |

The recorded focused run collected **106 passing tests**, including all three files, Direct requested-goal lifecycle, evidence recovery contract, native Benchmark Runner result revisions and scenario safety. The new files themselves add 45 parameter-expanded instances (25 + 13 + 7).

## Root cause disposition

| Audit issue | Root cause | Changed mechanism / evidence | Status |
|---|---|---|---|
| Context reduction double-clipped `read_payloads` / skill-file pages | Generic adaptive reduction treated an already bounded, paginated output like an arbitrary large tool result; continuation and body could be separated. | Reader `preserve` policy, four-page working-context retention, whole-page retirement, stable source identity/EOF, hard-admission regression. | **FIXED at runtime level; benchmark benefit unverified.** |
| Direct budget spent without meaningful progress | Stall tracking did not evaluate every tool batch; changing IDs/arguments and duplicate responses could mask a loop. | `record_validation_batch`, source-range accounting, response fingerprints and finite correction/exploration; offline valid-loop and permitted-progression tests. | **PARTIAL.** Mechanism is tested; recovery-closure full-suite failures remain, and live agent effectiveness is unknown. |
| Captured HTTP evidence was unavailable after response truncation | Sanitized `tr_` reader is not a reader for retained native `obs_` response bodies. | Session/attempt-bound `ReadHTTPObservation`, bounded ranges, same permission/integrity/source gates, no added request, whole-source secret check. | **FIXED for covered native observation contract; benchmark benefit and imported-capture path unverified.** |
| Cleanup/actionability loop | A terminal assessment blocked by operator cleanup could remain actionable as if more probes would solve it; required finding/coverage work must still proceed. | `_has_actionable_requested_goal` separates operator-only cleanup from pending cleanup, coverage and finding persistence. | **FIXED for covered state combinations; full operator-resolution lifecycle not fully tested.** |
| Save/load changed bounded text and proof binding | Cap/redaction/normalization was not idempotent at text boundaries. | Stable prefix `_text`; serialization and accepted-result binding tests. | **FIXED for tested boundaries; legacy artifact migration was deliberately not run.** |
| Explicit proof references in headings/tables escaped parent check | The checker recognized structured fields and standalone IDs but not common Markdown request layouts. | Heading/table handle check with accept/reject test. | **PARTIAL.** Structural references are covered; narrative claim entailment and ambiguous scope are not. |
| HTTP write/destructive effect authority | Permission path does not provide a complete effect/intent contract for extra-write actions. | No source change; current grant contract and existing test explicitly leave unknown effects unclassified. | **DEFERRED contract change; high priority before autonomous mutating validation.** |
| SQLI-2/XSS semantic confirmation | Generic workflow admission checks evidence bindings and admissibility, not class-specific proof meaning; legacy SQLi compatibility permits weaker parser-error confirmation. | No vulnerability classifier added. Skills distinguish indicators from confirmation, but failed grounding-guidance contract tests remain. | **DEFERRED.** Do not treat the audited TP results as semantically repaired. |

The earlier audit flagged evaluator-accepted TP claims whose SQLi support was parser-error-only or whose XSS support was reflection without demonstrated execution. The changes here preserve primary-source binding, but do not establish class-specific proof. Those TP claims need a case-by-case evidence review; do not relabel them from evaluator acceptance alone. Cases **00441, 01777 and 02546** have not been rerun. Nothing in these offline tests establishes that any will succeed after the changes. Live benchmark verification was expressly excluded from this work.

## Verification and remaining failures

| Check | Recorded result |
|---|---|
| Regression setup against pre-change source | Relevant fixtures failed before implementation, including Direct batch stall, missing HTTP observation reader, cleanup actionability, capped-text stability and complete-page metadata. This supplies before/after evidence for the mechanisms. |
| Final focused suite | **106 passed** in 137.89 seconds. |
| Final full suite, isolated source snapshot | **7,140 passed, 12 failed, 18 skipped, 3 xfailed, 2 warnings** in 1,001.76 seconds; no new failing node IDs versus baseline. |
| Baseline full suite | **7,089 passed, 18 failed, 18 skipped, 3 xfailed**. Four toolkit script failures were caused by executable mode loss in the source archive; those scripts passed when snapshot modes matched the workspace. |
| Browser private-namespace check | Full-snapshot invocation could not execute the interpreter hidden by its `/tmp` mount; the same test from workspace passed (**1 passed**, mock extension, no real browser). |
| Pyright | **0 errors, 0 warnings, 0 informations**, using `venv-linux`. |
| `git diff --check` | Clean after implementation. |

There are 12 final failures. All 12 node IDs were present in baseline, but baseline status alone does not make them harmless:

| Final failing test(s) | Count | Assessment for the experiment |
|---|---:|---|
| `tests/integration/test_hybrid_schema_budget.py::test_projected_default_inventory_and_guidance_budgets`; `tests/integration/test_tool_schema_budget.py::test_default_tool_schema_budget_is_measured_and_bounded` | 2 | Both measure **30,163 against a 28,000 bound** on baseline and final. This is relevant to the context-budget objective and should be resolved or explicitly bounded before relying on budgeted runs. Do not increase the limit to hide it. |
| `tests/llm/test_workflow_action_projection.py::test_transport_retry_keeps_encoded_projection_snapshot[anthropic]`; `[gemini]` | 2 | Mocked provider retries encode different workflow action projections after the request changes. Provider/request-snapshot integrity is independent of the modified files, but it is a real baseline failure; evaluate before model-driven benchmark runs on these backends. |
| `tests/scenarios/test_recovery.py::test_s04_s16_native_truncation_immutable_repair_or_bounded_closure[budget-closure]`; `tests/security/test_observation_grounding.py::test_agent_closes_exhausted_repair_without_new_probes[same-source]`; `[stale-parent]` | 3 | These are directly relevant to bounded evidence recovery. The S04-S16 fixture reports that runtime repair did not stop after two submissions; the grounding fixtures end in an unusable-primary-source rejection for truncated/incomplete evidence instead of expected closure. The final full suite still fails them. Keep integrity rejection; inspect why retry allowance/closure is not reached before declaring evidence recovery safe. |
| `tests/security/test_browser_local_protocol.py::test_real_persistent_owner_permission_and_cleanup_in_private_namespace` | 1 | Snapshot-layout failure: `bwrap --tmpfs /tmp` hides the snapshot interpreter. The isolated workspace rerun passed, so this node is not evidence of a product regression. |
| `tests/skills/test_validation_grounding_contract.py::test_loaded_validation_guidance_binds_claims_to_captures_and_new_repair_snapshots[sql-injection]`; `[cross-site-scripting]` | 2 | Both expect literal grounding/repair guidance in loaded skills and fail on baseline and final. This matters to model instructions even though no skill markdown was edited. Resolve the contract/test discrepancy before using these instructions as evidence of safe prompting; do not weaken the checks without review. |
| `tests/ui/test_markdown.py::TestRenderMarkdown::test_wraps_long_table_cells_inside_coherent_borders`; `test_narrow_table_respects_requested_terminal_width` | 2 | Baseline rendering widths exceed requested widths. Low direct relevance to the security experiment, but still a real user-facing UI defect. |

Six baseline failing node IDs passed in the final run: four toolkit script checks after correcting snapshot executable modes, `test_native_request_budget_exhaustion`, and one UI responsiveness timing case. A Whole-target `[deferred]` scenario timed out in an intermediate run, then passed in its isolated check and final full run; its timeout was not increased. The final comparison therefore shows no newly failing node ID, but does not establish absence of all behavioral regressions beyond test coverage.

## Risk, priority, and independent review

1. **High: effect/intent authority and class-specific proof contract.** Before autonomous write/destructive probes or treating confirmed SQLi/XSS as reliable, review the grant path (`src/permission/network/grants.py`) and workflow confirmation (`src/workflow/assessment.py`, `src/tools/workflow/workflow_tool.py`). Design bounded intent/effect permissions and per-skill structured proof criteria with tests for both legitimate bounded validation and denied actions. Avoid payload blacklists and generic reflection/parser regexes.
2. **High for Whole-target: evidence-repair closure.** Diagnose the three failing recovery/grounding scenarios while preserving immutable-parent and completeness gates. This directly affects exhausted validations and confidence in honest terminal status.
3. **Medium-high: context/schema budget.** Investigate the two unchanged 30,163/28,000 limits. Confirm the net schema/context cost of the added reader and keep the hard provider limit effective.
4. **Medium: provider retry projection.** Repair or explicitly scope the preexisting Anthropic/Gemini mocked retry mismatch before relying on those runtimes for benchmark sessions.
5. **Low for benchmark validity: UI width failures.** Track separately; they are unrelated to evidence or target behavior.

An independent reviewer should first verify (a) Direct versus Whole-target call paths and bounded reset semantics in `agent.py`, (b) reader ownership/revocation/integrity across permission await and session resume, (c) source-page retention against actual hard capacity, (d) that cleanup never implies completion while work remains, and (e) the three unresolved recovery failures. Then review the deferred permission and per-skill proof contracts before a new benchmark run.

**Readiness: NOT READY for declaring all audited issues fixed or using this change as validation that the Official 40 cases will improve.** The covered offline mechanisms pass, and no new failing test ID appeared. Evidence-repair failures and unresolved authority/proof semantics remain material. Record these limits in the project report; do not relabel the audited TP outcomes or promise success for any named case without new authorized benchmark evidence.

## Source pointers

- Direct progress tracker and execution: `src/agent/agent.py:760–893`, `4651–4689`.
- Cleanup and requested-goal actionability: `src/agent/agent.py:2661–2688`.
- Context reduction and page retirement: `src/agent/agent.py:5137–5245`.
- HTTP reader: `src/tools/common/tool_result.py:121–256`; Agent admission/resume: `src/agent/agent.py:1156–1163`, `5866–5910`, `5960–5990`.
- Stable skill page metadata: `src/tools/skills/paths.py:154–188`; reader policies: `src/tools/skills/payloads.py:85`, `src/tools/skills/skill_file.py:87`.
- Proof references: `src/workflow/evidence.py:30–120`.
- Stable serialization: `src/workflow/state.py:98–121`.
- Verification logs from the recorded session: `/tmp/kagent-full-resumed.log`, `/tmp/kagent-baseline-snapshot.log`, `/tmp/kagent-focused-accepted.log`, `/tmp/kagent-pyright-accepted.log`, `/tmp/kagent-browser-namespace-recheck.log`.
