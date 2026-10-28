# XSS returned-code validation audit

## Root cause and historical evidence

`lan-300` and `lan-700` crossed an inline HTML script boundary, then treated
the resulting markup as sufficient confirmation without reconciling the
JavaScript actually returned after server escaping. These are different
evidence levels: structural breakout, valid effective JavaScript, exploitability
under the skill's deterministic HTTP exception, and observed browser execution.

| Run | Stored response evidence | Incorrect assessment |
|---|---|---|
| `lan-300` | `obs_becbc7031e3345af9d87ed3bd8bd65b6`: complete, non-truncated, 3727 bytes; the new script contains `document.title=\'xsspoc-d17\'`. | Proof claims the new script executes; the finding describes the intended expression without surviving backslashes. |
| `lan-700` | `obs_6f313baaf7244c469d79a25164f1806e`: complete, non-truncated, 3769 bytes; the new image handler contains `document.title=\'xsspoc-1770031201\'`. | Proof says quote escaping preserves the handler, then records `confirmed/high`. |

Both effective expressions contain a backslash outside a JavaScript string.
HTML script-data parsing or attribute parsing does not remove it. The changed
element in `lan-700` retains the same broken marker expression. Both runs explicitly
acknowledge the absence of browser execution. A failed variant does not establish
that the endpoint is safe, either.

Local audit sources (this task does not write these files):

- `experiments/scenario3/runs/lan-300/logs/session.jsonl`: HTTP probe seq 323,
  result submission seq 373, finding call seq 387.
- `experiments/scenario3/runs/lan-300/project/artifacts/cross-site-scripting/0ac7005603fdeb3b8162a23600d500b9.web-security-academy.net/cand_164ee363f507cf56f5ff.md`:
  returned source at line 63, execution inference at lines 68–82.
- `experiments/scenario3/runs/lan-700/logs/session.jsonl`: original script probe
  seq 180, handler probe seq 286, result submission seq 368.
- `experiments/scenario3/runs/lan-700/project/artifacts/cross-site-scripting/xss-reflected-search-pointer.html/proof.md`:
  returned source at line 64, incorrect handler interpretation at lines 69–73.
- Each run's `project/.kagent/observations/<session>.json`, saved session and
  `project/skills/cross-site-scripting/` snapshot were compared. The selected
  observations' response hashes match their retained bodies.

`lan-700` already had the pre-change worktree's XSS skill and corpus, including
the warning that quote escaping can invalidate a newly introduced script,
the optional decimal marker, parser-boundary guidance, and the instruction to
inspect returned bytes before confirmation. Adding that warning alone had not
prevented false confirmation. Historical reports also demonstrate that usable
capture metadata is independent of correct vulnerability interpretation.
The saved `load_skill` tool messages contain step 5's actual-response rule and
the final stop conditions in both runs; the relevant returned code is also
present in the observations/readback. The audit therefore found adequate input
data for the assessment that the Agent failed to make.

The inspected runtime contract explicitly assigns vulnerability meaning to the
Agent. `record_result` checks owned usable sources, immutable proof and assessment
binding; `confirm_finding` consumes that accepted assessment. No defect requiring
a workflow/planner/evidence-runtime change was identified in this audit.

## Scoped change

The existing skill structure and allowed-tools metadata are retained. Step 3
now requires a short returned-code trace after each response and before result
submission: submitted input → retained bytes → parser context → effective code
→ syntax/trigger/policy assessment → evidence decision. It preserves backslashes,
decodes only evidenced parser layers, and includes surrounding script/handler
syntax. Step 5 requires reconciliation before confirmation and report generation.
Each resulting executable unit is assessed separately; an intentionally terminated
original script can be invalid while a newly introduced script is valid.

The checkpoint distinguishes invalid complete code from truncated markup,
permits a justified harmless adaptation within the same scope and budget, and
requires a prediction followed by review of the new observation. Failed variants
remain adverse evidence. No extra probe is demanded when evidence already
suffices or no useful authorized test remains. The corpus references this same
checkpoint; its examples remain hypotheses rather than an execution claim.

Unresolved syntax/proof maps to `insufficient-evidence`; a viable browser-dependent
path retains `browser-required`. A single failed payload is not a bounded negative.
Optional offline syntax checks prove syntax only. No browser capability, mandatory
runtime syntax checker, new payload phase, request allowance or evidence field
was added. SQLi and all production Python sources remain unchanged.

## Regression scope and verification

- `tests/skills/test_cross_site_scripting_outcomes.py`: static guidance contracts,
  a test-only evidence policy, synthetic HTML decoding and optional Node
  `--check` fixtures. These cover valid submitted/invalid returned code, new
  scripts and handlers, quote-free syntax, one-layer attribute decoding, missing
  triggers, enforced versus report-only CSP, incomplete proof and honest negatives.
  Node checks do not execute the fixture; existing Node-unavailable skips remain.
- `tests/agent/test_xss_returned_code.py`: the existing `ScriptedModel` harness
  supplies authored decisions through real Agent dispatch and HTTP observation
  readback, with HTTP confined to `httpx.MockTransport`. Three cases stop on
  invalid code, adapt to valid inline code, or retain a missing handler trigger.
  They retain one owned attempt, adverse evidence and existing immutable proof,
  result, finding and coverage behavior. They also check that the new instructions
  and actual transformed bytes reach the model input.

Offline verification in the configured `venv-linux`:

| Command / check | Result |
|---|---|
| `python -m pytest tests/skills -q --tb=short` | 548 passed |
| `python -m pytest tests/agent/test_xss_returned_code.py -q --tb=short` | 3 passed |
| `python -m pytest tests/agent/test_validation_continuation.py tests/security/test_agent_assessment.py tests/integration/test_skill_workflow.py tests/integration/test_contextual_coverage.py -q --tb=short` | 144 passed |
| `pyright tests/skills/test_cross_site_scripting_outcomes.py tests/agent/test_xss_returned_code.py` | 0 errors, 0 warnings |
| `git diff --check` | Clean |

The 695 tests above are separate responsibility-group runs, not a full-repository
suite run. Skill tests exercise the actual loader, corpus pagination, allowed-tools
metadata, cross-references and unchanged two-phase payload structure. No live
target, Burp, browser or live LLM was started; the full repository suite was not run.

Preservation checks compared against a task-start snapshot: all five unrelated
dirty/untracked files retained their hashes, and all 226 production runtime files
match both run manifests. Of 55 historical/profile files, 51 retained their hashes,
including session JSON, observations, findings, immutable proofs and skill snapshots.
Four mutable log/context files changed while the task was running: the `lan-300`
context Markdown, and `lan-700` session log, process log and context Markdown.
The session log includes periodic `context_snapshot` events after the completed
turn; process-log warnings identify the existing run PID, 172520. This task did
not write or restore those files. Changes to the two already-dirty XSS resources
were layered on top of the saved worktree versions; SQLi and the pre-existing
untracked parser-boundary tests were preserved.

## Remaining limitation

Static assertions and authored scripted decisions cannot prove that an unscripted
LLM follows the checkpoint. The runtime continues to validate evidence ownership
and integrity rather than JavaScript semantics. A future separately authorized
LLM run is needed to measure whether the model preserves transformed code,
rejects the broken variant, makes a justified adaptation and reports an honest
outcome across unseen contexts. Browser-dependent execution remains unverified
without the corresponding supported capability and evidence.
