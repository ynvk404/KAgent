# XSS hypothesis reassessment audit

## Proven failure in lan-1000

The Agent tested quote/backslash techniques, correctly interpreted the returned
marker as JavaScript string data, and then closed the Candidate as `not-confirmed`
despite recording an independent, untested HTML-parser hypothesis. The error is
the scope of the negative decision, not an observed execution being suppressed
by a new runtime gate.

Local sources:

- `experiments/scenario3/runs/lan-1000/logs/session.jsonl`: native HTTP calls at
  seq 36, 95, 109 and 193; first negative submission at seq 235; repaired submission
  at seq 256; final stop at seq 802.
- `project/artifacts/proofs/cand_15fba61e0081f099bef5-xss-js-string.md`, under that
  run: lines 75–87 interpret the tested string correctly; lines 97–100 retain the
  untested alternative.
- Saved session `540b6946-9613-4a16-a42a-ab982c5162ca.json`: the accepted result's
  notes explicitly say the HTML terminator is untested, while
  `assessment.completed_attempt=true` and `outcome=not-confirmed` close the work.
- The associated observations contain all four native responses, complete and
  non-truncated, with matching response hashes. Coverage stores `passed` and the
  objective stores `tested_not_confirmed`. No finding was persisted.

The selected Burp capture had no response body; native HTTP recaptured it. The
first result omitted `observation_ids` and was rejected. That happened after the
Agent had already selected a negative outcome. It repaired the references and
submitted the same decision, so that admission failure does not explain the
initial premature negative.

The final answer identifies the alternative but asks the operator whether to
continue the same XSS goal. The run stopped at 22 of 100 iterations, not at its
limit. HTTP requests were not denied, upstream-blocked or truncated. Before the
negative submission, logged planner recommendations continued to select XSS
validation. Context-pressure messages reported soft estimates below the hard
input limit, not a stop requirement. Sixteen dropped debug records limit claims
about a complete event stream; the persisted session, observations and explicit
untested-hypothesis notes corroborate the decision being audited.

## Guidance and contract assessment

| Possibility | Evidence and conclusion |
|---|---|
| Fixed number of probes or variants | The snapshot explicitly has no numeric variant cap or corpus-exhaustion requirement. No such stop was required. |
| Fixed context-specific payload list | The snapshot says examples are not a fixed selection algorithm. The Agent stayed with literal-escape techniques, but the logs cannot prove an internal list-based strategy. |
| Reassessment after a failed technique | Generic reassessment existed. The most concrete adaptation paragraph began with transformation invalidating the probe; a syntactically valid but inert result was less explicit. This is a wording gap, not proof of LLM causality. |
| Bounded negative interpreted too narrowly | Proven in the submitted assessment: tested techniques were ruled out while an essential distinct hypothesis for that Candidate remained open. |
| Browser absence used too broadly | The final answer cites unavailable browser capability while leaving a potentially discriminating HTTP question untested. The existing skill already permits deterministic HTTP proof where sufficient. |
| Minimum testing encourages early closure | Minimal payload/proof language was present alongside instructions to adapt. It could be read too narrowly; logs do not establish that wording as the model's internal cause. |
| Runtime forces closure | No pre-result exhaustion/denial is evidenced. An accepted negative naturally resolves work and maps to coverage `passed`; this is the existing contract. |

`src/tools/workflow/workflow_tool.py` requires completed bounded-attempt declarations
and usable owned evidence. It assigns assessment meaning to the Agent rather than
parsing prose about remaining hypotheses. `src/workflow/state.py` derives completion
from accepted outcomes, and `src/agent/validation_guidance.py` permits an identified
missing bounded step. No demonstrated runtime defect calls for a change to those
contracts in this task.

## Evidence fidelity

Owned observation `obs_ce9cfd17ba59458d838ff9626bca08c7` actually contains:

```html
<h1>0 search results for 'xsspocdemo7&apos;'</h1>
```

The proof instead quotes a decoded apostrophe as if it were raw source and claims
that a quote can terminate the h1 element. A quote in HTML text is data, not an
element delimiter. The saved native HTTP tool result contains `&apos;`, so the
data was available. Historical proof/transcript files are not corrected in place.

The existing excerpt range/hash contract checks cited retained bytes when supplied;
it does not verify the semantic correctness of all free-form proof prose. New
tests retain both raw and explicitly labelled decoded analysis, and verify that a
decoded reconstruction's hash is rejected as an excerpt of the raw source.

## Scoped correction

- The decision checkpoint now requires the tested hypothesis, prediction versus
  owned observation, ruled-out scope, supported essential alternatives, useful
  next discriminator and actual resource/authority limits in existing notes.
- A useful, permitted, bounded test for an essential alternative continues the
  owned attempt without another prompt to repeat the same goal. Equivalent
  variants add no information; no boundary list, payload, variant count or
  exhaustion sequence is mandatory.
- Reassessment covers invalid code, valid but inert code, neutralized output and
  inconclusive responses. Sufficient evidence requires no further probes.
- `not-confirmed` remains a completed bounded negative for the actual scope; it
  cannot close essential unresolved alternatives merely to finish. Other sinks
  keep their existing Candidate identities and outcomes.
- `browser-required` names the actual browser-only fact. Browser absence does not
  settle a useful HTTP question, and does not force unnecessary HTTP either.
- Raw excerpts preserve the retained observation's entities, backslashes and
  redaction. Decoded/effective-code analysis is labelled separately.

The returned-code/syntax/trigger/policy safeguards from the earlier false-confirmation
fix are retained. No production Python, workflow/coverage semantics, evidence
admission, permission/scope, browser capability, persistence or budget policy
was changed. Payload resources still have the same two stages.
The early reminder remains compact at 1,617 normalized characters, below its
existing 1,800-character regression limit; the detailed closure procedure is in
step 3. The shared reasoning test now expects `Probe` for XSS and retains
`Execute` for SQLi. Its other assertions and the compactness limit are preserved.

## Checkpoint limit and actual context delivery

`git blame` traces the 1,800-character assertion to commit
`ac6363774772010c6d710450f41a05bee68a0ce8`, which introduced the early checkpoint
and its content test together. Neither that commit nor the inspected runtime
documents a technical reason for the exact number. It is an editorial compactness
guard, not a model input limit or a runtime truncation threshold. The existing
limit is retained because the essential continuation and honest-stop rules fit;
new assertions require those rules in the early checkpoint itself.

`src/skills/registry.py:materialize_skill_body` and
`src/skills/load_skill.py:LoadSkillTool.run` deliver the entire playbook, not just
the early checkpoint. The load tool's `preserve` policy excludes ordinary generic
tool-result offloading. The checkpoint is not separately injected on every model
call. Detail in step 3 is therefore available in the same loaded message, without
depending on a later optional corpus read. The five scripted returned-code paths
now assert that the detailed reassessment and raw-evidence instructions remain
in the actual model input immediately before `record_result`, together with the
adverse returned bytes. This checks delivery at the decision, not merely that an
earlier `load_skill` returned the text.

This is not a guarantee of model attention or permanent retention. General
history compaction can summarize away a skill body, including its early
checkpoint; `tests/agent/test_skill_context_policy.py` explicitly exercises that
behavior. Moving essential rules to a later resource would not fix it. Essential
rules remain early, detailed rules remain in the same playbook, and no compaction
behavior is changed in this scoped correction. The delivery tests cover ordinary
uncompacted validation; retaining or reloading full skill instructions after
compaction would require a separate runtime investigation/change.

## Change map

Line numbers refer to the current worktree, including the earlier uncommitted
false-confirmation safeguards that this task preserves.

| File | Main changes in this task |
|---|---|
| `skills/cross-site-scripting/SKILL.md` | Early decision rules at line 62; terminal reassessment at 657 and adaptation at 685; browser-only distinction at 719; raw proof at 853 and scoped negative at 910. |
| `skills/cross-site-scripting/payloads.txt` | Reassessment and raw-proof cross-references at line 112. |
| `tests/skills/test_cross_site_scripting_outcomes.py` | Delivery, inert probes, raw entities, independent sinks and equivalent variants at line 946. |
| `tests/agent/test_xss_returned_code.py` | Five returned-code paths at line 28, including guidance delivery before the terminal decision; resource/permission/unresolved paths at 214; raw excerpt integrity at 285. |
| `tests/skills/test_validation_grounding_contract.py` | Essential early rules and explained compactness guard at line 147; XSS `Probe` wording at 228. |
| `docs/xss-hypothesis-reassessment.md` | Audit evidence, scoped correction, threshold/context investigation and verification. |

## Verification and remaining limits

Skill tests are static delivery contracts plus synthetic parser/syntax fixtures
and a test-only outcome reference. Runtime tests use authored `ScriptedModel`
decisions, actual tool dispatch/owned readback and `httpx.MockTransport`. Added
cases cover inert-code adaptation without browser execution, bounded negative
closure, equivalent existing variants, separate sinks, actual budget exhaustion,
revoked HTTP rights, unresolved interpretation, raw entity fidelity and excerpt
hash rejection. The previous invalid-script/handler, trigger and policy cases
remain in place.

Verification uses the configured `venv-linux`:

| Check | Result |
|---|---|
| `python -m pytest tests/skills -q --tb=short` | 561 passed |
| `python -m pytest tests/agent/test_xss_returned_code.py -q --tb=short` | 10 passed |
| `python -m pytest tests/agent/test_validation_continuation.py tests/security/test_agent_assessment.py tests/integration/test_skill_workflow.py tests/integration/test_contextual_coverage.py -q --tb=short` | 144 passed |
| `python -m pytest tests/skills/test_validation_grounding_contract.py tests/skills/test_loadskill.py tests/agent/test_skill_context_policy.py tests/agent/test_skill_lifecycle.py -q --tb=short` | 122 passed |
| `pyright tests/skills/test_cross_site_scripting_outcomes.py tests/skills/test_validation_grounding_contract.py tests/agent/test_xss_returned_code.py` | 0 errors, 0 warnings |
| `git diff --check` | Clean |

The first three rows cover 715 tests across separate responsibility groups; the
122-test context/loader group overlaps the skills group. After strengthening the
early-rule and decision-input assertions, the context/loader group and all ten
returned-code runtime cases were rerun and passed. These are targeted groups, not
the full repository suite. Live model/target/Burp/browser evaluations were not run.
Existing optional Node-unavailable syntax-test skips remain intact. Loader,
resource pagination, cross-references and skill metadata regressions pass.

Preservation checks against the task-start snapshot show all six unrelated dirty
or untracked files unchanged. Runtime files match all 226 hashes in each of the
three run manifests. Of 82 historical/profile files, 81 retained their hashes,
including all session JSON, observations, coverage, findings, proofs and skill
snapshots. Only `lan-1000/logs/kagent.log` changed: it acquired shutdown warnings
from the existing run PID 181443 reporting 16 dropped debug records. This task
did not write, restore or rerun that experiment.

Static/scripted success does not prove
that an unscripted model will continue correctly or quote raw source faithfully.
An authorized new LLM evaluation is recommended before claiming improved detection
reliability, retaining the prior false-confirmation cases as well as unseen inert
and unresolved-hypothesis cases. A single lab success would not establish that
reliability across contexts.
