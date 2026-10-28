# General XSS assessment quality audit

## Scope and evidence

This audit reviews the current worktree after the earlier returned-code and
hypothesis-reassessment changes. Those changes, the two earlier audit documents,
and unrelated SQLi edits were already uncommitted at task start. This change is
layered on top; prior audit verification counts describe their own iterations.
No historical artifacts were edited, and no live LLM, target, Burp or browser was
started. The source/harness changes below do not establish live quality gains.

Reviewed: the full XSS skill and corpus; skill loader/resource reader contracts;
XSS static, syntax and scripted Agent tests; prior audit documents and related
git history; all four runs' saved sessions, owned observations, skill snapshots,
proofs/results and relevant log events. Runtime reading was limited to evidence
admissibility, assessment/completion and finding contracts where needed to
distinguish an Agent decision from a tool-enforced limit.

## Findings and confidence

| Evidence | Finding | Attribution / confidence |
|---|---|---|
| `lan-300`, `obs_becbc7031e3345af9d87ed3bd8bd65b6` | New script contains `document.title=\'xsspoc-d17\'`, but the accepted result and finding claim executable code. The surviving backslashes are outside a JS literal. | Proven false confirmation of this payload; high confidence. The Agent substituted intended semantics for returned code. It does not establish that the endpoint is safe. |
| `lan-700`, `obs_6f313baaf7244c469d79a25164f1806e` | Changing to an image handler preserved the same invalid expression. The proof says escaping preserved usable quotes; neither valid handler syntax nor its error trigger was established. | Proven false confirmation; high confidence. Existing parser/quote-free advice was delivered, so lack of that advice alone is not an adequate root-cause explanation. |
| `lan-1000`, `obs_57769ebc9ae841acb108d2cb496ddaea`, saved result/proof | The tested marker remains inside a valid JS string. The Agent records `not-confirmed` and `completed_attempt=true` while explicitly leaving an HTML-parser alternative untested. | Proven overbroad bounded negative; high confidence. Generic reassessment existed. The earlier correction already addresses continuation; this task preserves it. |
| `lan-1000`, `obs_ce9cfd17ba59458d838ff9626bca08c7`, proof | Response has `&apos;`; the proof labels decoded text as raw and claims an apostrophe closes an h1. | Proven evidence/interpretation mismatch; high confidence. A quote in HTML text is data. Raw/decoded separation and excerpt-integrity tests already exist and are preserved. |
| `lan-2000`, `obs_975a5249f5a649e399dd45b7d36c9481`, proof and result | Correctly recognizes HTML boundary success and invalid new JS, but says continuing requires repairing the original quote/backslash boundary. It stops `insufficient-evidence` without testing a simpler expression in the new unit. | The stopping explanation applies the old literal requirement to the new context; high confidence. The outcome is honestly unresolved, not a false negative/confirmation. A useful adaptation was overlooked; no success on the real target is claimed. |
| Current playbook vs run snapshots | Context detection, parser paths, returned-code checking, adverse evidence, hypothesis reassessment, permission/budget limits, scoped negatives and raw fidelity were already present. The early diagram still jumped from nondeterministic evidence directly to `browser-required`; the outcome summary could imply a JS-string label alone required a browser. | Confirmed wording inconsistencies. Their effect on a particular model decision is uncertain. |
| Current playbook | A discriminating prediction was requested, but expected supporting/falsifying observations and invalid request comparisons were less explicit. Rebuilding the model after a successful transition and simplifying the resulting expression were implicit. Long synthetic examples repeated material in the main decision flow. | Confirmed guidance/organization gaps; plausible contribution, not demonstrated LLM causality. |

Historical observation bodies were complete, untruncated and marked completed;
their response hashes were verified against retained bytes. Minimal verbatim
script excerpts and exact encoded request queries are now in
`tests/fixtures/xss-returned-contexts.json`, with original observation IDs,
response hashes and byte ranges for audit lookup. They contain no credentials or
hostnames and are test data, not new live evidence. All historical code is parsed
only; even the inert `alert(1)` text from `lan-1000` is never executed.

For `lan-2000`, saved `load_skill` output already contains the returned-code
checkpoint, quote-free marker guidance and hypothesis-closure instructions.
The proof describes a server transformation observed on sample inputs; neither
its implementation nor all possible inputs were verified. Log result submission
seq 327 precedes `workflow_blocked` at 17/100 iterations (seq 336–337). All four
native HTTP observations were retained without truncation; no pre-result
resource exhaustion or HTTP permission denial is evidenced. The runtime stops
after the Agent's unresolved choice; that is not evidence it prevented a prior
permitted discriminator. The proof's claim about another DOM-fragment sink has
no demonstrated source-to-sink evidence in these captures and is not adopted.

## Smallest useful correction

The skill now leads with **Observe → Model Context → Form Hypotheses → Predict →
Probe → Interpret → Adapt → Reassess → Decide**. Changes strengthen the existing
decision process rather than add payload recipes:

- Model only evidenced input/request, server/template, response and client-parser
  layers. Keep transport decoding, HTML decoding and JS escapes distinct. Check
  method, input binding, session and response identity before diagnosing absent
  propagation. No mandatory encoding survey is introduced.
- State supporting and falsifying predictions and their information value before
  a chosen probe. If both hypotheses predict the same visible result, choose a
  better discriminator, reuse existing observations or state the limitation.
- After a proven boundary crossing, derive the new context from actual bytes.
  Preserve surviving transformations while dropping obsolete delimiter needs.
  Consider a simpler harmless expression before abandoning the path. This applies
  to any evidenced transition, not a particular tag, delimiter, target or lab.
- Distinguish absent propagation/invalid comparison, neutralization, valid inert
  code, invalid new code, missing triggers, effective policy and HTTP ambiguity.
  Interpret each cause before adapting, requesting a missing capability or
  selecting the outcome. Syntax validity alone still cannot confirm XSS.
- Preserve the existing useful-test continuation rule. A bounded negative must
  address the assigned hypothesis; narrowing it after a failed technique cannot
  justify `completed_attempt=true`. Repeating equivalent variants is unnecessary.
- Reconcile the early workflow diagram and final outcome summary with step 3:
  `browser-required` identifies a necessary browser-only fact, while deterministic
  HTTP evidence may establish exploitability without claiming observed execution.
  Choose the stop reason before recording an outcome.

No production Python, workflow object/schema, parser enforcement, browser adapter,
permission, scope, evidence/provenance gate or SQLi behavior was changed. The
inspected runtime deliberately checks source integrity/ownership and accepted
assessment bindings; vulnerability meaning remains an Agent responsibility.
Accepting the historical semantic errors under that contract is not itself a
demonstrated runtime defect that warrants a new gate in this task.

## File changes

| File | Purpose |
|---|---|
| `skills/cross-site-scripting/SKILL.md` | Context model, two-sided predictions, context rebuilding, failure interpretation, honest closure and consistent browser/finding wording. Essential checkpoints remain in the loaded playbook. |
| `skills/cross-site-scripting/payloads.txt` | Align the browser stop reminder and reference the new-context reasoning; keep the same two payload stages and harmless actions. |
| `skills/cross-site-scripting/payloads/context-reasoning.md` | Move existing worked context contrasts out of the main flow. Optional, accessible through the existing bounded `read_payloads` tool; no new tool or approval. |
| `tests/skills/test_cross_site_scripting_outcomes.py` | Keep parser/example assertions by reading the relocated resource through real pagination. Clarify the test-only classifier's assumptions and limits. Update the requested reasoning flow. |
| `tests/skills/test_xss_parser_boundaries.py` | Static instruction contracts, concrete request/HTML decode contrasts and four retained historical parser/syntax regressions. |
| `tests/skills/test_validation_grounding_contract.py` | Check the new XSS reasoning flow; leave SQLi's separate flow and the existing compactness threshold intact. |
| `tests/agent/test_xss_returned_code.py` | Extend the existing scripted real-dispatch harness with attribute, comment, style and data-block adaptation, including decision-time delivery. Strengthen its bounded negative with a distinct outer-boundary probe and observed neutralization, rather than narrowing scope to the failed quote technique. |
| `tests/fixtures/xss-returned-contexts.json` | Minimal retained excerpts for all four requested runs; tests do not depend on ignored experiment directories. |
| `docs/xss-assessment-quality-audit.md` | Findings, attribution, change rationale, verification and independent evaluation proposal. |

The main playbook is shorter despite adding the decision rules. Critical parser,
syntax, trigger, policy, continuation and evidence safeguards remain in the main
body, including before result submission. Optional worked examples move to a
resource; the main skill does not depend on that resource being read. The early
checkpoint's existing editorial character limit is unchanged, and no instruction
was shortened merely to obtain a passing count.

## Regression coverage and validation levels

| Behavior group | Check |
|---|---|
| Context recognition and multiple parser boundaries | Existing HTML/attribute, inline vs external JS, template, JSON, DOM/CSS contrasts; new scripted transitions through four additional placements. |
| Escaping/transformation and invalid syntax | Actual `lan-300/700/2000` excerpts, separate effective scripts/handlers, Node `--check`, surviving backslashes and one-layer entity decoding. |
| Valid but inert code, encoding/sanitization | Actual `lan-1000` string, existing escaped literals/templates/inert insertion tests; request encoding vs HTML decoding contrasts. |
| Triggers and CSP | Existing missing-click/handler outcome and enforced vs report-only policy fixtures. These do not simulate events or implement a CSP evaluator. |
| Evidence gaps/fidelity and false confirmation | Missing/incomplete sources, raw entities, transformed expressions, ownership/attempt binding, immutable proof, excerpt-hash mismatch and finding eligibility tests. |
| Adaptation and premature closure | Existing inert-to-adapt, adverse evidence, resource/permission stops and bounded negatives; new context-rebuilding/prediction delivery across multiple placements. |
| Correct bounded negative and browser-required | Existing completed scoped-negative, separate API/DOM sinks and absent browser-trigger paths; outcome semantics remain unchanged. |

1. **Static skill tests** check what instructions/resources are delivered and
   preserve the allowed-tools/two-stage contract. They do not test attention or
   reasoning. Resource tests follow real pagination rather than inspect an
   unreachable local reference.
2. **Deterministic tests** use constrained HTMLParser fixtures, optional Node
   syntax checks, and the existing `ScriptedModel`/`httpx.MockTransport` Agent
   harness. Real tool dispatch exercises ownership, request encoding/readback,
   one-attempt adaptation, proof/result persistence, coverage and finding gates.
   Decisions are authored; runtime does not newly reject all syntactically invalid
   confirmations. Historical fixtures retain complete relevant units and suffixes:
   suffix text can also create inert elements after an early script close.
3. **Live LLM evaluation** was not run. Neither the static/reference classifier
   nor authored scripted success demonstrates improved unscripted reasoning.

Verification used the configured `venv-linux`, with focused tests before the
related contract groups:

| Command | Result |
|---|---|
| `python -m pytest tests/skills tests/agent/test_xss_returned_code.py tests/tools/test_xss_outcome_runtime.py -q --tb=short` | 589 passed |
| `python -m pytest tests/agent/test_validation_continuation.py tests/security/test_agent_assessment.py tests/integration/test_skill_workflow.py tests/integration/test_contextual_coverage.py tests/agent/test_skill_context_policy.py tests/agent/test_skill_lifecycle.py -q --tb=short` | 227 passed |
| `pyright tests/skills/test_cross_site_scripting_outcomes.py tests/skills/test_xss_parser_boundaries.py tests/skills/test_validation_grounding_contract.py tests/agent/test_xss_returned_code.py` | 0 errors, 0 warnings |
| `git diff --check` | Clean |

These are 816 passing tests in separate responsibility groups, not a full-suite
run. Existing optional Node-unavailable skips remain; Node was available for this
verification. The full repository suite and all live evaluations were not run.
After strengthening the bounded negative, all 14 scripted returned-code cases
were rerun successfully. The invalid-code stop case uses an explicit operator
baseline-plus-one-probe bound; it does not endorse stopping on invalid syntax
while a useful permitted adaptation remains. That final constraint clarification
was checked with a focused rerun of the stop case.

Task-start hash checks preserve all six unrelated dirty files. Of 100 historical
files, 98 stayed byte-identical, including saved sessions, observations, findings,
proofs and run skill snapshots. Two mutable `lan-2000` files changed externally:
`logs/session.jsonl` gained periodic `context_snapshot` events after its `done`
event, and the corresponding profile context Markdown changed. An already-running
Python process was present. This task did not write, restore or resume those files.

## Remaining trade-offs and minimum independent live evaluation

The more explicit failure distinctions add reading/attention cost. Optional
examples reduce main-flow repetition but require a resource read when needed.
General compaction can summarize away a loaded skill; these changes do not alter
context retention. HTMLParser does not implement the full HTML5 tokenizer, and
Node syntax acceptance cannot prove browser reachability, trigger, policy or
execution. Known escaped/double-escaped script states retain their existing
warning rather than acquire a partial runtime parser.

No amount of instruction text guarantees that a model preserves raw bytes,
chooses a useful adaptation or resists early certainty. `lan-700/2000` show that
related advice was already available. Missing browser execution, auth/context,
or unavailable evidence must remain honest limitations. Repeated failure despite
clear available guidance should be reported as a model limitation rather than
met with an ever-growing exception list.

For a future separately authorized evaluation, use six **held-out local HTTP
fixtures**, not these run snapshots or their marker strings: an attribute-context
transition with marker escaping; encoded inert HTML; valid code in an uncalled
function; a handler with a missing event; enforced vs report-only inline policy;
and an ambiguous consumer with genuinely missing evidence. Give each model the
same scoped Candidate and budget. Compare old/new guidance on two fresh seeds
per fixture (24 short sessions), with only the mock HTTP adapter enabled. Keep
the fixture answers outside the model context; do not provide scripted decisions
or a prescribed payload sequence.

Blindly score correct context/transform model, useful prediction and adaptation,
stop justification, false confirmations, early negatives/unresolved stops,
redundant requests and raw-proof fidelity. Inspect code and observations manually
against fixture ground truth. Treat this as a small directional comparison, not a
statistical reliability claim. It can assess HTTP reasoning, not browser execution;
execution claims would need a separate supported browser evaluation. No live
evaluation was executed as part of this task.

Parser/policy grounding: the distinction between outer HTML parsing and script
processing follows the [HTML tokenizer](https://html.spec.whatwg.org/multipage/parsing.html#tokenization)
and [script processing](https://html.spec.whatwg.org/multipage/scripting.html#script-processing-model).
Policy assessment preserves the distinction between enforcement and reporting in
the [CSP framework](https://www.w3.org/TR/CSP3/#framework-policy).
