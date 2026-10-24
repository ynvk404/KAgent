# lan-10: HTTP replay decision trace

Investigation is offline. No target/provider requests are part of this work.
lan-09 and lan-10 are read-only inputs; all reproduction uses synthetic captures
and `httpx.MockTransport`. Existing worktree edits are outside this change,
including the earlier proof-parent guidance in the SQLi playbook.

## Evidence and limits

Verdict: **FIXED — OFFLINE VERIFIED**, for the demonstrated model-facing
construction/guidance gaps. Validator rejection and unmatched TUI history are
expected behavior. This is not a claim of guaranteed future LLM compliance.

Session: `03136011-c5c9-4697-82cc-3d58738ed109`, objective
`5778bc63edf9415b866df2d2536c091e`, mode `direct`, candidate
`cand_7eb30a26b8a7a2761cdb`, attempt
`attempt_b58b574d0a584a669a0eb8e7e0c8db15`.

Primary historical sources under `experiments/scenario3/runs/lan-10/`:

- `logs/session.jsonl`: 717 original records at investigation entry; `seq`
  equals the 1-based line number. Periodic snapshot appends are accounted for below.
- `profile-home/.kagent/sessions/<session>.json`: saved messages, tool arguments,
  system prompt, loaded Skill with activation metadata, workflow and findings.
- `project/.kagent/observations/<session>.json`: effective request previews,
  retained response bytes and provenance for eight observations (one imported
  capture plus seven executed HTTP responses).
- `profile-home/.kagent/context/<session>.md`: periodic conversation snapshot,
  not an outbound provider request. The saved snapshot is later than the error.
- `project/skills/sql-injection/SKILL.md`, registered proof and finding files.

Neither JSONL nor `logs/kagent.log` archives the per-request tool schemas,
complete transient request injections, encoded provider body, or model reasoning.
The session records no reasoning content for either decision. It is therefore
impossible to identify the model's internal reason or prove the exact historical
provider-visible payload byte-for-byte from these artifacts. Current source and
offline projection establish the application's construction path, not an archived
wire payload. No logged source revision/hash proves the entire historical runtime
equals the checkout. The historical Skill and system message themselves *are*
available; their text can be checked independently of current source.

## Decision trace: before the first invalid call

| seq | Evidence | Meaning |
|---|---|---|
| 20–21 | `browser_capture_get` reads `burp:burp-9f6772f7e64fbee7` with its bound baseline reference | Capture context was obtained, not guessed from endpoint names. |
| 25–27 | `load_skill(sql-injection)`, successful result and activation | SQLi is the active validation playbook. Its saved activation fingerprint is `db0a6b15df64a6ace5ccda29e0e48ec4bbd0cd1d247ea04d78bf5bb606dbd9d9`. |
| 32–39 | Two pages of `payloads.txt` | SQL payload examples, not examples authorizing replacement transport headers. |
| 60–68 | Candidate with selected `source_ref` and `baseline_request_ref`; validation starts | Primary endpoint/input association exists. No HTTP permission follows from selection alone. |
| 90–91 | `http(phase=recon, candidate_id, mutation_value="baseline-probe-sqli-cand", input_path="/email")` → 401 | A replay mutation, not the original captured email value unchanged. |
| 97–98 | Read retained baseline observation | No new HTTP response. |
| 132–133 | Same replay mode, `mutation_value="'"` → 500 | Captured headers retained, including `Accept-Encoding: gzip, deflate, br`. |
| 139–140 | Read quote observation | Retained body is unreadable; readback does not supply a Brotli decoder. |
| 143–145 | Context diagnostic, request admitted, SQLi planner recommendation | Estimated total 48,944 tokens; reduction achieved 0; under estimated hard input limit 602,931. |
| 146–176 | Assistant says the body is Brotli-compressed and proposes `Accept-Encoding: identity` | This is the stated immediate motive, not evidence about hidden model reasoning. |
| 177–178 | Mixed replay/direct arguments rejected with `invalid_args` | No HTTP status, observation or recovery receipt for this call. |

The stored system message explicitly says to use
`http(candidate_id, mutation_value, phase)` when a live capture exists, and to
report unavailable/incomplete capture rather than rebuild authenticated traffic
from memory. The historical SQLi Skill, served body lines 494–523, says to preserve
the original structure, change only the candidate input, keep session/CSRF/content
headers, and leave every other POST/JSON field/header unchanged. Its selected-Burp
section also preserves the capture's endpoint/method/input identity.

These instructions do not conflict with the replay prohibition. The generic
phrase “build the equivalent baseline” does not explicitly distinguish native
direct request construction from capture replay; no saved Skill example describes
a legal encoding change or the response to this particular rejection. Prior HTTP
calls in this turn demonstrate the correct replay argument form. The historical
corpus provides SQL expressions and a conditional shell/curl output example;
none licenses `candidate_id` plus `headers`.

There is no compaction event in the 717-record trace; saved memory is null.
`load_skill` has a preserve reduction policy. Current `_project_skill_bodies`
keeps the active version and retires superseded activations, rather than cutting
paragraphs from an active Skill. At seq 143 reduction was zero. These facts do
not support a claim that the replay rule was lost. A long context may affect
attention, but that causal claim cannot be verified offline. At seq 181, before
the direct fallback, the guard reports reducing 1,804 characters; the artifacts
do not identify an exact outbound message diff for that reduction.

## Model-facing construction path

Current path, checked independently of source-level descriptions:

1. `Registry.as_llm_tools()` exports `HTTPTool.description()` and `schema()`.
2. `Agent._workflow_request_view()` filters tools by active capabilities and
   invokes `ActionView.project_tools()`. The latter projects only `workflow`;
   it does not remove HTTP field descriptions or choose a request mode.
3. `_prepare_turn_request()` refreshes the view, admits/reduces context and
   projects active Skill bodies before the client is invoked.
4. `OpenAIClient.encode_request()` for DeepSeek copies dictionary tool specs
   into `body.tools`, without stripping the HTTP description/schema. It does
   not add `strict` or enforce generation-time schema constraints.

Before this patch the flat HTTP schema already described `candidate_id` as
excluding replacement `url/method/headers/body`; the top-level description only
said it replayed baselines. The `headers` property had no mode-specific description.
The schema had no structural mutual-exclusion constraint: a JSON Schema validator
accepted the seq-177 combination, despite the field description and runtime
prohibition. Flat shape is intentional elsewhere in this provider integration;
`tests/llm/test_workflow_schema_deepseek.py` explicitly protects a flat Workflow
contract. There is no evidence that a new `oneOf`/`not` contract is supported or
generation-enforced by every configured provider. Do not equate schema validity,
provider acceptance, or model compliance with runtime authorization.

## Decision trace: self-correction and effective request

The exact rejected arguments at seq 177, call
`call_00_20ltRyMCanLWwxrFGdNh4224`, are:

```json
{
  "candidate_id": "cand_7eb30a26b8a7a2761cdb",
  "headers": {"Accept-Encoding": "identity"},
  "input_path": "/email",
  "mutation_value": "'",
  "phase": "validation"
}
```

Only `headers` is a forbidden replacement field in this call. The other four
arguments form a valid quote mutation against the bound capture. The error is
raised by `_resolve_baseline`, reached through Registry pre-dispatch validation,
before request approval, resource reservation and send. Runtime behavior is the
expected rejection, not an HTTP 500, permission refusal or failed network send.

The next tool call is seq 184, `call_00_CCgsoxUP8jHQZGknuNO20607`:

```json
{
  "body": "{\"email\":\"'\",\"password\":\"[REDACTED]\"}",
  "headers": {"Accept-Encoding": "identity", "Content-Type": "application/json"},
  "method": "POST",
  "phase": "validation",
  "url": "http://juice.lab:8081/rest/user/login"
}
```

This is a syntactically valid **direct** request. Secret values above are redacted
representations, not executable replacements. Equality of redacted passwords
does not prove equality of the original secrets. The retained request metadata
records 29 original body bytes for the captured quote mutation and 31 for the
direct quote request, so byte identity cannot be claimed.

Removing `headers` from seq 177 repairs its argument form and preserves replay
identity; it does **not** accomplish the requested change to identity encoding.
The identical quote replay already executed at seq 132, so resending it solely
for readability has no established value. Reading retained bytes also cannot
decode an unsupported encoding. These are separate request-validity and response
readability questions; the repair must not manufacture an equivalent success.

| Field | Selected capture / replay | Direct followup | Attribution |
|---|---|---|---|
| Origin, method, path | `http://juice.lab:8081`, POST, `/rest/user/login` | Same | Model explicitly supplies direct method/URL. |
| Input | Captured email `ss`; quote replay changes it to `'` | `'` in reconstructed JSON | Model supplies a whole replacement body. |
| Password | Captured non-target field | Redacted in saved direct arguments | Original equality unverified; body byte counts differ. |
| Accept-Encoding | `gzip, deflate, br` | `identity` | Explicit model change. |
| Content-Type | `application/json` | `application/json` | Explicit model field retained. |
| User-Agent | Captured Chrome UA | `KAgent/0.2.0` | Model omits it; direct adapter adds its native default. |
| Accept, X-User-Email, Origin, Referer, Accept-Language, Cookie | Present in capture and captured quote preview | Absent from model arguments and effective preview | Model omissions; adapter does not strip these supplied fields. No selected-capture inheritance in direct mode. |
| Host / Content-Length / Connection | Captured framing/hop metadata | Host and length regenerated; Connection absent | Expected `origin_headers` framing/hop filtering and HTTPX request construction. |
| Baseline binding | `CaptureSource`, bound baseline reference | No `baseline_request_ref` in observation source details | Model drops `candidate_id` and selectors; direct builder has no capture source. |

The direct request still belongs to the active candidate/attempt as an observed
primary method/URL. That observation ownership is **not** captured-request
provenance or proof of request equivalence. Runtime does not silently convert the
rejected replay: it executes the model's next, separate direct call through its
normal permissions. Direct requests cannot inherit the captured credential grant.

Seq 185 returns HTTP 500 with an HTML SQLite/Sequelize diagnostic in
`obs_c0861b7c8cbf4250afb4804ba9f28cfe`. Seq 191 and 198 read retained ranges.
The boolean HTTP calls are **222, 243, 262, 269** (results 223, 244, 263, 270). All use the
direct request template with identity encoding. They are further probes, not
equivalent retries of seq 177.

KAgent currently has no captured-replay option for changing a non-candidate
header. `profile`, browser context and `auth_context_ref` do not implement one;
candidate mutation can change the named input only. With email as the candidate
input, `Accept-Encoding` cannot be changed through `mutation_value`. Retained
readback accesses stored bytes but does not add codecs. Current `venv-linux`
HTTPX decoders are identity/gzip/deflate; the retained Brotli response corroborates
the triggering readability problem but does not prove the historical dependency
set. No decoder/dependency change is required to explain either decision.

To change encoding while preserving capture provenance, an operator can provide
a fresh captured request with that encoding, using the normal capture ingestion,
baseline binding and credential review. An active attempt's request context is
immutable: a new baseline requires honest closure and the existing retest/new
attempt path where applicable, not transplanting old refs or old evidence. This
is not an automatic repair for lan-10 or permission to send another request.

## Root-cause matrix and fix-layer decision

| Hypothesis / layer | First decision (seq 177) | Second decision (seq 184) | Evidence / decision |
|---|---|---|---|
| Model tool/argument choice | Confirmed mixed-mode call | Confirmed reconstruction and omissions | Directly logged arguments. Hidden reasoning unknown. |
| Contract absent from source | No | No | Existing candidate field description and system replay rule. |
| Contract removed in model projection | Not demonstrated | Not demonstrated | Current projection/encoder preserves HTTP spec; exact historical outbound body is missing. Regression must inspect actual projected/encoded request. |
| Flat-schema ambiguity | Confirmed structural gap; not proven sole model cause | Both modes remain independently available | Add mode descriptions/examples near the decision; do not claim strict generation enforcement. |
| Contradictory Skill | No explicit contradiction | Reconstruction violates preservation rule | Generic baseline wording lacks native mode/encoding examples; clarify it. |
| Context loss | Unsupported at seq 177 | Reduction logged, exact removed text unknown | No compaction; zero reduction before invalid call; active Skill retained in session. Do not invent a causal explanation. |
| Feedback gap | Does not explain the first call | Confirmed absence of an identity-preserving recovery route | Original error says only what is forbidden. Add bounded repair/recapture/stop guidance. |
| HTTP validator defect | No | No malformed direct arguments | Preserve rejection and all effective-request/permission checks. |
| Adapter strips capture fields | No dispatch | No: missing headers were already absent from model arguments | Native UA/framing defaults are expected; do not change transport defaults. |
| Workflow request-construction gap | No ready-to-use request recipe in transient context | No capture-preserving encoding override | Add a concise current-capture recipe to the model-facing request projection; do not introduce a new mutation capability or mode conversion. |
| TUI recovery defect | No receipt for invalid call | Different args, effective request, provenance | Keep unmatched; do not use finding success as a recovery receipt. |

Compared options before finalizing the patch:

- More pre-dispatch validation cannot prevent this call from reaching the model's
  output: the existing boundary already rejects it before any network effect.
- Adding `oneOf` or splitting HTTP into new public tools changes a shared provider
  interface, without archived proof of a projection defect or evidence of
  cross-provider support/enforcement. The flat shape remains; its descriptions
  are sharpened. Offline tests must not claim LLM compliance from prose assertions.
- Automatic header rewriting, implicit direct fallback or borrowing capture
  credentials would change the authorized effective request and provenance.
- A new override/clone API or workflow-wide ban on direct primary requests is
  a larger execution-policy change. This trace does not establish its correct
  semantics for independent direct work. It is not needed to preserve rejection.
- **Chosen minimal change:** current-capture request guidance in the actual Agent
  projection (prevention at the decision boundary), explicit mode/encoding
  descriptions and examples, and actionable identity-preserving rejection feedback.
  Keep validator predicates, TUI correlation and request constructors unchanged.

This addresses the demonstrated interface/guidance gaps. It cannot guarantee
that an arbitrary LLM will never ignore instructions. Offline prevention checks
prove that the current recipe/contract reaches the encoded model request before
the first tool decision; runtime regressions prove invalid combinations have no
effects even if emitted. No live-model behavioral claim is made.

## Final state and recovery

Seq 178: `invalid_args`, no receipt, no HTTP observation. UI `_repairable` only
allows native HTTP connection failures with a retry-safe receipt into its recovery
path. Full argument hashes and matching effective-request receipts are also
required. Seq 184 changes the argument identity, mode, header set and provenance.
Its successful completion receipt is for its own request; it cannot recover 177.

Seq 303–304 registers `ev_7939cdce9c62c88b5eb7`; 310–311 accepts confirmed result
`result_3256775a876b4956b77e08d3a89c9324`, with seven primary observations and
`coverage_sync=synced`. Seq 326–327 persists the finding. These are separate
workflow/evidence milestones. The report remains historical and unchanged; this
investigation does not re-adjudicate the finding's severity or other claims.

The supplied TUI ending, “Turn completed; 1 finding saved; 1 operation error
without a matched retry”, correctly distinguishes workflow completion from
unrecovered operation history. The JSONL ends with a normal final-response stop;
it does not archive a rendered UI screenshot. Regression uses the real reducer
and native receipts, not a successful finding as inferred recovery.

## Offline verification

Changed files belonging to this investigation:

- `src/agent/agent.py`: current-capture recipe in the actual, refreshed request
  projection, emitted only for an available bound baseline and advertised HTTP
  capability. No request is constructed or dispatched by this guidance block.
- `src/tools/http/http_tool.py`: mode descriptions on the tool/headers/body and
  actionable rejection feedback. The exclusion predicate is unchanged.
- `skills/sql-injection/SKILL.md`: native request-mode examples, encoding limits
  and identity-preserving recovery/recapture guidance. Earlier proof-parent
  worktree edits are preserved.
- `tests/security/test_http_replay_contract.py`: 30 deterministic cases across
  Direct and Whole-target, including the admitted request before the first HTTP
  decision, stream/non-stream DeepSeek encoding, feedback visibility, rejection
  before permission/budget/send, exact effective request/cookie/baseline retention,
  stale capture availability, retained body readback, direct fallback unmatched,
  and native connection-retry receipt matching. Changed payload, capture/header
  binding or missing completion receipt cannot manufacture recovery.
- This investigation report.

The synthetic replay fixture uses gzip to exercise supported bounded decoding
without installing dependencies. It does not claim to decode the historical
Brotli response or preserve its bytes through a direct reconstruction.

Before the HTTP guidance patch, the stabilized 26-case regression set produced
**12 failed / 14 passed**: ten missing-feedback cases and two missing header-mode
descriptions, with existing replay/recovery behavior passing. Separately, running
the two admitted-request tests with only `Agent._workflow_request_view` restored
from task-entry HEAD **in memory in an isolated test process** produced
**2 failed / 28 deselected**, because neither mode received the new capture
recipe. No repository or experiment file was reverted by that check.

After patching: **30 passed** in the focused file. Broader verification:

```bash
venv-linux/bin/python -m pytest -q \
  tests/tools/test_http{,_replay,_context}.py \
  tests/tools/test_request_builder.py \
  tests/tools/test_systemic_tool_contracts.py tests/tools/test_lan08_contracts.py \
  tests/security/test_http_replay_contract.py \
  tests/security/test_captured_http_replay.py \
  tests/security/test_http_{grants,yolo_session,body_fidelity,observation_reader,readback_lifecycle,invocation_lifecycle,semantic_progress}.py \
  tests/security/test_evidence_recovery_contract.py \
  tests/security/test_proof_parent_feedback.py \
  tests/ui/test_tool_recovery_acceptance.py tests/ui/test_lan08_audit.py \
  tests/agent/test_native_recovery_receipts.py \
  tests/agent/test_workflow_request_preparation.py \
  tests/integration/test_http_pipeline_regressions.py \
  tests/integration/test_burp_offline_audit.py \
  tests/skills \
  tests/llm/test_workflow_schema_deepseek.py \
  tests/llm/test_workflow_action_projection.py --tb=short
venv-linux/bin/pyright
git diff --check
```

Results: **1,035 passed**; Pyright **0 errors / 0 warnings**. The focused
30 cases also passed after the final budget assertion. Full repository suite,
live providers/models and real target tests were not run.

An entry SHA-256 manifest covered all **45 files** in lan-09 (20) and lan-10
(25), including ignored logs. Final comparison found 43 unchanged files, no
added/missing files, and two periodically updated files: lan-10's JSONL and
context Markdown. The JSONL's first **717 records hash exactly to its entry
hash**; appended records 718–720 are solely `context_snapshot` at
03:20:30Z, 03:25:30Z and 03:30:30Z. The context header reports a periodic
five-minute snapshot, updated to 03:30:30Z. These are ongoing runtime snapshot
writes, not investigation edits; no runtime was stopped or history restored.
Historical session JSON, observations, permissions, coverage, Skill copies,
proof snapshots and both finding files retain their entry hashes. The report
does not misrepresent the live snapshot files as frozen during investigation.

Pre-existing edits to workflow/evidence files and the separate proof-parent
investigation/test remain untouched. No package installation, commit or push.
