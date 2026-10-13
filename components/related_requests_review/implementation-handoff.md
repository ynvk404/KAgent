# B + A + C implementation handoff

**READY FOR INDEPENDENT VERIFICATION** for the related-request contract patch.
All 106 focused acceptance tests pass. The same 910-test responsibility group
has 908 passes and the same two verified baseline failures before and after
the patch. Configured Pyright has zero errors. The broader suite is not green;
the failure assessment below explains its limits.

## Baseline and ownership

- Repository: `/mnt/d/DOANTOTNGHIEP/kagent`. The lower-case path supplied in the
  corrections resolves to the same repository in this workspace.
- Baseline HEAD: `29c4f92f91d61e7a669af34d0d3d18e05f8767db`. This was observed,
  not imposed as a prerequisite or reached by resetting the repository.
- Initial `git status --short`, tracked diff and staged diff were empty.
  There were no preexisting modified files or unrelated hunks to preserve.
- All production/test hunks in `patch.diff` belong to this task. Existing tests,
  skills, providers, permission code and state persistence code were not edited.
- This directory is an intentional, user-requested repository handoff artifact.
  It remains untracked and appears as `?? components/related_requests_review/`.
  Its manifest records source/test hashes, artifact hashes, hunks, commands and
  final Git status. It is not a restore/delete instruction.
- No reset, staging, commit, push, package installation, live target HTTP,
  paid/external model calls, or BenchmarkJava run was performed.

## Production changes

1. `src/tools/workflow/workflow_tool.py`: tool description and flat schema now
   explain Candidate-only admission, optional supplementary associations,
   uniqueness, observations versus associations, existing required defaults,
   Generic prerequisites and conditional argument repair. The schema includes
   primary-only and POST `/comments` / GET `/comments/123` readback examples.
   Only duplicate association exceptions receive the new error envelope.
2. `src/workflow/assessment.py`: a small `ValueError` subtype identifies a
   duplicate and its first/conflicting array indices. The existing association
   checker raises it at the existing rejection point. It stores no request
   URL, body, headers or credential material.
3. `src/agent/action_guidance.py`: one conditional line recommends
   `start_validation(candidate_id)` when the Candidate covers the primary
   request. Every preexisting guidance line, including Available, Recommended,
   Excluded and lifecycle guidance, is preserved verbatim.

B reuses the existing Candidate-only implementation, resolver and admission
checks. It does not reconstruct `start_validation`, infer executable context,
send probes, grant permission, confirm a vulnerability or persist a finding.
No skill edits were necessary; matching validation contracts and allowed-tools
metadata were read for SQLi, XSS, access control, CSRF, SSRF and SSTI.

The uniqueness key remains the existing normalized method plus the existing
resolved/redacted URL. Role, required, body, payload and identity do not create
another association under that key. Actual distinct methods, paths and queries
remain admissible under the existing contract. There is no second normalizer,
`uniqueItems`, union/conditional schema construct, strict mode, auto-drop,
auto-merge or role/requirement selection.

## Examples and Agent-visible error

When the Candidate covers the primary request and current prerequisites hold:

```json
{"action":"start_validation","candidate_id":"<returned candidate.id>"}
```

For an already registered Candidate POST `/comments`, retain a supplementary
readback obligation as follows:

```json
{"action":"start_validation","candidate_id":"<returned candidate.id>","related_requests":[{"role":"readback","method":"GET","url":"/comments/123"}]}
```

`required` defaults to true, except cleanup defaults to false. Explicit values
remain authoritative. Cleanup still needs separate authorization. A single
legacy explicit primary declaration and `related_requests: []` remain valid.
Omission on an active attempt preserves its previously declared associations;
explicit changes, including clearing them, still require closing/retesting.
Session loading retains historical declarations while interrupting execution
ownership; it does not borrow an interrupted attempt's observations.

The duplicate result is an `error:`-prefixed string followed by a JSON envelope:

```json
{
  "ok": false,
  "error": {
    "code": "DUPLICATE_REQUEST_ASSOCIATION",
    "action": "start_validation",
    "field": "related_requests",
    "indices": [0, 1],
    "message": "ambiguous duplicate related request method/URL association; declare each method/URL once with one role and requirement, or use distinct actual request URLs",
    "repair_hint": "See the complete actual tool text in agent-visible-example.json."
  }
}
```

The abbreviated hint above is explanatory, not a claimed runtime response.
[agent-visible-example.json](agent-visible-example.json) contains the complete
actual production Agent tool-result event and the tool message sent in its
next `ChatRequest`, captured by a deterministic offline SnapshotClient. The
hint requires preserving supplementary obligations and restating conflicting
intent, prohibits invented URLs/merges/HTTP argument repair, and permits
Candidate-only repair only under the stated conditions.

The tool-result has `status=error` and the existing `error_kind=workflow_state`.
The text prefix/classification remain compatible with current string consumers
and UI recovery. The semantic code distinguishes this argument rejection from
scope, ownership, prerequisite and active-attempt failures without reclassifying
all workflow failures. Neither `retryable` nor `state_changed=false` is emitted.
The envelope is in tool text, not hidden metadata. Agent/outcome transport and
retention production code required no changes.

## Verification

Exact executable commands are in [commands.json](commands.json); all commands
use `venv-linux` and the repository's existing configuration.

| Run | Result | Log |
| --- | --- | --- |
| Pre-edit responsibility-group baseline | 908 passed, 2 failed, 0 skipped | `logs/baseline-tests.log` |
| Pre-edit configured Pyright | 0 errors, 0 warnings, 0 informations; exit 0 | `logs/baseline-pyright.log` |
| Focused acceptance, final | 106 passed, 0 failed, 0 skipped | `logs/focused-tests.log` |
| Post-edit same responsibility groups | 908 passed, 2 failed, 0 skipped | `logs/broader-tests.log` |
| Post-edit configured Pyright, final | 0 errors, 0 warnings, 0 informations; exit 0 | `logs/pyright.log` |
| Final diff checks | No whitespace errors, including new test files | `verification-results.json` |

The responsibility group covers workflow dispatch/arguments/projection,
assessment security, evidence integrity and reads, Generic/bounded probes,
findings, workflow state/session persistence, Agent request preparation,
outcomes/offloading/compaction, provider schema interoperability, and the
existing UI workflow recovery tests. Live/external-model semantics were not
changed. HTTP transport in selected tests is mocked; no live tests were run.

Three new test modules provide focused acceptance coverage:

- `tests/tools/test_related_request_associations.py`: real skill registry and
  validator routing for SQLi, XSS, IDOR, CSRF, SSRF and SSTI; Candidate-only,
  empty list, legacy explicit primary, distinct method/path/query; role,
  required and identical duplicates; method normalization, relative/absolute
  and dot-path resolution collisions, redaction collisions; original indices;
  state/revision/status/active-attempt atomicity and unchanged arguments;
  required defaults, exact-origin rejection and explicit retest requirements.
- `tests/security/test_related_request_evidence.py`: distinct captured POST
  payload/principal variations remain observations; active omission preserves
  required supplementary evidence; saved valid assessments remain usable and
  malformed duplicate assessments remain inadmissible; Candidate-only and
  explicit proposals cannot bypass Generic trusted-context prerequisites.
- `tests/agent/test_related_request_contract.py`: error code/indices/hint reach
  the actual next Agent request in streaming and non-streaming; explicit
  corrected arguments succeed without HTTP; failed status survives retention,
  session serialization and prior-turn elision; full compaction does not
  synthesize success or change canonical workflow state; all four supported
  provider encodings retain the schema guidance and error text; a mocked 503
  transport retry with an unchanged request preserves both.

Existing tests additionally passed guards for required missing/truncated/
incomplete/unfinished evidence, immutable proof, source hash/provenance,
Candidate/session/objective/epoch/attempt/target binding, finding eligibility,
unresolved outcomes, selected-source resume and separate cleanup controls.
These assertions exercise production dispatch with synthetic fixtures and
temporary isolated stores, not a personal session or `~/.kagent` fixture.

Development logs are retained and classified in the results file. Initial
failures were corrected assumptions in the new tests (resolved endpoint,
queued registration, interrupted restore, rendered summary format) and a
duplicate test-module basename under pytest's existing import mode. Existing
tests were not weakened, skipped or edited to make the result pass.

## Verified baseline failures and impact

Both baseline and post-edit runs fail exactly these unchanged tests:

- `tests/llm/test_workflow_action_projection.py::test_transport_retry_keeps_encoded_projection_snapshot[anthropic]`
- `tests/llm/test_workflow_action_projection.py::test_transport_retry_keeps_encoded_projection_snapshot[gemini]`

The mocked first 503 mutates `ChatRequest.tools` from a direct-objective view
to a whole-target view. Both providers encode inside `_chat_once`, so retry
re-encodes the mutated request and the two request bodies differ. This is an
existing transport snapshot defect, not a harmless failure or a new
regression. It prevents claiming frozen projection identity when a caller
mutates tools during those providers' retries. No provider fix was attempted.

It does not block the mandatory B + A + C acceptance demonstrated here:
portable encoding with every provider, actual delivery of the failed tool
text, unchanged-request transport retry, workflow atomicity and evidence
guards are independently covered and pass. The new schema uses descriptions
on existing fields; it does not change projection enums, request snapshots,
provider transport or permission enforcement. READY applies to this patch's
independent verification, not to general provider snapshot reliability or a
claim that the whole suite passes. No unresolved new regression was found.

## Limits and next-session inputs

- There is no association-specific enforced retry counter. A successful
  scripted argument correction is not evidence of bounded semantic retries.
  Existing playbook one-correction guidance, malformed-call retries and Agent
  outer iteration limits remain unchanged; no retry controller was added.
- Full compaction summarizes prior tool messages. The test proves that it
  preserves canonical queued/no-attempt state and does not turn this rejection
  into a successful receipt; it does not promise permanent retention of every
  historical error envelope after full compaction.
- The SQLi playbook still requires reproducible TRUE/FALSE pairs for its
  boolean-based technique. Current assessment code checks source admissibility
  and bounds/redacts `confirmation`; it does not independently enforce all
  boolean-pair/technique semantics. This existing limitation is not fixed or
  generalized to other techniques/classes by this patch.
- Observation-role ledger behavior, request identity, host case/default-port/
  fragment handling and redaction collision semantics remain outside scope.
  Redaction collisions still reject duplicate association keys rather than
  distinguish identities with hidden secret material.
- No live model/target run, comprehensive scenario/E2E harness, full repository
  pytest suite, or BenchmarkJava was run. Scenario/integration verification is
  the next session's work. No claim is made that a live LLM always selects
  correct arguments.
- Read this directory, `manifest.json`, `patch.diff`, current source/tests and
  logs directly. The handoff does not depend on `/tmp` investigation artifacts
  or prior conversation state. Review known provider snapshot failures as a
  separate defect without broadening this patch silently.
