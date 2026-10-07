# Agent-assessed evidence and conclusion authority

Native tools collect evidence. The runtime checks its provenance, integrity,
owner, request identity, scope and execution completeness. The Agent applies the
loaded skill to interpret controls, repeatability, alternative explanations,
impact and severity. Admissible evidence does not establish vulnerability truth.

`workflow.record_result` accepts both terminal outcomes without calling a class
verifier. Production startup does not register SQLi verifiers. The legacy
`VerifiedResult`, verifier functions and certificate readers remain available for
compatibility and explicit diagnostics; new assessments do not depend on them.

## Attempt and submission contract

1. `start_validation` opens an opaque durable attempt bound to the current
   session, objective, Candidate identity, target revision and execution epoch.
   Generic fallback still requires its controller-admitted probe context and
   bounded proposal. Declare its hypothesis, criteria and limitations in
   `assessment` at start; missing criteria cannot produce a terminal conclusion.
2. Collect actual source IDs through native HTTP/broker execution or selected
   scoped browser/Burp capture import. A summary file or stdout saying
   “confirmed” is derived interpretation, not evidence that a remote request ran.
3. Register immutable redacted proof using `record_evidence`. Optional
   `observation_ids` retain selected source snapshots and persist the artifact's
   primary-parent association. Sources must belong to this attempt.
4. Submit `attempt_id`, `observation_ids`, `evidence_refs`, the native outcome
   and a bounded `assessment` containing hypothesis, criteria, limitations,
   observed_impact and severity. A negative additionally requires
   `completed_attempt=true` for the declared bounded scope.

`related_requests` declares up to 16 exact method/URL/role associations on the
same origin: baseline, control, trigger, readback, cleanup or auxiliary.
Associations must be unambiguous: duplicate method/URL declarations are rejected
before an attempt opens, and persisted ambiguous declarations are inadmissible.
Required steps need completed sources in a terminal manifest; cleanup defaults
optional and still needs separate action authority. Runtime checks that the required
execution exists, while the Agent judges whether the controls are meaningful.
Optional excerpts bind a primary source ID, byte range and SHA256 of that range
in its retained redacted body. They cannot substitute for their parent source.

Invalid IDs, substituted bytes, wrong session/epoch/owner/attempt, wrong origin
or request, changed identity and stale submissions are rejected before canonical
result/coverage publication. Incomplete required evidence can accompany an
unresolved assessment. Optional partial sources retain their limitations and
cannot substitute for completed primary evidence. The five native unresolved
outcomes remain unchanged; timeout, process/provider error, crash and
budget exhaustion remain separate execution states.

## Source and assessment provenance

HTTP captures record actual method, URL, status, bounded redacted body and
allowlisted response headers, local elapsed time, cap/completeness, request and
response hashes, and snapshotted attempt ownership. The retained envelope has a
separate canonical hash; raw-byte hashes are not hashes of redacted derivatives.

Shell, command-plugin and MCP output captures identify their actual producer and
invocation receipt where present. They are supplemental process output. A web
terminal assessment also needs native HTTP/broker evidence or a declared scoped
capture import. No stdout parser certifies remote exploit success.

Browser/Burp imports have a local import identity and current import association,
with the original bridge source and local receive time. Original owner, receipt
and request/response hashes remain unknown. Import hashes describe only the
selected local redacted representation; source-reported timing/completeness do
not become native execution provenance. Unknown completeness is unresolved. Import permission or
origin filtering does not authenticate an actor. Raw request credentials are
not promoted into the retained representation.

New results use assessment contract/binding version 2 and controller-assigned
`assessment_source=agent`, plus exact result/attempt IDs, Candidate binding,
artifact metadata and a bounded redacted source manifest. Model-supplied authority
fields are rejected. An unresolved assessment without execution records Agent
provenance and leaves its attempt/source ownership absent. Public tool results
summarize manifests without traffic bodies. Workflow schema version 8 persists
attempts and source associations.

`/review-result` is optional. Real operator ALLOW_ONCE creates a distinct operator
revision that supersedes the reviewed result. It grants no execution rights and
cannot repair missing or wrongly owned primary evidence. Tickets, full stale
snapshots, evidence reads, policy/scope checks and private staging remain in the
path. Workflow mutation and session checkpoint share a lock; the staged revision
is published only after a successful checkpoint and final guards. Failed or
cancelled staging drains pending writes and restores/reconciles the coverage
projection from canonical state. This is not a cross-file ACID transaction.

## Findings, coverage and resume

Coverage, requested goals and production completion resolve accepted structured
assessments. `ConfirmFindingTool` requires the latest accepted confirmed revision,
intact artifact/source bindings, current request identity, and completed coverage
synchronization. It adopts assessed severity/impact rather than caller prose.
Reports bind result ID, attempt ID, source and version. Exporting a historical
report cannot treat a stale structural binding as a current Finding; export
records structural admissibility without opening proof contents. Retrying a
historical Candidate report against a new revision cannot mark that report as
the new Finding. Collision-safe storage and same-revision retries retain existing paths
and modes. CWE classification remains a separate responsibility.

Selected source storage is bounded to 256 entries / 16 MiB. Each result manifest
is bounded to 32 sources / 2 MiB; retained bodies stay at most 64 KiB. These
redacted snapshots allow an accepted assessment to survive live-store eviction.
Resume seals active attempts as interrupted and restores no receipts, grants or
transient probe contexts. A new attempt cannot adopt historical source ownership.

Legacy results, observations, certificates and Markdown Findings remain readable.
Missing provenance stays unknown. Version 1 result fingerprints, review snapshots
and confirmation bindings are unchanged. A uniquely matching legacy certificate
can support the old compatibility contract and a labeled provenance view retaining
its original source string. Ambiguous repeated legacy records are not all assigned
the same certificate. Loading does not relabel their persisted fields as Agent
assessments. Historical bookkeeping alone is not current conclusion authority.

## External evaluator integration

No Scenario 1 correctness evaluator adapter exists in this repository. The
existing internal benchmarks do not evaluate this architecture's vulnerability
correctness. A future external harness should join session/objective/Candidate,
result/attempt identity and provenance, separately record execution completion,
compare the adopted outcome against independent truth, and distinguish unresolved
outcomes from false positives/negatives. It must not inject truth into runtime
admission or use a certificate as its correctness label. No accuracy improvement
or benchmark result is claimed by this migration.
