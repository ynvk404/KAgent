# Safe worker handoff audit — C2 through C5

**Audit + design + offline verification only. No production changes.**
HEAD: `772aea42d559fc544a826b8117f463d81e9e003a`.
The C1 and Planner patches present at audit start remain intact. This report
uses the new request's numbering: C2 FileWrite, C3 evidence, C4 finding
post-read, C5 summary. It does not use the older combined checkpoint numbering
in PERSISTENCE_IMPLEMENTATION.md.

| Boundary | Verdict | What is ready / what is missing |
|---|---|---|
| C2 FileWrite | **BLOCKED** | Needs explicit authorization/admission semantics for a worker and descriptor-bound resource use. Both a naive worker race and an existing final-check pathname race were reproduced. |
| C3 evidence snapshot/read/verify | **BLOCKED** | Needs read-admission semantics, source/resource consistency and failure-safe immutable publication. Storage-only work on already captured bytes can be isolated, but that does not settle source-read authority. |
| C4 finding post-read | **READY TO IMPLEMENT** | Extend the existing worker transaction to return the canonical path and detached parsed Finding; retain the existing cancellation handler, shared lock and controller-side finalization. Tested candidate passes stale-result, cancellation and read-failure/retry probes. |
| C5 summary | **READY WITH CONDITIONS** | Post-publication fsync and passive preparation/read phases can be offloaded with joining and revalidation. Moving replace itself requires a workflow ownership reservation or an explicit publication contract. That commit phase is not ready. |

These verdicts are design readiness, not an implementation or live-validation
verdict. Four responsiveness XFAILs remain. No live Burp/LLM correlation or
natural WSL filesystem latency was measured.

## Scope and evidence classification

Reviewed the repository instructions, current diff, both prior reports, the
mounted Textual reproduction, the four production boundaries, their direct
call sites, registry dispatch, ExecutionPolicy receipts/reviews, relevant
workflow locks and focused tests. The report is a review of the earlier design;
there was no second agent or separate human reviewer.

The new probe module is
`tests/security/test_persistence_handoff_audit.py`. It uses fresh controlled
`/tmp` directories and denies socket connect/connect_ex and getaddrinfo, including
swallowed violations. A worker hold is bounded by five seconds and released in finally;
workers are joined before fixture teardown.

**A passing observation test means the reported behavior was reproduced.**
`HANDOFF_AUDIT` records separately label `PRODUCTION` versus `DESIGN_ONLY` and
`PASS`, `FAIL` or an inconclusive contract outcome. The production code has
not been changed to make these probes pass. Failed design probes are not
reported as production defects. They are rejected alternatives. No existing
test/oracle/XFAIL was changed in this audit.

## A. Boundary safety matrix

| Dimension | C2 FileWrite | C3 evidence | C4 finding save | C5 summary export |
|---|---|---|---|---|
| Current topology | Registry receipt start; async sensitive gate; synchronous filesystem work and final revalidation on loop | WorkflowTool.run owns mutation_lock; source gate can await; capture/redact/hash/publish/checksum are synchronous; permission-aware verify also reads synchronously | Immutable rendered text to existing write-once worker under shared store lock; synchronous read_report after worker; copy parsed fields on loop | Shared store lock; lookup/read/render on loop; private temp preparation worker; loop guard, canonical byte check, destination check, replace, directory fsync |
| Blocking work | resolve/stat/exists, mkdir, write_text/open/truncate/write/close, chmod; path operations inside guards | resolve/stat/is_file, whole read_bytes, redaction/hash, mkdir/chmod, exclusive creation/write, collision readback, recapture, source-claim read | Post-worker read_bytes and Markdown parse; render CPU still on loop | glob/stat/read/parse/link metadata/destination selection; verification read, destination checks, replace, fsync, cleanup; render CPU on loop |
| Authority | ExecutionReceipt binds tool/module/args and file_resource_identity; active review and policy stamp; sensitive read/write decision is nested | Current workflow receipt when bound; exact source/read gate and project containment; local approved_paths only saves duplicate dialogs; managed proofs have require_evidence identity checks | Store itself has no FileWrite receipt. ConfirmFindingTool owns accepted-result/provenance/evidence authorization and finalization | Derivative API has no FileWrite receipt or prompter. Closure binds current persisted workflow result, canonical finding, assessment and endpoint identity; output paths constrained to project |
| New stale windows | After last loop guard, before worker resolves/opens/truncates/creates; queued job can outlive receipt/cancel; old writer can finish last | Before source read after approval; after worker read before controller metadata adoption; later checksum reads with changed policy; source and storage path substitutions | Enlarged disk-wait interval already covered by caller guards; a separately awaited read needs drain and locked ownership; no permission guard belongs in parser worker | Before worker commit after final loop guard; workflow can change while store lock stays held because it is not a workflow lock |
| Snapshot/TOCTOU | Immutable content does not bind the inode/path used by writer; in-place write is not atomic | Source path provenance is not an inode/content lease; capture can mix pre-read size and later digest; snapshot recapture may adopt modified bytes; partial final filename visible | Render before lock is a value snapshot; candidate_id/slug should also be captured before waiting. Parser output must be detached. Store lock does not exclude external file edits | Frozen SummaryContext and artifact records; canonical bytes compared after preparation; final pathname checks are not descriptor-based external CAS |
| Ownership | No per-destination writer lock. Synchronous sections serialize cooperating loop tasks incidentally; approvals can await | One WorkflowState mutation_lock covers its operations; no shared low-level lock for content-addressed storage across states/instances/processes | Project-keyed shared asyncio store lock covers writer and readback, including retries and CWE mutations | Same project store lock covers lookup/preparation/validation/publication/fsync; cooperating canonical writers and CWE promotion wait |
| Cancellation now | Checks at gates/revalidation; no await/check during synchronous write; cancellation cannot roll back a write already made | No async interruption inside capture. Metadata added only after capture and proof checks; failures can leave storage bytes | Shield and repeated-cancel drain retain store lock. Worker error during drain can surface as OSError rather than CancelledError | Preparation drain catches failure without overriding cancellation; temps cleaned; replace is publication point; later fsync failure leaves publication visible |
| Existing controls | Registry copies args, checks dispatch identity; scope/protected paths/type/hardlink checks; gate verifies review freshness; second guard after mkdir | Project containment, sensitive provenance, 2 MB accepted-content limit, text redaction, SHA-256, read-only content addressing, managed identity/path/nlink checks, source association checks | O_EXCL collision-safe reports, partial-write cleanup, candidate dedup, canonical historical readback, result/evidence/binding revalidation before persisted mark | Safe destination/collision selection, private fsynced temp, current-result guard after prep, canonical exact-byte check, atomic replace, directory fsync, independent canonical persistence |
| Confirmed observations | Blocking; existing final-check symlink substitution redirects write in controlled probe. Naive worker stale-authority/overwrite are design failures | Blocking; source substitution escapes project, inconsistent size/hash versions, altered destination accepted by low-level recapture, failed partial publication poisons retry | Blocking post-read; ownership/retry controls pass; cancellation/error precedence differs from session/summary. Proposed offloaded read is safe in tested windows | Blocking; existing preparation guards, concurrency, cancellation and failure controls pass. Naive stale commit is a design failure, not an installed defect |

Store locks provide in-process cooperation on one event loop. They are not
cross-process locks and do not protect against arbitrary external filesystem
mutation. Evidence's workflow lock also does not serialize policy revocation.

## B. C2 failure model and linearization gap

Relevant source: `src/permission/runtime/execution.py` (ExecutionReceipt,
file_resource_identity, invocation_digest, stamp, revoke, start,
execution_is_current, revalidate_active); `src/permission/runtime/invocations.py`
(ReviewGuard); `src/tools/common/registry.py` (execute/_execute/finally stop);
`src/tools/execution/file.py` (gate_sensitive_path, FileWriteTool.run).

1. `prepare()` validates and records a receipt digest. For file tools the digest
   includes resolved pathname and stat dev/inode/size/mtime, or `absent`.
   The receipt also captures policy/profile/engagement/HTTP revisions and the
   review owner/signal. Registry args are private copies.
2. `dispatch_receipt()` rejects stale reviews/changed args and exchanges review
   tickets for dispatch receipts. `start()` checks current authority, resource,
   TTL, validation binding and budget, consumes the review and installs an
   active receipt. Its 60-second dispatch TTL is not the running-operation TTL.
3. `execution_is_current()` still requires matching current stamp and an open,
   uncancelled review owner. `revoke()` adds the revoked tool, increments
   policy revision and retires reviews; an active receipt also becomes stale
   through its stamp. `retry()` and other revision changes likewise invalidate
   an old active receipt.
4. The sensitive gate checks cancellation, scope and nested authority; after a
   dialog it also compares resource identity and review freshness. FileWrite
   revalidates before mkdir and again after mkdir, just before write_text.
5. The final synchronous guard -> write has no asyncio scheduling gap today.
   Submitting a thread after that guard creates one. The worker receives no
   enforceable authority by merely receiving a path/content tuple. A final
   check after writing cannot undo the write. Path-based use also remains
   vulnerable to an external substitution between the last check and open.

**DESIGN GAP G1:** `start()` is explicitly dispatch admission, but there is no
worker mutation-admission/commit capability coordinated with revision changes.
Source comments say the consumed receipt authorizes its running operation;
continued stamp checks show that dispatch is not an unconditional lifetime
lease. They do not specify whether a separately admitted, not-yet-writing job
may proceed after revoke/cancel, or whether a pending create/truncate must be
prevented until its first filesystem mutation. This audit does not select new
semantics.

Distinguish the cases:

- Revoke before `start()`: production rejects; no file mutation.
- Revoke after dispatch but before the next guard: production rejects at that
  guard; parent mkdir may already have occurred. No rollback of that mkdir is
  promised. A naive submitted worker skips this protection.
- Revoke after a valid write has happened: this probe returns success with the
  bytes present. It is evidence of current behavior, not proof of the intended
  semantics for a not-yet-started worker. Rollback is not implied.
- Task cancellation while a worker runs: shield alone preserves its execution;
  joining prevents an orphan but does not make its effects authorized or undo
  them. The queued-worker probe shows join alone can run a writer that had not
  begun when the task was cancelled.
- Resource substitution after validation: distinct from policy revocation;
  requires pinning and checking the object actually used, not merely rechecking
  the original path string.

## C. Reproduction results

Common preconditions: fresh `/tmp` lab, synthetic proof/report bytes, no network.
`active_file` uses real ExecutionPolicy prepare/start/stop with FileWriteTool;
C3 authority probe uses a real WorkflowTool receipt and sensitive source gate.
C4/C5 use production Store and ConfirmFindingTool with explicit offline test
assessment fixtures. DESIGN_ONLY is implemented solely in this new test file
or by scoped per-instance monkeypatch, never in src.

| Probe (parameter cases) | Trigger / APIs | Expected safe behavior | Observed behavior / verdict |
|---|---|---|---|
| C2-before-start-revoke | prepare -> revoke(file_write) -> start | Reject before mutation | Rejected; no file. **PASS production** |
| C2-current-second-guard-revoke | FileWrite.run; revoke injected after mkdir | Final guard rejects stale receipt | Rejected; no content write. **PASS production** |
| C2-current-second-guard-path | Swap destination to outside symlink after mkdir | Resource/scope revalidation rejects | Rejected; outside canary unchanged. **PASS production** |
| C2-naive-revoke | final real guard; hold proposed worker; revoke | No unadmitted write with stale receipt | Real revalidation rejects, worker still writes. **FAIL design** |
| C2-naive-revision | Same, policy.retry() | Revision change invalidates old worker authority | Old worker still writes. **FAIL design** |
| C2-naive-path | Same, substitute outside symlink | Writer uses only reviewed resource | Outside synthetic file overwritten. **FAIL design** |
| C2-naive-cancel_signal | Same, set captured AbortEvent-like signal | No unchecked mutation after cancellation before use | Real guard raises cancellation, worker still writes. **FAIL design** |
| C2-revoke-after-write | Production write_text completes, then revoke | Contract must distinguish begun/completed mutation from admission | Bytes remain and run returns success. **INCONCLUSIVE semantics**, observed production behavior |
| C2-current-final-check-path-swap | Symlink substitution immediately before original write_text opens file | Scope check binds object actually written | Outside canary overwritten; later real guard rejects. **FAIL production**, external-path TOCTOU |
| C2-naive-old-after-new | Hold old writer; perform a newer real FileWrite; release old | No stale overwrite / revalidate stale resource | Old worker overwrites newer content; real old guard would reject. **FAIL design** |
| C2-queued-cancel-drain-without-admission | Single-slot executor held; shield queued writer; cancel task; drain | Cancellation policy must define whether queued unbegun mutation is skipped | Writer runs during drain; no orphan, but creates file. **INCONCLUSIVE semantics design** |
| C3-source-after-snapshot | Production capture_snapshot; subsequently rewrite source | Immutable derivative remains valid historical proof | Original derivative, hash and source-path provenance remain valid. **PASS production** |
| C3-source-path-swap | After scope/is_file check, read_bytes substitution to outside symlink | Read remains project-contained | Outside synthetic bytes become snapshot. **FAIL production**, path TOCTOU |
| C3-content-address-mismatch | Alter just-written destination before original capture recaptures it | Returned digest/content/path stay bound to intended redacted bytes | Artifact hash matches changed bytes, filename contains old digest. **FAIL production low-level contract** |
| C3-partial-proof-retry | fdopen wrapper writes prefix then raises OSError | Failed creation removes owned incomplete publication; retry possible | Partial final .proof remains; retry raises hash collision. **FAIL production** |
| C3-naive-concurrent-publish | Proposed concurrent snapshot workers, first reserved but empty final filename | Second writer sees complete immutable content or waits | Second reports hash collision against incomplete first write. **FAIL design/new concurrent window** |
| C3-metadata-after-worker-success | Actual WorkflowTool.run; injected synchronous snapshot error | No evidence metadata on failure; release workflow ownership | No metadata committed; lock released. **PASS production** |
| C3-capture-inconsistent-size | Production capture stats old file; rewrite in read_bytes | Size and digest describe one byte snapshot | Old size with new digest. **FAIL production capture/read contract** |
| C3-proposed-cancel-drain-retry | Test-only workflow-locked snapshot worker held during file creation; repeated cancel | Drain before lock release; no cancelled metadata commit; retry idempotent | Complete unregistered proof retained; no state commit; retry reuses it. **PASS with retained-proof limitation design** |
| C3-naive-read-after-revoke | Real workflow source gate; proposed worker held; revoke workflow | Read does not consume obsolete authority before source use | Worker reads/writes derivative; final guard rejects but cannot undo read. **FAIL design** |
| C4-cancel-worker-success | Actual save worker held; repeated cancel; another Store retries | Keep shared lock until drain; one canonical report | Retry waits, restores original report; one file. **PASS production** |
| C4-cancel-worker-error | Same, worker raises OSError | No orphan/lost lock; define error versus cancellation outcome | Drains, retry works; OSError overrides cancellation. **INCONCLUSIVE precedence contract**, production observation |
| C4-current-stale-result | Actual writer held; change latest result notes on loop | No persisted mark matching obsolete result | Historical report retained; finalization rejected. **PASS production** |
| C4-proposed-read-stale-result | Proposed write+read worker; read held; change latest result | Existing controller result guard rejects | No persisted mark; one canonical report. **PASS design** |
| C4-proposed-read-cancel | Same, repeated task cancellation | Keep store ownership through read; no caller snapshot publication | Drain then cancel; report retained; no persisted mark. **PASS design** |
| C4-proposed-read-mounted-oracle | Same proposed worker, original mounted measure/assert_responsive unchanged | Heartbeat and actual Esc remain responsive during held post-read | 405.5 ms operation; 22.1 ms heartbeat gap; 1.4 ms Esc; 21 ticks. **PASS design** |
| C4-proposed-read-error-retry | Proposed read raises after canonical write | Preserve canonical; leave status pending; dedup on retry | One canonical survives; retry finalizes it without duplicate. **PASS design** |
| C5-failure-before_replace | Real export; replace raises | Old derivative and canonical retained; temp cleaned | Retained; retry regenerates same destination. **PASS production** |
| C5-failure-after_replace_fsync | Real export; directory fsync raises | Publication is visible despite durability failure; canonical remains authoritative | New derivative visible; canonical/persisted status intact; retry succeeds. **PASS production** |
| C5-preparation-workflow | Real preparation held; clear persisted status | Recheck loop guard before publication | Rejected; previous derivative retained, temp cleaned. **PASS production** |
| C5-preparation-canonical | Real preparation held; external canonical byte change | Exact-byte check rejects changed snapshot | Rejected; previous derivative retained, temp cleaned. **PASS production** |
| C5-concurrent-exports | Hold first prep; launch second | Shared lock orders preparation/publication | Second prep cannot start first; same destination, canonical unchanged. **PASS production** |
| C5-naive-commit-stale-workflow | Capture actual write_summary guard; validate then hold proposed commit; invalidate workflow | No unreserved stale publication | Real guard now rejects, worker replaces anyway. **FAIL design**; marker content is synthetic proposal content |
| C5-cancel-queued-before-worker | Hold shared lock; cancel waiting production export | No preparation worker/temp started | None started; existing derivative preserved; retry works. **PASS production** |
| C5-proposed-postcommit-fsync-drain | Isolate worker fsync of already published summary under shared store lock; cancel twice; concurrent canonical save | Drain durability work before releasing lock; never roll back publication | Waiter blocked until drain; summary/canonical unchanged. **PASS design**, tests only durability phase |

There are **35 parametrized observation cases**. Tests assert both the
interleaving and outcome before emitting a verdict. Three initial harness
failures were corrected only in the new probe file: optional notes were None,
and replacing a summary with text lacking its canonical-link marker correctly
caused collision-safe destination selection. The corrected fsync/replace probe
preserves that marker and checks the actual existing destination.

Evidence limits:

- Path substitution probes simulate an actor able to modify the relevant
  filesystem entry. They prove a check/use gap, not arbitrary remote access.
- Managed `require_evidence()` also checks filename/digest-derived identity;
  it rejects the malformed content-address artifact later. Low-level recapture
  accepting it is not evidence that a bound finding becomes confirmed.
- Historical source changes after successful capture are allowed by current
  tests. Rejecting every later source change would break this contract. A
  consistent snapshot during read is a different requirement.
- The C3 naive concurrent-publication probe introduces simultaneous workers.
  Existing WorkflowTool calls on one state are serialized today. No claim is
  made that their current same-loop calls race in that way.
- Caller-owned direct Finding objects should not be mutated while save awaits.
  The implementation plan captures all writer scalars before waiting; no
  production caller aliasing defect was reproduced.
- Actual queued executor cancellation for C3/C4 is not exhaustively tested;
  C2 illustrates why a drain helper alone is not an authorization protocol.
  Arbitrary external process crashes/power loss were not tested.

### Required matrix coverage and N/A

| Required interleaving | C2 | C3 | C4 | C5 |
|---|---|---|---|---|
| Revoke/revision after validation | Real policy plus rejected worker designs | Real workflow receipt plus rejected read design | N/A to raw Store: no receipt. Caller evidence/generic guards stay on loop | N/A to derivative Store: no prompter/receipt. Workflow/canonical validity is its authority |
| Source/path changes between check/use | Real final-check path swap and earlier guard control | Real source swap, digest/size mismatch, altered snapshot | Detached path read and stale result tested; arbitrary external edit during proposed read untested | Canonical changes during preparation and existing unsafe path regression tests |
| Cancel before worker starts | Queued executor observation; admission semantics undecided | Current snapshot has no async worker; future queued read admission remains untested | Current lock/worker drain plus proposed read cancel; executor-queue skip untested | Actual cancellation while waiting for store lock |
| Cancel during worker/retry | Naive shield/join and old/new races; no installed file worker | Proposed in-progress file creation drained, retry reuses complete proof | Actual worker success/failure drain and candidate dedup retry; proposed read error retry | Actual preparation cancellation success/failure regressions; proposed fsync drain |
| Same destination / old worker late | Rejected stale overwrite design | Rejected concurrent incomplete-publication design | Shared-lock cancellation/retry and existing concurrent same-slug tests | Shared-lock concurrent exports; old preparation cannot bypass newer guards |
| Exception before/after replace | N/A: current FileWrite uses in-place write, no atomic replace | N/A to current snapshot: no replace. Partial publication failure is reproduced | N/A: current canonical creation uses O_EXCL; write-failure cleanup already tested | Both sides of replace tested |
| Hash/provenance mismatch | N/A: FileWrite is not an evidence ledger | Source/hash/size/content-address controls and mismatch probes | Existing evidence integrity tests + result/binding checks + proposed stale result | Canonical guard and exact bytes; derivative links are not new evidence eligibility |

## D. Alternatives and minimal safe recommendations

### C2 FileWrite

**A — entire filesystem transaction in a worker:** reject as currently defined.
Immutable path/content alone carries no revision-fenced authority. Both stale
receipt and stale overwrite designs failed. There is also no per-destination
lock, and raw paths can change before open. It would be responsive but unsafe.

**B — controller validation with a checked handoff:** the candidate full design.
Controller owns permission/review/receipt validation, destination ordering and
an explicit worker lifecycle: queued, admitted, mutating, settled. Worker inputs
are resolved root/resource identity, immutable path/content/mode values
and exclusively owned descriptors/handles, not live PermissionPolicy or tool
args. A coordinator must fence revoke/cancel against admission, and filesystem
use must pin root/parent/leaf, prohibit substituted symlinks/hardlinks, and compare
the descriptor identity against the reviewed resource before destructive
truncate/write. A new file's create is itself a mutation and cannot be hidden
in a supposedly passive preparation phase. Handle-based use must preserve
existing authorized alias behavior or reject changes fail-closed.

Linearization is **not defined yet**: dispatch, worker admission and first
create/truncate are distinct. After admission, allowed cancellation/revocation
behavior needs to be settled under G1; merely setting a ticket/event does not
prove actual begin-before-revoke. A callback requesting a fresh loop guard from
a worker also leaves a check/use gap unless ownership/admission is fenced.
Destination lock ordering must be controller ownership -> filesystem job, with
no worker acquiring an asyncio lock or invoking live policy. Drain/join all
mutations before releasing ownership or completing cancellation. Retain current
in-place write/mode semantics; FileWrite is not currently an atomic-temp writer.
Adding atomic replacement would be a separate behavioral decision.

**C — offload individual phases:** safe metadata-only discovery can precede
loop guards and be treated as a hint needing revalidation. mkdir/write/chmod are
mutating phases and still need B's admission. Keeping synchronous final guards
and simply dispatching write is the rejected design, not a solution. Leaving
the loop permanently blocked is not the recommended fix.

Complexity/risk: high relative to a one-line to_thread change; descriptor
portability and new-file handling need focused tests. Required tests include
before/after admission revoke, policy retry/revision, abort and queued cancel,
leaf/parent/root substitution, allowed existing aliases, hardlinks, denial,
same-destination ordering, partial write/error and retry. **BLOCKED on G1 and
resource-bound mutation protocol.** No new policy semantics selected here.

### C3 evidence snapshot/read/verify

**A — entire current capture method in a worker:** reject unchanged. It includes
an authorized source read, global sensitive-verification cache mutation,
exclusive but non-atomic final-file creation and a later recapture that need not
match the intended bytes. Moving it unchanged adds authority and concurrent
publication windows. The current defects above also exist without offloading.

**B — checked read, isolated storage transaction, controller adoption:**
controller keeps source selection, current candidate/objective/target/route and
policy checks, exact read approvals, generic attempt/source association checks,
and WorkflowState mutation. Worker receives pinned approved source/root handles
and immutable candidate/provenance values. A source reader should bound the read
itself (current code accepts only <=2 MB but first read_bytes can read more),
compare descriptor signatures before/after, derive size from the returned bytes,
and fail/retry on detected in-read mutation. Read admission must be fenced with
revocation/cancellation; a final metadata check cannot undo an unauthorized read.
No policy/propmter/WorkflowState runs in the worker.

After read authorization and consistent byte capture, redaction/hash/storage
can operate on exclusively owned immutable bytes. Preserve binary proof support
and text redaction; hash exactly the bytes published. Publish complete read-only
content without replacing an existing immutable proof: private exclusive temp,
complete write/close/mode, atomic no-clobber publication (a suitable primitive
must be selected and tested), verify an existing complete destination, clean
only owned temps/partial creations. Plain unconditional replace is not acceptable.
If linking is considered, account for require_evidence's nlink==1 constraint and
finish temp unlink before adoption. A per-key shared storage ownership contract
must cover concurrent states/instances; workflow lock alone is insufficient.
Keep original durability semantics unless separately authorized—current evidence
creation does not perform fsync.

Return detached artifact/content/signature data to the controller. Apply the
bounded `_verified_sensitive` cache there, not concurrently in worker dictionaries.
Under the existing workflow mutation lock, repeat candidate/objective/target/
route/policy/attempt checks after every new await, then validate immutable proof
hash/path/provenance and declared observation references before add_evidence and
source-map updates. Record_evidence currently checks these identities after the
permission await; offloading requires another post-worker check. Do not commit
evidence metadata before worker success. A cancelled complete, shared immutable
file may remain unregistered and be reused; do not delete a published proof
another operation could own. Drain first, then cleanup only owned unpublished
resources. Preservation/cleanup of complete unregistered proofs must be explicit.

**C — phase offloading:** storage of already authorized/captured bytes and
checksum reads of a fixed descriptor can be separate workers. Every source or
protected-evidence read still needs current read admission, even when a dialog
is skipped through operation-local approved_paths. Gated verification preserves
managed identity checks and source restrictions. Synchronous legacy capture/
resume APIs need compatible wrappers/call-site migration; do not merely wrap
the existing cache-mutating is_resolvable in arbitrary threads.

Lock ordering: WorkflowState mutation lock -> storage ownership. Policy revision
changes are outside that lock, so it is not an authorization fence. No storage
worker may acquire workflow ownership or mutate UI/Agent state. CPU redaction/
hashing in threads may still contend for the GIL; measure rather than promise
CPU responsiveness.

**DESIGN GAP G2:** read-admission revocation/cancel semantics, consistent source
capture and low-level immutable publication/retention contract. Phase B's
storage-only design is separable, but **the full C3 boundary is BLOCKED** pending
these conditions and source-/destination-mutation, partial-write/close failure,
collision, concurrent publication, cache-thread ownership and post-read
policy/objective/route tests. Existing evidence eligibility must stay unchanged.

### C4 finding post-read

**A — extend the already offloaded canonical transaction:** recommended minimum.
Take candidate_id, slug and rendered content before the first await. Under the
existing shared store lock, one worker performs the existing write-once/dedup
operation followed by the existing read_report parser and returns `(path,
detached Finding)`. This extends the existing worker wait; it does not require a
new FileWrite receipt, introduce live workflow objects or move authority guards.
Preserve exclusive report creation, writer cleanup and historical readback.

The publication point remains the existing canonical write-once creation.
Parsed field assignment to the caller's Finding remains on the loop, after
successful joined completion. ConfirmFindingTool then retains all current
review_snapshot, confirmation/assessment binding, generic attempt checks,
evidence authorization/reverification, accepted_result and persisted-status
updates. Evidence reads are C3, not part of a blind parser offload. A stale
result can leave a historical canonical report but cannot mark it current.

Keep the shared lock until write/read worker settles, including repeated cancel.
Keep the existing store's exception-versus-cancellation handler for this narrow
change. Do not import the session helper wholesale: session/summary suppress
worker failure in favor of cancellation, while finding save currently can
surface worker failure. Resolving that difference would be an explicit separate
contract fix. A read/parse failure must preserve the canonical report, leave
workflow pending and allow candidate-deduplicated retry.

**B — separately awaited joined post-read:** also possible, with the same lock
held and no field publication on cancellation. It adds a second await and
cancellation boundary, so has more regression surface than A without a benefit
for the selected blocking boundary. Authoritative state stays on the loop.

**C — offload only read bytes, parse on loop:** removes filesystem wait but
leaves parse CPU on loop; no evidence it is needed to preserve security or
compatibility. Offloading the existing full parser on detached bytes/Path is
simpler. Do not move workflow/policy guards into the worker.

Lock scope/order: current project store lock, no new workflow lock acquired
inside it. No stale overwrite from cooperating saves: later retries restore the
same canonical candidate report under the lock. Cross-process or external
in-place edits remain outside its ordering contract. Proposed A passed read
cancel, stale-result and postread-error/retry probes. The same candidate also
passed the unchanged mounted Textual oracle: 405.5 ms operation, 22.1 ms
heartbeat gap, 1.4 ms Esc delivery, cancellation requested at 56.7 ms and
completed at 405.6 ms, 21 in-operation ticks, with post-read off the UI thread. Add worker syscall
and parse checks, same-candidate concurrent saves and failure+cancel precedence
regressions while preserving semantics. **READY TO IMPLEMENT**, independently
of C2's receipt gap. It is not implemented by this audit.

### C5 summary export

**A — put lookup through replace/fsync in one worker:** reject unchanged.
Its guard closes over live WorkflowState and must not move into a worker. A
snapshot validated before submission is not guaranteed current at publication;
the naive commit probe failed even while the store lock remained held.

**B — checked commit with ownership reservation:** possible full candidate.
Controller owns authoritative workflow/canonical guard and an ownership scope
covering the commit. Worker receives immutable prepared content/temp/destination
identity plus pinned directory handles and expected canonical bytes/hash, then
revalidates filesystem resources/canonical snapshot and atomically publishes.
No worker calls a live guard. The reservation must prevent relevant workflow
mutations between the final guard and completion of replace; the shared store
lock already excludes cooperating canonical/CWE changes but not workflow changes.

A workflow mutation lock is useful only if all relevant mutators honor it:
WorkflowTool.run and operator result review do; ConfirmFindingTool finalization
and state reset are not established as participants in a new summary reservation.
Do not assume that adding a lock around the exporter alone solves this. Avoid
acquiring workflow ownership after holding the store lock; a future consistent
order would be workflow reservation -> store mutation lock -> worker. Audit its
actual call sites for reentrancy/order before implementation. Neither an
irrevocable publication ticket nor permitting stale publication after admission
is chosen by this audit. Preserve exact canonical verification and root/path
checks, using descriptor-bound use to avoid a larger worker path race.

**C — offload phases while retaining loop publication:** recommended first step.
Lookup/read/parse/relative links/collision metadata can be prepared from immutable
inputs under the store lock, followed by loop guard revalidation. Repeat the
canonical/destination checks around any new await; do not silently weaken their
current detection of external changes. Private temp preparation is already a
joined worker. After the existing final guard/checks and loop os.replace, use a
joined fsync worker under the same store lock; cleanup I/O is also joined.
Once replace succeeds, immediately relinquish temp ownership on the controller
before the fsync await, so cancellation/failure cannot delete a published file.
Never roll back canonical finding/status for derivative failure. Existing
post-replace fsync failure already means visible publication with uncertain
durability, not failed atomicity.

Linearization remains **os.replace** for phase C. Cancelling post-publication
fsync may wait for drain and must not pretend publication was rolled back. Pin
and own directory/temp handles for new asynchronous filesystem windows; no
worker should resolve an unconstrained destination. The fsync prototype verifies
joining/lock preservation only; it does not prove all descriptor/path cases.

C gives real responsiveness improvement and addresses the sampled fsync oracle
without deciding B's new commit semantics. It still leaves final guard/path
checks and replace on the loop. Those residual syscalls need controlled timing
probes; passing the sampled fsync test must not be advertised as eliminating all
summary I/O blocking. A permanent blocking loop is not the recommendation:
finish B when ownership/guard contracts are proven.

**READY WITH CONDITIONS** for this staged plan. **DESIGN GAP G3** blocks worker
replace until the ownership/linearization contract and mutator coverage are
proven. Required tests: cancel before prep/during prep/precommit/post-replace,
fsync and cleanup failure, canonical/workflow generation changes at every await,
concurrent exports/CWE/save, pinned root/parent/leaf swaps, temp ownership,
expected-byte validation and publication/durability recovery.

## E. Implementation checkpoints

| Checkpoint | Smallest implementation scope | Entry gate / oracle |
|---|---|---|
| C2.1 | Specify admission/resource ownership; add safe-contract probes before code | G1 resolved; revoke/cancel on both sides of admission and descriptor substitution tests. **BLOCKED** |
| C2.2 | Apply checked FileWrite worker under destination ownership; keep permission guards | No new policy bypass or in-place write semantics change; all FileWrite syscall phases and mounted oracle must pass |
| C3.1 | Correct consistent capture and complete no-clobber publication, separately from threading | Current source/path/size/hash/partial-file probes become safe-contract tests; managed identity/redaction/provenance stay intact |
| C3.2 | Checked read/storage/verify workers and controller-only adoption/cache | G2 resolved; new await revalidation, cancel drain, concurrent storage and mounted oracle. **BLOCKED for full C3** |
| C4.1 | Extend existing writer worker to include canonical parser; return detached result | Candidate A probes, current writer semantics, full finding integrity/revalidation and post-read mounted oracle. **READY TO IMPLEMENT** |
| C5.1 | Joined post-publication fsync/cleanup, retain atomic publication owner | Current failures/cancel/concurrency plus pinned-directory cases and fsync mounted oracle. **READY WITH CONDITIONS** |
| C5.2 | Offload passive lookup/read/render inputs with final controller revalidation | No external-change detection regression; ownership/temp cleanup at each await |
| C5.3 | Checked worker atomic replace under proven workflow/store ownership | G3 resolved; no stale publication, no lock inversion; descriptor race tests. **Not ready yet** |

These are independent small changes. Do not combine FileWrite authorization,
evidence storage, canonical parsing and summary publication into one refactor.
Readiness of C4 does not retroactively authorize changes in this audit session.

## F. Narrow C1 risk check

Session Store.save has no ExecutionReceipt, prompter or execution policy. It
persists controller-owned session checkpoints, not model-authorized arbitrary
file writes. Detached inputs and its same-path ownership lock therefore do not
have the C2 receipt-admission problem. `_joined_thread` retains ownership through
serialization/writing, repeated cancel and failure retrieval; a cancelled queued
save never acquires its lock. The existing 24 worker tests were rerun in the
focused regression group and pass.

Filesystem aliases/external parent replacement and cross-process writers remain
outside C1's documented lock contract. This audit did not expand C1 into a
filesystem trust-boundary review, find a new C1 defect or modify it. Do not reuse
its drain helper as proof that FileWrite/evidence read admission is safe.

## G. Verification and preservation

Final commands/results:

```bash
PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest -q -s --tb=short -p no:cacheprovider \
  tests/security/test_persistence_handoff_audit.py
```

**35 observation cases passed, 6.39 s.** Security/design verdicts are in the
probe table above; passing observation cases include reproduction of unsafe
outcomes and do not imply those designs are accepted.

```bash
task_audit_scratch=$(mktemp -d /tmp/kagent-audit-regression.XXXXXX)
TMPDIR="$task_audit_scratch" PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest \
  -q --tb=short -p no:cacheprovider -p tests.scenarios.offline_checkpoint \
  --basetemp="$task_audit_scratch" \
  tests/tools/test_file.py tests/security/test_evidence_reads.py \
  tests/data/test_findings_store.py tests/data/test_finding_summary_store.py \
  tests/tools/test_finding.py tests/security/test_execution_policy.py \
  tests/state/test_session_persistence_async.py
```

**203 passed, 9.01 s; no failures/XFAIL/skips.** Initial use of the containment
plugin with its default pytest scratch had **14 failures, 14 teardown errors,
189 passes**: legacy file/finding fixtures allocate tempfile.mkdtemp directories
outside pytest's basetemp. Guard rejection occurred before their file writes.
The rerun places both TMPDIR and basetemp in the same fresh `/tmp` container;
the fail-closed filesystem/network guard was retained, not weakened. No
production/test-fixture changes were made to suppress this result.

```bash
PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -m pytest -q -s --tb=short -p no:cacheprovider \
  tests/ui/test_persistence_responsiveness.py
venv-linux/bin/pyright tests/security/test_persistence_handoff_audit.py
git diff --check
git status --short
```

Mounted Textual: **7 passed, 4 xfailed, 20.76 s**, same unchanged oracle/markers.
Pyright: **0 errors, 0 warnings, 0 informations**. An initial type error in the
new test-local summary method replacement was corrected with scoped monkeypatch;
no production types changed. Available-version notice ignored; no installs.
Diff check passed. Existing diff and new probe/report were reviewed locally.

Every non-cache file under src was hashed at audit start and compared at final
review: **no production hash changes**. Existing modified/untracked C1/Planner
files and prior reports were preserved. This audit adds only:

- `tests/security/test_persistence_handoff_audit.py` — adversarial observations
  and explicitly labeled design-only candidates.
- `tests/ui/PERSISTENCE_HANDOFF_AUDIT.md` — this report.

Not performed: live LLM/Burp/external HTTP, full repository suite, Planner/Hybrid
reaudit, implementation of any proposed handoff, platform portability proof,
external-process/power-loss stress, every syscall's mounted timing test, or a
new permission/commit semantics decision. No commit/push/reset/clean/restore,
dependency install, UI change or production patch was made.
