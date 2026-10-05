# Generic bounded validation contract

Generic fallback is vulnerability-class agnostic at admission, but execution
remains capability/action bounded and conclusions remain verifier/review gated.
This does not mean every vulnerability or request shape is supported.

```text
Full registry + candidate class
  ├─ one enabled model-invocable expert → existing expert lifecycle
  ├─ ambiguous / disabled / manual-only / incomplete → deferred
  └─ genuinely missing mapping → generic consideration
       ↓ current objective/provenance/Target/exact origin/scope
       ↓ concrete proposal + controller-verified endpoint/action context
       ↓ transient attempt binding + exact prepared request comparison
       ↓ native receipt/private-host/grant/budget/scheduler → recheck → send
       ↓ native observation + candidate proof → immutable redacted evidence
       ↓ existing result → trusted verifier OR human ALLOW_ONCE review
       ↓ coverage → existing confirmed finding store
```

## Route and execution admission

The previous implementation only considered Open Redirect and CORS, and
constructed fixed URL/Origin markers from their class names. The resolver now
considers any class with no dedicated mapping. `Registry.validators_for_class`
semantics are unchanged. Expert errors, missing proof, timeouts or unavailable
capabilities never select generic. Registry load errors prevent inferring
absence, while an already resolved unique expert retains its path.

`generic_admission` checks the current route, objective provenance, active Target,
exact origin, scope and whole-target discovery dependencies. It also serves
stored evidence review/finding checks, so it deliberately does not require an
execution proposal. `GenericValidationBoundary.admit_probe` separately checks
the concrete request/action contract. A generic route grants no execution.

```python
workflow(action="start_validation", candidate_id="cand_...", probe={
    "candidate_id": "cand_...",
    "objective_id": "current-objective",
    "target_origin": "http://127.0.0.1:3000",
    "endpoint": "/lab/compare?keep=1",
    "method": "POST",
    "location": "json",
    "parameter": "term",
    "baseline_request_ref": "wr:captured-baseline",
    "auth_context_ref": None,
    "values": ["Lab-A", "Lab-B"],
    "occurrence": 0,
    "input_path": "/term",
    "observation": "compare-response",
    "capture": "native-http+candidate-proof",
    "stop": "after-comparison",
})
```

The immutable proposal contains no safety flags, authorization, certificate,
conclusion or raw credentials. It selects exactly one candidate input and
concrete comparison values. Baseline/auth references must match the candidate.
All other query/header/body bytes must match the prepared baseline/variant.
Observation is one of `compare-response`, `compare-status`, `compare-header`;
capture and stop mechanisms are fixed. Representation size limits constrain
proposal data, not request quotas. Native budgets allow repetition.

Expert starts still need no proposal. Generic starts may omit `probe` only when
the controller already has the equivalent complete concrete proposal in live
context. Missing/malformed proposals return tool errors and preserve deferred
work. An explicit start can reconsider a context blocker without automatically
requeueing old candidates. Any existing result or terminal candidate still
requires the existing explicit retest intent; force/status/proposal changes
cannot establish that intent.

## Trusted action context and authority

Source inspection found scope, exact-action HTTP approvals and operator lab
grants, but no trusted automatic endpoint side-effect classification. A capture
proves bytes existed, and a lab grant accepts unknown effects; neither proves
an endpoint/variation has bounded, nonpersistent application effects. GET,
marker syntax, boolean comparison and model claims are also insufficient.

The small trusted-controller integration is:

```python
policy.generic_validation.bind_probe_context(
    native_http_tool, candidate_id, concrete_probe,
    verified_input_only=True,
)
```

Only a controller that has independently verified the lab endpoint and **these
exact baseline/comparison values** may call this method. The verified facts
must exclude persistent application mutation, identity/role changes, command
execution, uploads and outbound callbacks. The local regression fixtures own
their mock handlers and establish those facts. This is a Python controller
hook, not a model tool, permission dialog, saved setting, universal detector or
production vulnerability verifier. The boolean argument is a trusted caller
precondition; it is never accepted as model-supplied safety evidence.

The hook compiles the proposal using the existing native preparation and
captured input builder, and binds candidate/objective object generations,
candidate context, exact Target revision and baseline/request hashes. No grant,
receipt, permission cache, budget renewal or authorization is created. Native
execution policy, engagement scope and operator HTTP authority are still
independently required. There is no new CLI approval flow or automatic producer
of these verified endpoint facts. Unintegrated/unknown endpoints remain
context-needed/deferred. Existing authorizations need no extra generic dialog.

## Supported and deferred actions

With matching verified action facts and native authority, positive fixtures
exercise custom classes using query comparisons, named noncredential headers,
POST UTF-8 form fields and POST JSON scalar values. Query/form occurrences and
JSON selectors use the existing byte-preserving request builder. Prepared
baseline requests may also be repeated. GET/HEAD/OPTIONS without a body and POST
with supported baseline context are representable; HTTP method is not proof of
safe effects.

Fail closed for missing/stale captures or identity credentials, unverified
effects, other endpoints/origins/inputs/values, identity/transport field
variation, path/raw/cookie selectors, multipart/upload, compressed bodies,
unsupported form charset or malformed/ambiguous/truncated baseline encodings.
DELETE/PUT/PATCH and application mutation/impact are unavailable. Header framing
injection is rejected. Actual redirects remain `max_redirects=0`.

URL data creates no destination rights. Only reserved example.com URL markers
are representable here, and only for endpoint/value contexts independently
verified not to cause callbacks. Other absolute callback destinations are
rejected. Responses cannot add values, routes, endpoints or chained actions.

## Runtime enforcement and lifecycle

Native execution-policy prepare/start checks precede HTTP execution.
`begin_http` checks the concrete proposal and starts an in-flight guard;
`HTTPTool._dispatch` rechecks immediately before `reservation.start()` and send,
after DNS, native permission, private-host and scheduling awaits. It compares
the logical prepared request even when the socket request is DNS-pinned.
Current baseline/auth is rebuilt every time; registry, candidate, objective,
Target, policy and attempt changes block stale sends. Explicit context updates,
switching attempts or recording results cannot occur in-flight. Proposal
replacement while an attempt is active is rejected; terminal work retains
explicit retest gates.

HTTP grants retain rate, concurrency, expiry, request/response byte and request
count controls. ExecutionPolicy call/concurrency budgets and agent step/stall
limits remain shared. Scheduling `HTTPPending` does not synthesize a terminal
blocked result; native denial/exhaustion does. No generic quota or budget reset
exists. YOLO does not bypass contracts, scope, native gates or proof, and cannot
auto-approve human conclusion review.

The capability set remains native HTTP, workflow bookkeeping, ask_user,
permissions_status, candidate-bound proof file_write and gated confirm_finding.
Shell, plugins, MCP, browser, discovery/search, arbitrary file reads/edits and
uploads remain unavailable even with broad active skill tools or YOLO.
Recording another candidate preserves bookkeeping without granting probe
rights. Input questions reuse the existing session answers and cannot establish
generic execution authority. No approvals become durable memory.

## Evidence, review, finding and resume

The existing immutable evidence pipeline preserves redaction, ownership,
path/size/hash/integrity restrictions. Proof writes only target the candidate's
proof source path, with existing symlink/hardlink/control-plane checks. Request
input variation does not mark persistent mutation or require invented cleanup.

Both confirmed and not-confirmed require the existing trusted certificate or
observations.verify adapter. There is no new universal verifier; the existing
production adapter registry currently registers SQL boolean JSON verification.
The four custom-class fixtures have no production verifier and first record
insufficient-evidence with no terminal negative coverage, then exercise human
review. LLM notes, repeatability, observation IDs and force do not confer proof.

Human review retains ALLOW_ONCE through the operator prompter, no session cache,
task-local staging, review tickets and overlapping-review protection. Result,
coverage and session save precede certificate publication. Existing stale,
decline, cancellation, evidence and failure guards remain authoritative.
Findings require the latest confirmed result, current binding and matching
certificate; store success precedes the persisted marker. Pure finding
eligibility has no runtime/disk checks added.

Proposals and verified action contexts are transient. Candidate/ValidationResult
and session version/JSON formats are unchanged. Fresh boundaries and in-place
session replacement invalidate probe context; saved status, route, plan or
proposal-like text cannot reconstruct it. Stored evidence can still undergo
human review without a live proposal; that review cannot grant new probe
rights. Planner guidance distinguishes context-needed from admitted starts,
uses no recommended generic Skill, and preserves discovery phases. Whole-target
and direct completion require recorded generic work to be resolved; direct
unresolved final responses produce an explicit incomplete runtime status.

## Verification

Verification commands and final results are recorded with the handoff. Tests
use mocks/local fixtures and the configured venv-linux. No external model API,
live external target or live Burp integration is required. The pytest.ini Burp
exclusion and existing platform/filesystem/worker skips remain intact.

The final focused responsibility group passed **829 tests, zero failures/skips**
using workflow/state/planner/benchmark, generic contracts, schema budget, SQLi
runtime compatibility, execution/permission/private-host/HTTP, evidence,
operator review/finding, whole-target/skill/phase integrations and session
store tests. The planner benchmark separately passed **68/68**, with unchanged
expectations (five ambiguity cases and 21 no-recommendation cases). Pyright
using the repository configuration passed with **0 errors, 0 warnings**.
`git diff --check` passed. Final full offline verification passed **3662 tests,
1 existing skip, zero failures**, with two expected malformed-config warnings
from `tests/runtime/test_config.py`, in 223.71 seconds.

```text
venv-linux/bin/python -m pytest -q                  3662 passed, 1 skipped
venv-linux/bin/python -m benchmarks.internal.planner_benchmark   68/68
venv-linux/bin/pyright                             0 errors, 0 warnings
git diff --check                                  pass
```

The first full run exposed the schema budget overrun and a SQLi runtime fixture
that omitted the full skill registry. The schema description was compacted
without relaxing parse checks or changing the budget test. The fixture now
loads the real registry; its four-observation/proof assertions are unchanged.
Two superseded diagnostic pytest runs were interrupted; the final focused and
full runs cover their responsibilities. Intermediate fixture/import/event-shape
mistakes were corrected before final verification.

## Change ownership

This task started with nine modified source files and three untracked generic
implementation/test files. It extends that work without staging/restoring it.

| File | Changes in this task |
| --- | --- |
| `src/workflow/validation_route.py` | Remove class allowlist; separate current provenance/scope checks from execution admission. |
| `src/workflow/probe.py` | New immutable proposal parser and compact tool interface. |
| `src/permission/runtime/generic_validation.py` | Transient verified context/attempt binding, native prepared request rebuilding/comparison, sensitive/context/stale guards; retain existing capability/proof/bookkeeping protections. |
| `src/tools/workflow/workflow_tool.py` | Probe start interface, explicit context reconsideration, unchanged expert compatibility, result clears live attempt; compact descriptions within existing schema budget. |
| `src/tools/http/http_tool.py` | Preserve pending scheduling, independent native rechecks, metadata-aware no-policy fail-closed handling. |
| `src/cli/runtime.py` | Supply full registry to the native HTTP compatibility guard. |
| `src/agent/decision_planner.py` | Class-neutral proposal guidance, context-resolved deferred work can receive explicit start guidance. |
| `src/agent/agent.py` | Transient admission/readiness, reviewed completion without proposal, direct unresolved completion/stream guards, latest matching proof checks. |
| `src/workflow/state.py` | Describe context-resolved deferred work as actionable without requeueing; no persistence change. |
| `tests/security/test_generic_validation.py` | Supply verified fixture action facts; retain existing security/expert tests and update intentionally changed consideration behavior. |
| `tests/security/test_bounded_probe_contract.py` | New custom shape/proof/finding/resume/action/stale/scheduling/planner/direct regressions. |
| `tests/security/test_repair_runtime.py` | Full registry in the SQLi expert fixture; proof assertions unchanged. |
| `tests/tools/test_workflow.py` | Missing mapping is generic consideration, still unsupported/deferred without runtime context. |
| `docs/generic-bounded-validation.md` | Contract, trust source, limitations and verification record. |

`src/permission/runtime/execution.py`, `src/skills/registry.py`,
`src/tools/workflow/finding.py` and `src/ui/commands/result_review.py` already had
generic changes before this task; their contents were preserved and their
behavior was exercised by verification. No skill playbook, provider/user
configuration, persistence schema, dependency or benchmark expectation changed.
No stage/commit/push, package install, sub-agent, external model API or live
external target operation was performed. Live Burp remains excluded by
pytest.ini rather than enabled for this task.
