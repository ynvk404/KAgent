# lan-05 Enumeration stall audit

Scope: offline inspection and regressions only. Historical lan-05 data was
read, not edited. No model/provider request, live-target request, new experiment,
commit or push was performed for this audit.

## Verified causes

Inspected `experiments/scenario3/runs/lan-05/` logs, saved session, context
snapshot and ObservationStore, plus current production context shaping,
tool-result admission, permission/reader gates, Action Guidance, planner,
Workflow source/input/phase contracts and the relevant shipped playbooks.
The pre-change versions of the seven relevant runtime modules match the
SHA-256 identities recorded in the lan-05 profile, including the production
reduction transform, guidance, result handler, readers and Workflow tool.

- The retained initializer observation
  `obs_a8a6bf1f02f54b63bd6620ba41b1118e` is complete, not truncated, and
  contains 5,457 body bytes. It has no Candidate/Attempt owner. This is not
  a capture failure or exhausted HTTP response cap.
- Its saved HTTP message is 6,888 characters. The production
  `bound_recent_tool_result(..., 2000)` transform omits `paths` (original
  message offset 1,990), `/orders` (2,007), `requestBody` (2,556), and `cid`
  (3,112), while retaining `OrderConfirmation` fragments. The context guard
  at log sequence 209 removed 6,375 characters across working results.
  Full outbound model requests were not archived, so the exact historical
  request cannot be asserted; the omission mechanism is reproducible.
- Raw HTTP results intentionally bypass generic `tr_` result retention.
  Adaptive context reduction can omit their body independently of capture
  completeness. There was no discovery-body reader: `get_source` returns
  metadata, and `read_http_observation` correctly requires Candidate/Attempt
  ownership. File access is a separate permission boundary, not an implicit
  fallback to managed observation files.
- The owned-reader failures were repeated. Feedback pointed to owned IDs
  and forbade rerunning HTTP, but offered no authorized discovery-body path.
  Action Guidance did not distinguish metadata from content retrieval.
  Source-frontier guidance applies only to selected sources; all ten sources
  were unselected. Existing timely-input guidance was already present.
- `get_source` succeeded at sequence 252. The final response's claim of its
  failure is false. The spec contains only `POST /orders` under server base
  `/b2b/v2`; it does not document the familiar login/search/product-filter
  SQLi endpoints claimed by the model. Those claims are model-generated,
  not observed evidence. Their internal cognitive cause is unverifiable.
- No `record_input` or Enumeration inventory/coverage calls occurred.
  Capturing endpoint/source metadata did advance discovery, but did not
  establish request parameters. Response object fields and familiar route
  names alone do not justify input records. Losing the operation/request
  schema, then fixating on failed reads, prevented this handoff; there is no
  demonstrated `record_input` admission failure or missing action.
- Iterations 12–15 produced no structured progress: failed reader, metadata
  listing, repeated failed reader, successful metadata lookup. The runtime
  stopped at 15/60 with four consecutive no-progress iterations. Stall
  protection behaved as configured; the iteration budget was not exhausted.

## Minimal changes and retrieval contract

| File | Change |
| --- | --- |
| `src/tools/common/tool_result.py` | Separate `read_discovery_source`, shared bounded range/permission envelope, clearer owned-reader description/error. |
| `src/agent/agent.py` | Register/project the reader, preserve and revalidate its HTTP provenance before outbound context, and credit only bounded content-page exploration without Workflow mutation. |
| `src/agent/action_guidance.py` | Enumeration-only metadata/content/ownership distinction, alternate-source recovery, and prior-knowledge grounding. |
| `src/agent/decision_planner.py` | Existing selected-source guidance includes the newly authorized range path. |
| `skills/web-enumeration/SKILL.md` | Document reader limits, stop/recovery behavior and accurate spec attribution. |
| `tests/security/test_discovery_source_reader.py` | Production offline regressions for content access, authorization, provenance, exposure, recovery and grounded input progression. |
| `docs/lan-05-enumeration-stall-audit.md` | This audit and validation record. |

The reader is justified because already captured, in-scope discovery content
can be omitted from model context despite remaining fully retained. It uses
an exact current Whole-target `ds_` reference, not arbitrary paths or IDs.
Every range passes the existing Registry receipt/permission gate with no
session permission cache. Current objective/origin, session, epoch, HTTP
skill capability, revocation, producer, source/body hashes and managed-secret
protection are checked before and after permission review and again before
outbound use. Imported captures retain their capability revocation boundary.

Each result is at most 2,000 characters including its provenance envelope;
offsets address decoded Unicode characters. The source remains within the
existing 64 KiB body and 256-observation store limits. Completeness and adapter
truncation remain separate from page continuation. There is no new storage,
network request, cap escalation, replay authority, source selection, coverage
attestation, Candidate/Attempt ownership or terminal-evidence eligibility.
Existing session call budgets apply. At most four content/offset bands can
earn exploration novelty per body hash, within the existing phase exploration
allowance; identical pages and rejected reads cannot renew progress.

## Validation and limits

Initial focused regressions: **5 failed, 9 passed** before the implementation;
failures established missing production availability, useful feedback and
content access. Subsequent tests cover production reduction, actual prepared
Enumeration request schemas/guidance, metadata success versus body retrieval,
unchanged owned-reader rejection, permissions and revocation during review,
provenance/session/epoch/scope/integrity rejection, resource limits, truncated
sources, outbound revalidation, nonterminal discovery sources, duplicate-read
stall behavior, and grounded inputs from unselected/alternate sources.

Final verification:

- New regression file: **28 passed**.
- Final skill/guidance/request-projection checks: **103 passed**.
- Broader offline responsibility groups: **5,149 passed, 1 skipped** with
  `venv-linux/bin/python -m pytest tests/agent tests/security tests/tools
  tests/state tests/skills tests/integration -q --tb=short`.
  The opt-in live-model characterization remains skipped.
- Full configured `venv-linux/bin/pyright`: **0 errors, 0 warnings**.
- `git diff --check`: clean. Reviewed the diff and final worktree status;
  only the seven files listed above changed.

Other responsibility groups and live/model characterization were not run.
The existing offline production-contract tests pass, so the access/recovery
fix is ready for a fresh Whole-target SQLi-only run under normal Runtime
Permission, scope and Workflow gates. No run is claimed to have succeeded.

These tests exercise production controllers with offline transports and
caller-supplied review facts. They do not prove an LLM will choose recovery,
follow guidance, or avoid hallucinations. Manual `source_attribution` remains
a caller declaration, not automatic semantic verification of a document.
Unavailable, evicted or revoked content remains unavailable; partial sources
retain limitations and phase-completion obligations. A fresh Whole-target
SQLi-only run remains necessary to evaluate model behavior; none was run here.
