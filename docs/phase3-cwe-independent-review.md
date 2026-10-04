**Independent Phase 3 final review — 2026-10-04**

Reviewed the current worktree, not the implementation session's claims. Read
AGENTS.md, initial status/diff, taxonomy, controller, UI, findings, review state,
MCP registry/transport, execution policy, worker, setup, packaging and tests
before editing. Documentation was read after implementation. No agents,
commit, push, package installation or active provider/MCP config change was used.
The implementation's existing uncommitted changes were preserved.

The actual flow is a persisted confirmed report with Phase 1 classification,
followed by an explicit `/enrich-cwe <candidate-id>` invocation only when CWE is
unresolved. The controller verifies historical confirmation binding and current
Candidate/result/evidence/scope, searches the designated offline MCP through
Registry, validates the bounded response, presents controller-owned candidates,
accepts numbered selection or abstention, asks the underlying operator prompter
for mechanism fit, performs exact lookup, then commits a separate guarded
classification update. No automatic fallback is wired into confirmation,
retry or resume.

| Boundary / responsibility | Independent result |
| --- | --- |
| Phase 1 / local first | Immutable local taxonomy remains authoritative at confirmation. Existing local, external or historical CWE returns before source access. Ordinary retry restores persisted fields even when current taxonomy changes. |
| Model authority | The model can invoke the two retrieval tools. There is no promotion/assignment tool. Extra model-supplied CWE, provenance and revision fields do not assign classification. Selected objects and provenance are constructed inside the controller. |
| Permission / YOLO | Registry validates and prepares an exact receipt, requests permission or uses existing YOLO retrieval mode, then starts the receipt before isolated dispatch. Denial/revocation/staleness cannot dispatch. Fit review uses the underlying operator prompter and requires ALLOW_ONCE with no session cache. Retrieval approval, result approval and ranking grant no classification authority. |
| Source identity | Checks actual MCPTool identity, designated server/command/args/no env, remote names, schemas, bound policy, reviewed manifest, deployed launcher/server source and official XML hash. Changes invalidate review. Payload-claimed hashes alone are not an authenticity proof. |
| Query | Only bounded canonical class/title mechanism vocabulary is used. No HTTP, impact, evidence, payload or target URL field is sent. Fixed credential/URL/JWT minimization now happens consistently before tokenization of either fragment. Empty safe queries fail safely. |
| Response | Strict frozen models forbid extras and coercion, including bool-as-int. Recursive duplicate JSON keys, malformed wrapper, oversized content, bad ranks/order/IDs, mismatched ID/status/flags, corpus/schema/adapter/algorithm and completeness/truncation inconsistencies are rejected. Required metadata must be present and complete. |
| Selection / exact lookup | A copied displayed set is presented; only an integer index into the controller's original set is accepted. Search-only rank/score/flag fields are removed. Exact lookup must match every normalized authoritative Candidate field, including guidance, maturity, abstraction and structure. |
| Eligibility | Only complete, untruncated Weakness entries with Mapping Usage Allowed and non-Deprecated/non-Obsolete status qualify. Allowed-with-Review, Discouraged, Prohibited, unknown/missing usage, Category and View do not. MITRE Variant abstraction is accepted independently of the removed semantic-variant design. |
| Review lifecycle | Tickets supersede older reviews. Identity-sensitive cleanup cannot clear a newer ticket. Guards bind report digest/revision/path, Candidate/result snapshot and position, evidence, policy, source and ticket. Denial, abstention, invalid selection, cancellation and exceptions leave no promotion. TUI shutdown now cancels and drains command tasks. |
| Confirmation / proof | ConfirmFindingTool retains its existing eligibility, certificate, scope/endpoint/method/parameter and evidence checks. Enrichment neither generates proof nor changes ValidationResult, eligibility, identity, routing or coverage. Failure does not alter the confirmed report. |
| Retry / resume / legacy | Store.save restores all fields from the existing report and does not query CWE. Actual SessionStore round-trip tests verify workflow binding and authoritative promoted/unresolved reports without retrieval. Legacy reports need no migration/provenance to remain readable; missing historical binding prevents enrichment. Unknown future provenance fields are retained. Invalid provenance fails safely without rewriting bytes. |
| Worker / deployment | Actual Linux bubblewrap/prlimit path tested. Project/deployment are read-only, .kagent and host venv hidden, artifacts/worker writable, direct network denied. Native model writes to imported adapter, generated deployment and canonical/legacy reports are blocked even under YOLO. Runtime has no downloader or query log and uses -I -B. |
| Packaging | Built a wheel from a temporary source copy using existing system build tools, extracted outside the repository and imported the client/UI with isolated Python. Both src and components came from the extracted wheel. Manifest was readable, checked source bytes matched, and corpus/generated runtime were excluded. No source checkout fallback or package installation was used. |

The persistence linearization point is synchronous `os.replace` on the controller
event loop. The shared project lock covers read/verify/derive, offloaded temporary
write/flush/fsync, final guards, replace and publication. The preparation thread
cannot replace the report. Cancellation drains preparation under the lock and
removes its temporary file. No await lies between the final guard and replacement.
Before replacement, failures retain the old authoritative bytes. Afterwards,
directory fsync failure reports uncertain durability, snapshot-refresh failure
reports a visible commit requiring reload, and notifier failure cannot roll back.

Only CWE, classification provenance and revision rows change. The same report
path and every other Markdown byte, including CRLF, are retained. Timestamp,
severity, URL, class/type, OWASP, impacts, evidence, payload, reproduction and
remediation remain authoritative. Ordinary write-once Store.save semantics are
unchanged. Tests exercise two cooperating Store instances, concurrent promotion
and retry, stale competing updates, cancellation around preparation/commit,
real temporary-file fsync failure and post-commit recovery.

The production mutation path remains in one controller process/event loop;
workers cannot write reports. Separate independently launched KAgent processes
or external writers to the same project are not covered by this transaction.
No cross-process CAS was added. Coordinating independent simultaneous project
sessions is backlog rather than an expansion of this release's guarantee.

| Finding | Severity | Reproduction / existing coverage | Fix / regression | Failed before | Passed after |
| --- | --- | --- | --- | --- | --- |
| CWE-R1 | P1 | Credential values made of allowlisted words reached query arguments: Authorization/Bearer, Unicode labels, multiword values and unknown class identifiers. The old query test covered simple ASCII one-token assignments and URLs only. | Apply the same bounded normalization, terminal/control handling, credential-tail removal and URL/JWT filtering to both input fragments. `tests/cwe/test_enrichment.py::test_credential_context_is_removed_before_normalized_query_tokens` (7 cases), `test_title_controls_cannot_hide_credential_labels` (2), `test_unknown_class_identifiers_receive_the_same_query_minimization` (3). | YES; seven failures initially, then control/class edge regressions were reproduced before their fixes. One intermediate newline failure was safe over-minimization rather than a remaining secret leak. | YES |
| CWE-R2 | P1 | An approved command paused during real offloaded report preparation committed after KAgent.on_unmount returned. Existing tests cancelled the coroutine directly but did not exercise actual slash-command ownership/shutdown. The reproduction inspected persisted bytes, not just a message. | Track command tasks in KAgent; refuse new starts during closing; cancel before the first shutdown await and drain cleanup. `tests/cwe/test_enrichment.py::test_tui_shutdown_cancels_and_drains_promotion_before_commit`. | YES; both the missing cancellation and changed report bytes were observed. | YES |
| CWE-R3 | P2, retained | Under concurrent suite/type-check load a real MCP handshake exceeded its existing deadline. Cleanup raised AnyIO BrokenResourceError, while acceptance tooling kept waiting for its delivery event and later reported timeout plus an unretrieved failed-task diagnostic. Subsequent sequential acceptance passed unchanged. | No Phase 3 transaction, authority or persistence failure occurred. Diagnostic/early-RPC-failure handling in existing MCP/acceptance code is left for follow-up; no timeout was relaxed and no test was weakened. | Observed integration failure, not a claimed fixed regression. | Sequential acceptance passed; diagnostic gap remains. |

No P0 finding was reproduced. Both identified P1 issues were fixed; no P0/P1
remains in the reviewed single-controller deployment contract. CWE-R3 is a safe
failure/diagnostic limitation, not a release blocker.

Additional coverage, rather than claimed fixes, was added for model-supplied
classification fields, adversarial Unicode/control/URL/JWT queries, enormous
inputs and allowlist-only titles, old review cleanup while a newer ticket is
pending, actual session save/load, real temporary-file fsync failure and
future/malformed provenance. These cases were already correct where applicable;
they are not inflated into new bug findings.

Existing unit fixtures replace MCPSession.open and synthetic corpus pins, so
their green status alone does not establish worker or publisher trust. Server
tests also reuse the contract models. The independent real acceptance run and
fresh official download address those gaps. Existing overlapping persistence
tests yield during preparation and compete for the shared lock; cancellation
tests hold a real thread/event boundary. The new shutdown regression reproduces
the real UI dispatch path and retains byte-level assertions.

Official identity was reverified against a fresh download from
[MITRE's release archive](https://cwe.mitre.org/data/archive.html) and its
[4.20 ZIP](https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip): ZIP SHA-256
`3976f599e5e5200219a3108bb896d06e2a88fbb293369e1883cb423a5e9d7d50`, XML SHA-256
`1f5a78bd62e00f86436b4fe32d5034a57e8f0da88e4063b2072b664ae510912e`.
The deployed XML matched downloaded XML byte for byte: 18,192,305 bytes,
2026-04-30, schema 7.3, 969 Weaknesses, 422 Categories and 59 Views.
Deployed launcher, manifest and all four serving-package files also matched
the independently reviewed source byte for byte. The deployment contains no
symlinks and its installed SDK metadata identifies mcp 1.28.1.

Real acceptance uses isolated configuration and a temporary synthetic finding,
not an operator target. It exercises actual discovery, Registry receipts,
worker isolation, search/get, normal denial without dispatch, YOLO retrieval,
operator abstention/denial/approval, exact official CWE-639 promotion, persisted
retry and cancellation/timeout cleanup. Official CWE-862 remains
Allowed-with-Review and non-promotable. Callback-driven operator decisions are
test inputs; focused Textual tests separately cover the actual UI rendering,
selection and cancellation. No real-human interaction is claimed.

Final verification results:

| Check | Result |
| --- | --- |
| Initial Phase 3 baseline | 165 passed, 27.94 seconds |
| Failing R1/R2 reproductions | Initial 8 cases failed; explicit byte-level shutdown rerun failed; later 2 control and 3 class edge cases failed before refinement |
| Exact query regressions after final fix | 18 passed, 82 deselected, 10.55 seconds |
| Final focused responsibility groups | 1,564 passed, 1 skipped, 2 warnings, 127.52 seconds; includes all 191 Phase 3 cases plus findings/store/taxonomy, workflow/review, security/permission/worker, MCP, UI, session/resume and config |
| Final `venv-linux/bin/python -m pytest -q` | 3,427 passed, 1 skipped, 2 warnings, 248.68 seconds |
| `venv-linux/bin/pyright` | 0 errors, 0 warnings, 0 informations |
| Explicit pyright of component and acceptance script | 0 errors, 0 warnings, 0 informations |
| Final wheel build / isolated client import / manifest / source parity / query behavior | Passed; 190 wheel members; no corpus/generated runtime included; no package installation |
| `git diff --check` / diff inspection | Passed; tracked implementation diff and new source/tests/docs inspected |
| Final real acceptance | Passed on final source: actual discovery/search/get, denial, isolation, operator flow, CWE-639 promotion, retry, cancellation and timeout cleanup. Repository initialization 9.101 seconds; isolated-project initialization 2.768 seconds; existing budget 15 seconds. |

The skip is the existing opt-in live-model characterization requiring explicit
environment opt-in and provider credentials. No new skip was added. Both warnings
are expected malformed custom-provider fixture warnings. The Burp live test
excluded by pytest.ini was not separately run; this review did not perform live
target penetration testing or live-provider calls. Full-suite and type-check
commands were rerun after the final query changes.

The final focused command was:

```sh
venv-linux/bin/python -m pytest -q tests/cwe tests/data/test_findings_store.py tests/data/test_vulnerability.py tests/tools/test_finding.py tests/tools/test_workflow.py tests/security tests/ui tests/integration/test_mcp_integration.py tests/state/test_session_store.py tests/agent/test_resume_after_compaction.py tests/runtime/test_config.py
```

Activation recommendation: keep `mcp_servers` empty by default and explicitly
activate the optional entry in user configuration only after deployment setup.
The existing schema and setup documentation are sufficient. Do not put a
deployment-specific /work path in Config defaults. Active configuration was
not edited, and no startup/default activation behavior changed.

Remaining limitations/backlog: this is lexical search and minimization, not
semantic matching or universal secret detection. An unlabelled secret or target
alias made entirely of mechanism vocabulary is indistinguishable from mechanism
words. Query minimization may abstain or reduce recall; useful actual CWE-639
retrieval was demonstrated. Trusted dependencies must stay immutable during
review: the controller fingerprints launcher/server/manifest/XML, not every
file in runtime/. Transitive dependencies are not completely locked. Generated
binary dependencies must match /usr/bin/python3's ABI; both interpreters in the
tested environment are 3.14.4. Other ABIs/platforms were not live-tested. Hashes
are consistency pins, not publisher signatures; full generic XSD validation
and cross-process writer coordination remain outside the initial design.

All requested invariants are true within these stated boundaries: Phase 1
authoritative; semantic variants absent; existing local/persisted CWE immutable;
ranking/LLM/YOLO/MCP permission cannot promote; operator fit review and exact
lookup required; only Mapping Usage Allowed promotable; Allowed-with-Review
distinct; MITRE Variant separate; confirmation independent of enrichment;
Store.save write-once; classification update separate; retry/resume no retrieval;
Candidate identity/routing/coverage/proof semantics unchanged; no commit/push.

The final acceptance record is `artifacts/cwe-integration.json`; the isolated
wheel record is `artifacts/cwe-wheel-review.json`. Both are ignored artifacts.
The under-load failure described in CWE-R3 is retained in this report rather
than concealed by the later successful runs. No acceptance worker/server
process was left running.

Incremental review edits are limited to query minimization, TUI command task
ownership/shutdown, focused enrichment/persistence regression tests, the feature
documentation and this review report. Existing Phase 3 store/policy/confirmation,
component/setup/packaging changes were reviewed and left intact.

Exact `git status --short --untracked-files=all`:

```text
 M .gitignore
 M pyproject.toml
 M src/findings/store.py
 M src/permission/runtime/execution.py
 M src/tools/workflow/finding.py
 M src/ui/commands/slash_handler.py
 M src/ui/commands/slash_items.py
 M src/ui/core/app.py
 M src/ui/widgets/text_input_modal.py
 M src/workflow/review.py
 M tests/ui/test_slash_items.py
?? components/__init__.py
?? components/cwe_mcp/__init__.py
?? components/cwe_mcp/catalog.py
?? components/cwe_mcp/contract.py
?? components/cwe_mcp/launch.py
?? components/cwe_mcp/manifest.json
?? components/cwe_mcp/server.py
?? components/cwe_mcp/setup.py
?? docs/phase3-cwe-enrichment.md
?? docs/phase3-cwe-independent-review.md
?? docs/phase3-cwe-verification.md
?? scripts/check_cwe_mcp.py
?? src/findings/cwe_enrichment.py
?? src/ui/commands/cwe_enrichment.py
?? tests/cwe/__init__.py
?? tests/cwe/conftest.py
?? tests/cwe/test_enrichment.py
?? tests/cwe/test_persistence.py
?? tests/cwe/test_server.py
?? tests/cwe/test_ui.py
```

PHASE 3 REVIEW PASSED — READY TO COMMIT
