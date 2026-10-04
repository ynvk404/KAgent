# Phase 3 verification and handoff

Verification date: 2026-10-04. Implementation details and deployment instructions
are in [phase3-cwe-enrichment.md](phase3-cwe-enrichment.md).

## Baseline and preserved contracts

The initial worktree was clean. The Candidate -> latest ValidationResult ->
eligibility -> ConfirmFindingTool -> Phase 1 taxonomy -> Finding -> write-once
report -> notification/retry path was inspected before implementation. Existing
MCP configuration/discovery, Registry permission gating, ExecutionPolicy receipt,
worker mounts, dependency visibility and timeouts were inspected and exercised.

Phase 1 remains authoritative. Semantic variants remain absent. MITRE `Variant`
is an abstraction label. Broad classes can remain unresolved. Only an existing
persisted unresolved report with provable historical/current result and evidence
bindings can begin enrichment. Classified local, promoted and legacy reports
return before external retrieval/review and cannot be externally replaced.

Ranking, LLM output, retrieval permission and YOLO never authorize classification
promotion. Only complete/untruncated `Allowed` Weakness metadata is initially
review-eligible; `Allowed-with-Review` stays distinct and non-promotable. An
explicit numbered selection, independent operator mechanism-fit approval and
matching exact lookup are required. `confirm_finding` has no enrichment dependency.
Ordinary `Store.save` write-once/retry semantics remain intact. The separate
classification update edits only CWE/provenance/revision metadata in the same
report. Candidate identity, routing, coverage, proof authority, finding eligibility,
severity, impact, evidence and OWASP semantics remain unchanged.

## Acquisition and deployed runtime

Official acquisition used exactly CWE 4.20 (2026-04-30), namespace
`http://cwe.mitre.org/cwe-7`, schema 7.3. Both provided audit fingerprints matched:

```text
ZIP: 3976f599e5e5200219a3108bb896d06e2a88fbb293369e1883cb423a5e9d7d50
XML: 1f5a78bd62e00f86436b4fe32d5034a57e8f0da88e4063b2072b664ae510912e
```

XML: 18,192,305 bytes; 969 Weaknesses, 422 Categories, 59 Views. The official XSD
and Terms of Use were also acquired. The ignored `cwe-mcp-deployment/` contains
the exact corpus, reviewed manifest, independent server and deployment-local
SDK/dependencies. Runtime serving code imports no KAgent internals. Deployment
code/manifest parity with the reviewed source was checked after final changes.

`mcp==1.28.1` matches the existing installed/configured SDK. A separate
`pip --target` installation supplied dependencies visible through the actual
read-only `/work` mount. The launcher uses `/usr/bin/python3 -I -B`, with no host
virtualenv imports, environment exports, network access or runtime acquisition.
Neither the KAgent virtualenv nor global packages were modified. MITRE notices
and dependency licensing metadata are retained with the generated deployment.

The ready configuration entry is:

```json
{
  "name": "cwe_catalog",
  "command": "/usr/bin/python3",
  "args": ["-I", "-B", "/work/cwe-mcp-deployment/launch.py"]
}
```

No active user MCP/provider configuration was changed. Activation requires adding
this entry to the existing `mcp_servers` array and restarting discovery. The
deployment is already prepared in this workspace; fresh destinations can use
the documented setup command. Existing destinations are never overwritten.

## Actual integration acceptance

`scripts/check_cwe_mcp.py` exercised actual discovery and Registry execution with
the separate deployed server and official corpus, using dedicated Config objects
and synthetic queries. Findings/workflow acceptance used a temporary isolated
project, actual workflow/result review, evidence, finding confirmation, retrieval
and persisted promotion. Its synthetic review callbacks deliberately exercise
abstention/denial and explicit fit approval; focused Textual tests separately
exercise the actual selection dialog and cancellation cleanup.

Recorded results are in the ignored `artifacts/cwe-integration.json`:

| Measurement | Repository mount | Isolated operator flow |
| --- | ---: | ---: |
| Cold discovery total | 21.413942 s | 4.427441 s |
| Worker preparation | 9.908116 s | 0.291057 s |
| MCP initialization | 11.455047 s | 4.076224 s |
| Existing initialization budget | 15 s | 15 s |

The budget starts after worker preparation; cold total is reported separately.
Both measured initializations passed. No timeout budget or worker isolation was
relaxed. Results verified real search/get, pinned identity, normal permission
denial without dispatch, no target HTTP grants, isolated namespace/network,
hidden control-plane/virtualenv paths, read-only deployment, and process cleanup
after cancellation/timeout. Cleanup tests stall controller delivery after a real
server reply; they do not substitute an ambient process or modify isolation.

The operator flow verified that YOLO plus selection alone cannot promote, that
abstention/denial preserve the unresolved report, and that explicit selection/fit
followed by matching exact lookup promotes official `CWE-639`. Its report and
directory fsync completed; ordinary confirm retry preserved the committed
classification. Official `CWE-862` was independently observed as
`Allowed-with-Review` and rejected by the initial external policy.

## Regression results

Final focused responsibility-group run:

```sh
venv-linux/bin/python -m pytest -q tests/cwe tests/ui tests/runtime/test_version.py tests/security/test_execution_policy.py tests/security/test_offline_worker.py
```

Result: **797 passed in 76.34 seconds**. Earlier targeted runs covered taxonomy,
findings/finalization, workflow review/evidence and permissions before expanding
to this group and the complete suite.

`venv-linux/bin/pyright` and an additional explicit check of
`components/cwe_mcp` plus `scripts/check_cwe_mcp.py` both reported **0 errors,
0 warnings, 0 informations**. The launcher separately printed an informational
new-pyright-version notice; no package update was performed.

A wheel built from a temporary copy of final source passed isolated `-I -B`
client import and manifest-resource checks outside the repository. Critical
packaged source bytes matched final source; corpus and generated dependency
trees were absent. Build dependencies used pip's temporary isolated environment;
the wheel was not installed. An initially overbroad smoke assertion matched
KAgent's existing `src/*/runtime` code; narrowing it to the actual generated
dependency/corpus directories corrected the assertion without changing packaging.

Final complete-suite command:

```sh
venv-linux/bin/python -m pytest -q
```

Result: **3401 passed, 1 skipped, 2 warnings in 292.15 seconds**. The skip is the
existing opt-in live-model characterization test requiring
`KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION=1` and provider credentials. It was not
enabled; no new skips were introduced. Both warnings are existing malformed
custom-provider configuration fixture warnings. All non-live regression groups,
including taxonomy, finding/store/finalization, workflow/review/evidence, MCP,
permissions/execution/worker, UI and sessions/retry/resume, ran in this suite.

`git diff --check` passed. Tracked diff, new source/tests/docs and final
`git status --short --untracked-files=all` were inspected. No unrelated initial
worktree changes existed. No acceptance server/worker processes remain running.

One intermediate version-cache test failed when a concurrent root-local wheel
build created fresh editable metadata while pytest had cached the older installed
version. Task-created metadata was moved to a temporary build directory and
subsequent wheel builds use copied source outside the repository. No version
logic or test expectations were changed to conceal the failure. Final results
below apply to the resulting source state and isolated build approach.

## Changed files

| Responsibility | Files |
| --- | --- |
| Independent server, reviewed schemas/manifest and explicit setup | `components/__init__.py`; `components/cwe_mcp/{__init__,catalog,contract,launch,server,setup}.py`; `components/cwe_mcp/manifest.json` |
| Finding controller and single-report persistence | `src/findings/cwe_enrichment.py`; `src/findings/store.py`; `src/tools/workflow/finding.py`; `src/workflow/review.py` (binding documentation) |
| Explicit operator command and plain scrollable selection | `src/ui/commands/{cwe_enrichment,slash_handler,slash_items}.py`; `src/ui/core/app.py`; `src/ui/widgets/text_input_modal.py` |
| Native write protection for trust anchors and legacy reports | `src/permission/runtime/execution.py` |
| Packaging and generated-artifact exclusion | `pyproject.toml`; `.gitignore` |
| Actual acceptance tooling | `scripts/check_cwe_mcp.py` |
| Focused regressions | `tests/cwe/{__init__,conftest,test_server,test_enrichment,test_persistence,test_ui}.py`; `tests/ui/test_slash_items.py` |
| Documentation | `docs/phase3-cwe-enrichment.md`; this file |

All listed changes belong to this task. No additional agents, commit, push or
active user-config mutation were used. Generated corpus/runtime trees and integration summary
are ignored, not staged for version control.

## Commit boundary and limitations

The shared project Store lock serializes read -> verify -> derive -> prepare ->
final guard -> replace -> publication among cooperating Store instances in one
process/event loop. No report lock spans operator input or MCP retrieval.
Preparation writes/flushes/fsyncs a same-directory temporary file off-thread;
that thread cannot replace the report. Cancellation drains preparation under the
lock and removes the temporary file. Final guards recheck report, revision,
Candidate/result/evidence, source, review ticket, policy and cancellation.

Synchronous `os.replace` is the atomic visibility/commit point, with no await
before snapshot publication. Directory fsync confirms rename durability where
supported. Before commit, failure/cancellation preserves the old authoritative
report. After commit, the visible replacement remains authoritative: directory
fsync failure reports uncertain durability, refresh failure reports committed
replacement/reload, and notifier failure cannot roll back. Retry/resume recover
persisted classification/provenance without retrieval or taxonomy reconstruction.

This is not cross-process CAS or a global ACID transaction. Uncoordinated external
writers are outside the lock boundary. Missing historical binding blocks legacy
enrichment while leaving its finding valid. Manifest/hash responses are
consistency checks under the trusted audited deployment assumption, not proof of
response origin or publisher signatures. Native model writes to the adapter,
deployment and persisted reports are blocked; external maintenance remains an
explicit trusted operation.

Binary dependency wheels must match `/usr/bin/python3`'s ABI (Python 3.14.4 in
this environment). The SDK is pinned, but its transitive dependencies follow
declared ranges rather than a complete lockfile. Full generic XSD validation,
semantic search, automated fit decisions, cross-process transactions and other
mapping usages are outside the initial implementation.

PHASE 3 IMPLEMENTED — READY FOR INDEPENDENT REVIEW
