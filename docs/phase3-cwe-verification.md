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
and Terms of Use were also acquired. The generated deployment is now at the
operator-configured external path
`/mnt/d/DOANTOTNGHIEP/cwe-mcp-deployment/` for this workspace. It contains the
corpus, reviewed manifest, independent server and deployment-local
SDK/dependencies. Runtime serving code imports no KAgent internals. Deployment
code/manifest parity with the reviewed source was checked after final changes.
The repository-local generated directory was removed after external acceptance;
`components/cwe_mcp/` remains the source of record.

`mcp==1.28.1` matches the existing installed/configured SDK. A separate
`pip --target` installation supplied dependencies visible through the actual
read-only `/opt/kagent-cwe-mcp` mount. The launcher uses `/usr/bin/python3 -I -B`, with no host
virtualenv imports, environment exports, network access or runtime acquisition.
Neither the KAgent virtualenv nor global packages were modified. MITRE notices
and dependency licensing metadata are retained with the generated deployment.

Set the explicit host deployment path in KAgent config, then use this MCP entry:

```json
{
  "cwe_mcp_deployment_path": "/path/to/cwe-mcp-deployment",
  "mcp_servers": [{
    "name": "cwe_catalog",
    "command": "/usr/bin/python3",
    "args": ["-I", "-B", "/opt/kagent-cwe-mcp/launch.py"]
  }]
}
```

No active user MCP/provider configuration was changed. Activation requires adding
this entry and explicit host path to the existing config, then restarting
discovery. Ordinary startup reuses the deployment. Setup can build a fresh
destination using the documented command and refuses to overwrite an existing
one.

## Actual integration acceptance

`scripts/check_cwe_mcp.py` exercised actual discovery and Registry execution with
the separate deployed server and official corpus, using dedicated Config objects
and synthetic queries. Findings/workflow acceptance used a temporary isolated
project, actual workflow/result review, evidence, finding confirmation, retrieval
and persisted promotion. Its synthetic review callbacks deliberately exercise
abstention/denial and explicit fit approval; focused Textual tests separately
exercise the actual selection dialog and cancellation cleanup.

The relocation-only acceptance, before the handshake reliability follow-up
below, recorded:

| Measurement | Repository project, external mount | Isolated operator flow, external mount |
| --- | ---: | ---: |
| Cold discovery total | 11.960413 s | 9.502110 s |
| Worker preparation | 6.069432 s | 4.735428 s |
| MCP initialization | 5.814852 s | 4.760828 s |
| Existing initialization budget | 15 s | 15 s |

The budget starts after worker preparation; cold total is reported separately.
Both measured initializations passed. No timeout budget or worker isolation was
relaxed. Results verified real search/get, pinned identity, normal permission
denial without dispatch, no target HTTP grants, isolated namespace/network,
hidden control-plane/virtualenv paths, absence of `/work/cwe-mcp-deployment`,
read-only external deployment, and process cleanup after cancellation/timeout.
Cleanup tests stall controller delivery after a real
server reply; they do not substitute an ambient process or modify isolation.
That relocation run additionally canceled initialization itself and verified cleanup.
All ten completed fresh-process handshakes took 4.058216–5.814531 seconds. One
separate initialization was deliberately canceled; it is recorded as incomplete,
not counted as a successful timing sample. Timeout cleanup used the original
120-second call deadline, without temporarily replacing the timeout constant.

The operator flow verified that YOLO plus selection alone cannot promote, that
abstention/denial preserve the unresolved report, and that explicit selection/fit
followed by matching exact lookup promotes official `CWE-639`. Its report and
directory fsync completed; ordinary confirm retry preserved the committed
classification. Official `CWE-862` was independently observed as
`Allowed-with-Review` and rejected by the initial external policy.

## Original Phase 3 regression results

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

Original complete-suite command (before the relocation follow-up):

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
| Independent server, reviewed schemas/manifest and explicit setup | `components/__init__.py`; `components/cwe_mcp/{__init__,catalog,contract,launch,server,setup,pack_runtime}.py`; `components/cwe_mcp/manifest.json` |
| Finding controller and single-report persistence | `src/findings/cwe_enrichment.py`; `src/findings/store.py`; `src/tools/workflow/finding.py`; `src/workflow/review.py` (binding documentation) |
| Explicit operator command and plain scrollable selection | `src/ui/commands/{cwe_enrichment,slash_handler,slash_items}.py`; `src/ui/core/app.py`; `src/ui/widgets/text_input_modal.py` |
| Native write protection for trust anchors and legacy reports | `src/permission/runtime/execution.py` |
| Explicit deployment binding and archive preflight | `src/config/config.py`; `src/cli/runtime.py`; `src/tools/mcp/{cwe_deployment,integration}.py`; `src/permission/worker/worker.py` |
| Packaging and generated-artifact exclusion | `pyproject.toml`; `.gitignore` |
| Actual acceptance tooling | `scripts/check_cwe_mcp.py`; `scripts/check_cwe_mcp_startup.py` |
| Focused regressions | `tests/cwe/{__init__,conftest,test_server,test_enrichment,test_persistence,test_ui,test_runtime_pack}.py`; `tests/ui/test_slash_items.py` |
| Documentation | `docs/phase3-cwe-enrichment.md`; this file |

All listed changes belong to this task. No additional agents, commit, push or
active user-config mutation were used. Generated corpus/runtime trees and integration summary
are ignored, not staged for version control.

## External deployment relocation follow-up

The source remains in `components/cwe_mcp/`. Only the generated deployment
directory moved to `/mnt/d/DOANTOTNGHIEP/cwe-mcp-deployment/`; neither
`integrations/` nor repository source was moved. `cwe_mcp_deployment_path` is an
explicit operator setting, and the worker mounts exactly that canonical tree
read-only at `/opt/kagent-cwe-mcp/` only for the designated CWE server. No parent
or sibling path is mounted. The registry permission gate, YOLO boundary,
network isolation and Phase 3 trust/promotion semantics remain unchanged.

The original post-removal acceptance passed with the repository-local deployment
absent. Two preceding attempts reached the existing 15 second MCP handshake
deadline; the timeout was not changed. The successful sequential run completed
both initializations inside the original budget and verified search/get,
operator review, CWE-639 promotion, retry, and cancellation/timeout cleanup.

## Four review fixes

The worker now rejects deployment roots equal to, below, or above its writable
output directory, and rejects overlaps with protected controller storage. A
read-only CWE bind can no longer acquire a writable alias through the output
mount. Ancestor device/inode checks also reject differently spelled paths to
the same directory, including case aliases on WSL drives. Symlink, hardlink,
special-file and canonicalization checks remain.

The policy stamp now includes the worker's deployment path. Shared validation
requires exact policy/worker agreement before discovery, Registry dispatch and
trusted-source verification. Discovery and RPC dispatch also recheck after
initialization so a changed configuration cannot dispatch against stale state.

Startup cancellation closes the SDK exit stack in its owning task even before
initialization returns. Repeated caller cancellation is deferred while that owner
finishes cleanup. Real-worker regression tests cover cancellation, repeated
cancellation and the unchanged 15-second initialization timeout, including task
identity and absence of unhandled async teardown errors.

Profiling identified dependency imports as the main initialization cost (5.60 s
versus 1.34 s for catalog loading in the initial probe). The independent offline
`components/cwe_mcp/pack_runtime.py` helper prepares a Python import archive with
bytecode from the serving interpreter. Native-extension packages keep their
original filesystem paths. The existing external deployment received only the
reviewed launcher update and this archive; corpus and installed dependencies
were not rebuilt, moved, acquired or installed. Setup prepares the archive for
new deployments. Existing unprepared trees remain compatible but slower.

The archive is a generated deployment artifact, never repository source.
Trusted-source signatures include its bytes and presence/absence. Adding,
changing or removing it during review invalidates classification review.
There is still no generic mount interface, persistent shared RPC process,
inspection cache, network change, or timeout increase. Each RPC starts a fresh
isolated worker and performs current-tree inspection; its startup now has
substantially more headroom in the measured external-deployment acceptance.

Post-fix focused verification covered `tests/cwe`, MCP integration, config,
execution policy, worker startup/isolation/responsiveness and operator review:
**416 passed, 2 existing warnings in 75.54 seconds**. The subsequent directory
identity refinement passed **65 worker tests in 19.80 seconds**, including the
two added physical-path alias cases. Live-model opt-in behavior was preserved.

The relocation-fix source state, including both new alias cases, passed the complete
suite with **3476 passed, 1 skipped, 2 warnings in 369.50 seconds**:

```sh
PYTHONDONTWRITEBYTECODE=1 venv-linux/bin/python -B -m pytest -q -p no:cacheprovider
```

The single skip is the existing opt-in live-model test; both warnings are the
existing malformed-provider configuration fixtures. Configured pyright and the
explicit component/acceptance-script check each reported **0 errors, 0 warnings,
0 informations**. `git diff --check` passed. Final checks verified source parity,
the unchanged pinned XML hash, absence of the repository-local deployment and
no remaining acceptance workers. Normal user config still has no deployment
path or MCP server entry. No packages were installed and no commit/push was made.

## Handshake reliability follow-up

An independent review observed a real 15-second initialization timeout while
pyright and dependency/archive inspection were running concurrently, despite
successful sequential initialization. The stdio server does not answer
initialization until dependency imports and pinned catalog construction finish.
Worker preparation is measured separately and remains outside that deadline.

Profiling the previous deployment in the existing worker measured dependency
import wall/CPU time of 2.817098/1.079445 seconds. Catalog construction took
1.534209 seconds, with peak RSS 306400 KiB; one pyright-loaded catalog sample
took 4.572500 seconds. The launcher still performed many ZIP import reads over
the WSL drive, and catalog validation retained one complete XML tree before
building another with `ET.fromstring`. These startup costs made initialization
sensitive to filesystem and memory/CPU contention.

The compressed runtime archive is now read once into a sealed, process-private
Linux memfd, and ZIP imports/resources/metadata use its existing `/proc/self/fd`
path. There is no new mount, persistent cache, extraction or shared MCP process.
The archive is 6066911 bytes and respects the unchanged 16 MiB worker per-file
limit. Catalog construction reuses the tree produced by the bounded pull parser.
A real-worker probe measured peak RSS 212276 KiB and verified that all 1450
official entries and the complete search index have exactly the same normalized
digests as the previous deployment:

```text
entries: 57a87fe22eb8a85c33689e4abd6c12e6cc582e6d5cde1cfa3b0a650d0878c0ac
index:   afad20e68d79a1984d55c988a46eae7f7a56eb17c5cadb49a3febf0ae9865c41
```

The archive includes a 1137-entry dependency inventory. Current file contents
(including native packages and resources), additions, removals and directory
names/types are checked during existing cancellable worker preflight. Changes with
preserved size/mtime also fail before spawn. Missing/invalid inventory fails
closed for prepared archives; explicit offline re-packing repairs it. Serving
never regenerates an archive. Regression tests cover stale-source/native/resource
changes, additions/removals, malformed/missing inventory, re-packing, sealed-memory
imports/resources/metadata, single XML parsing and cancellation during hashing.

`scripts/check_cwe_mcp_startup.py --deployment <absolute-path> --rounds 5`
exercises fresh discovery/search/get processes first sequentially and then while
actual configured pyright plus dependency/archive inspection run concurrently.
It changes no timeout constants or permission decisions. "Cold" here means a
fresh isolated Python process, without dropping the host OS filesystem cache.
Its bounded JSONL output is stored in ignored `artifacts/cwe-startup-reliability.jsonl`.

The completed run passed **30 fresh isolated processes**: five sequential
discovery/search/get rounds and five rounds under pyright plus continuous
dependency/archive inspection. All real search/get responses and source bindings
passed. Sequential initialization was **2.361197–4.944775 seconds**; loaded
initialization was **4.714900–7.004295 seconds**, within the unchanged 15-second
deadline. The additional dependency hashes increase preflight latency; that
latency is reported separately rather than counted as a handshake improvement.

Final focused responsibility groups passed **406 tests, 2 existing warnings in
66.03 seconds**. The complete suite then passed **3488 tests, 1 existing live-model
skip, 2 existing fixture warnings in 340.02 seconds** with the same bytecode/cache
disabled command documented above. No skip semantics were relaxed.

Configured pyright and the explicit component/acceptance-script check each
reported **0 errors, 0 warnings, 0 informations**. The subsequent complete real
acceptance passed discovery/search/get, normal permission denial, network/mount
isolation, cancellation, the actual 120-second RPC timeout, initialization
cancellation, explicit mechanism-fit review, CWE-639 promotion and persisted
retry. Its ten successful fresh-process initializations took
**3.030234–5.929646 seconds**; the deliberately cancelled initialization remains
separately marked incomplete. Combined with the reliability run, all **40
successful initializations** stayed below the original 15-second deadline.

Final acceptance discovery measurements (seconds):

| Measurement | Repository project | Isolated operator flow |
| --- | ---: | ---: |
| Worker preparation, including dependency verification | 14.546650 | 16.799926 |
| Initialization | 3.472381 | 5.929779 |
| Cold discovery total | 18.072695 | 22.742354 |

Results are in ignored `artifacts/cwe-integration.json`. Corpus and installed
dependencies were reused; only deployed launcher/catalog source and the prepared
archive were updated offline. The user config was not activated. No packages
were installed and no commit/push was made.

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
