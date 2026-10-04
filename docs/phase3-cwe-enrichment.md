# Phase 3: pinned local CWE retrieval and operator classification review

This implementation keeps Phase 1 taxonomy authoritative. Its intentional
unresolved broad classes remain unresolved until an operator invokes
`/enrich-cwe <candidate-id>` on an existing persisted finding. An existing
primary CWE, including a historical one with unknown origin, cannot be replaced.
External metadata never changes vulnerability class, severity, impact, OWASP,
evidence, proof authority, routing, coverage, or finding eligibility.

## Audited baseline

`Candidate` identity/fingerprint and `ValidationResult` remain unchanged.
`WorkflowState.eligible_for_finding` still requires the latest confirmed result,
registered matching evidence, and no failed coverage synchronization.
`ConfirmFindingTool` still validates endpoint/origin/method/parameter, the trusted
verification certificate where a policy is bound, and evidence integrity before
saving or notifying. The existing result-review tickets, complete review
snapshots, evidence gates and write-once/retry behavior remain intact.

`Store.save` still finds the first persisted Candidate report, restores every
`Finding` field from that report, and holds its mutation lock while a cancelled
background save finishes. It never consults the CWE server. Retry, resume,
notification and ordinary `read_report` perform no enrichment retrieval/review.
Semantic variants remain absent; MITRE's `Variant` is only a CWE abstraction.

The actual MCP path is existing configured discovery -> `Registry.execute` ->
normal permission decision -> `ExecutionPolicy` receipt -> isolated worker ->
`MCPTool.run`. Each invocation opens a fresh isolated stdio server and closes it.
The initialization budget is 15 seconds **after worker preparation**; MCP calls
use the existing 120-second budget. Worker inspection has its existing separate
120-second budget. None of these policies or isolation rules was loosened.

## Component and explicit setup

Source is under `components/cwe_mcp/`; serving code imports no KAgent runtime
modules. `setup.py` acquires/builds only at setup time. `launch.py`, `server.py`,
`catalog.py`, and `contract.py` are the independent runtime component.
`scripts/check_cwe_mcp.py` is controller-side acceptance tooling, not server code.

The generated deployment is deliberately separate from source and can live
outside the repository at an operator-selected canonical absolute path. It must
not overlap worker-writable output or protected controller storage. A sibling
directory can contain:

```text
/path/to/cwe-mcp-deployment/
  launch.py
  server/cwe_mcp/{__init__,contract,catalog,server}.py
  runtime/                         # separately installed SDK/dependencies
  runtime.zip                      # offline-prepared Python import archive
  manifest.json
  corpus/cwec_v4.20.xml
  corpus/cwe_schema_v7.3.xsd
  corpus/CWE-TERMS-OF-USE.html
```

The deployment is generated and not committed. The repository keeps a
`.gitignore` entry for a legacy repository-local copy, but normal runtime no
longer requires that directory. The worker exposes only the configured
deployment directory, read-only at `/opt/kagent-cwe-mcp/`, and only for the
exact designated `cwe_catalog` launch. It does not mount the parent or sibling
directories. `/usr/bin/python3` runs with `-I -B`; the launcher explicitly adds
only the deployment-local runtime archive, runtime and server directories. It
does not import from the hidden KAgent virtualenv, export environment variables,
or symlink to host
dependencies. Python bytecode writes and server logs are disabled. The server
performs no runtime acquisition, network/target interaction, query
logging/retention or application writes.

Setup prepares `runtime.zip` with the serving `/usr/bin/python3` interpreter.
Pure Python modules, precompiled bytecode, resources, licenses and distribution
metadata are bundled in a compressed archive to reduce dependency import I/O on WSL-mounted drives.
Packages containing native extensions remain in `runtime/`, with their original
filesystem paths. The launcher prefers the archive; existing unprepared trees
remain compatible but slower. The launcher reads the prepared archive once into
a process-private sealed Linux memfd and imports through its `/proc/self/fd`
path. This uses the existing worker `/proc` and resource limits: no extraction,
host/tmp cache, added mount, shared session or persistent write. The compressed
archive is limited to the existing 16 MiB per-file bound. Serving never creates
or updates deployment bytecode or the archive, and every RPC still starts a
fresh isolated process. Catalog startup reuses the bounded XML parser's tree,
instead of constructing a second full tree.

Prepared archives contain a complete dependency file/directory inventory with
SHA-256 hashes, including native packages and resources left on disk. The
worker verifies it against the current no-follow runtime inspection before
spawn, under the existing cancellable 120-second inspection budget. Changed,
added or removed dependencies fail closed before initialization; preserved size
or mtime does not bypass content verification. Old archives without this
inventory require explicit re-packing. Serving never regenerates them.

An existing deployment can receive just the offline import preparation, without
reinstalling dependencies, downloading corpus data or rebuilding the tree:

```sh
/usr/bin/python3 -I -B components/cwe_mcp/pack_runtime.py /path/to/cwe-mcp-deployment
```

Use the current reviewed `launch.py` with that prepared archive. The source
signature includes archive bytes; adding, replacing or removing it during
classification review invalidates the review. Policy and worker deployment
paths must match before discovery, dispatch and trusted-source verification.
KAgent's ordinary permission/tool/session context has its usual retention; this
feature does not claim universal context egress or non-retention guarantees.

Fresh setup (never overwrites an existing destination):

```sh
venv-linux/bin/python -m components.cwe_mcp.setup /path/to/cwe-mcp-deployment
venv-linux/bin/python -m scripts.check_cwe_mcp --deployment /path/to/cwe-mcp-deployment
```

Set `cwe_mcp_deployment_path` in the operator's KAgent config to that same
absolute path. Ordinary startup reuses the existing deployment; rebuild it only
when the component source, pinned corpus, or runtime dependencies change. Setup
refuses to overwrite an existing destination. A new destination can be built
and accepted before an operator switches the configured path.

This task acquired and independently hashed the exact official
[MITRE ZIP](https://cwe.mitre.org/data/xml/cwec_v4.20.xml.zip) and
[schema](https://cwe.mitre.org/data/xsd/cwe_schema_v7.3.xsd).
The server uses `mcp==1.28.1`, matching KAgent's configured and installed SDK.
Only the deployment's `runtime/` received an isolated SDK `pip --target` install;
the existing KAgent virtualenv and global environment were not modified.
The SDK's declared dependencies were installed as compatible binary wheels;
their distribution metadata and license files remain in the deployment.
Wheel verification also used pip's temporary isolated build environment for
existing setuptools/wheel build dependencies; neither the wheel nor build
dependencies were installed into KAgent. The wheel includes the independent
component's code/manifest and excludes corpus/deployment dependencies.

Rebuilding dependencies uses the pinned SDK with its declared dependency ranges,
not a complete transitive lockfile. Review the resulting environment as part of
deployment review.

MITRE corpus copies include the official Terms of Use page and copyright
notice; distribution must preserve those notices and licensing conditions.
See [MITRE Terms of Use](https://cwe.mitre.org/about/termsofuse.html).
This corpus is separately licensed; it is not relicensed as KAgent source.

## Exact ready-to-use MCP configuration

Set the top-level deployment path and add this **entry** to KAgent's existing
`mcp_servers` array when activating the feature. No active MCP/provider/user
configuration was edited by this task. The host path is explicit operator
configuration; the worker-visible path is fixed. Arbitrary servers sharing a
display name are not accepted.

```json
{
  "cwe_mcp_deployment_path": "/path/to/cwe-mcp-deployment",
  "mcp_servers": [
    {
      "name": "cwe_catalog",
      "command": "/usr/bin/python3",
      "args": ["-I", "-B", "/opt/kagent-cwe-mcp/launch.py"]
    }
  ]
}
```

Do not add `env`. Do not configure a host virtualenv path. The existing worker
still requires Linux/bubblewrap/prlimit and the deployment ABI must match
`/usr/bin/python3` (Python 3.14 in the verified environment).

## Pinned identity and startup checks

Reviewed `manifest.json` and code establish the expected identity:

```text
Manifest schema: 1
Catalog: CWE 4.20, 2026-04-30
XML schema identity: http://cwe.mitre.org/data/xsd/cwe_schema_v7.3.xsd
XML namespace: http://cwe.mitre.org/cwe-7
Adapter: 1.0.0
Search: weighted-token-v1
ZIP SHA-256: 3976f599e5e5200219a3108bb896d06e2a88fbb293369e1883cb423a5e9d7d50
XML SHA-256: 1f5a78bd62e00f86436b4fe32d5034a57e8f0da88e4063b2072b664ae510912e
```

ZIP/XML hashes matched the supplied audit fingerprints. These are consistency
pins, not publisher-signed checksums. The acquired XML is 18,192,305 bytes and
contains 969 Weaknesses, 422 Categories, and 59 Views. XSD bytes were acquired at
setup; their observed SHA-256 was
`690dedeed4e12eb8ba7244bbab90176afac549cfd6403de37000de7481e45f98`.
Runtime never resolves schema URLs or external entities.

Startup requires the reviewed manifest, bounded UTF-8 XML with matching hash,
correct root/name/version/date/namespace/schema location, supported catalog
groups and entry kinds, globally unique IDs, mandatory entry attributes and
known status/abstraction/structure/View-type/mapping-reason enums. DTD/entities
are rejected before parsing. Depth is limited to 64, node count to 500,000, and
XML input to 32 MiB. This is a pinned adapter validation, not a generic full-XSD
validation engine. Genuinely missing mapping guidance remains explicitly
incomplete and non-promotable, never implicitly Allowed.

## Wire schema, bounds and stable search

Exactly `search_cwe` and `get_cwe` are exposed, with the exact request schemas
in `contract.py` (`additionalProperties: false`, strict integer validation).
Their KAgent names are `mcp_cwe_catalog_search_cwe` and
`mcp_cwe_catalog_get_cwe`. Booleans are never accepted as IDs/result counts.

Both return one MCP text block containing JSON. `SearchResponse`,
`LookupResponse`, `CorpusIdentity`, `Candidate`, `SearchCandidate`, mapping
notes and suggestions have explicit strict schemas, required keys and forbidden
extras. Lookup distinguishes Weakness, Category, View and nonexistent IDs.
Weakness Abstraction and Structure are retained; Category/View use nulls and
Summary/Objective text. Mapping usages remain separate.

| Bound | Value |
|---|---:|
| Query | 512 Unicode characters / 2048 UTF-8 bytes |
| Unique normalized query tokens | 32 |
| Results | 1–5 (default 5) |
| Name / description | 512 / 1024 characters |
| Combined mapping guidance | 4096 characters |
| Rationale / comments | 1024 each |
| Reason / suggestion comment | 256 / 512 characters |
| Reasons / suggestions | 16 each |
| Truncation markers | 16 strings, 64 characters each |
| Adapter version | 32 characters |
| Serialized MCP response | 64 KiB |
| Operation budget after loading | 2 seconds |

Envelope accounting serializes the real MCP text wrapper (including escaped
JSON), with an additional 1024-byte reserve for JSON-RPC framing and KAgent's
small integer request IDs. Search drops lowest-ranked whole candidates when
necessary and sets `results_limited`. Truncated records identify affected fields
and are incomplete; exact lookup returns bounded incomplete data or a stable
error. No JSON is cut mid-object. Stable MCP `isError=true` errors contain only
schema version, code and fixed safe message (`INVALID_ARGUMENT`, `CORPUS_INVALID`,
`QUERY_TIMEOUT`, `RESPONSE_LIMIT`, `INTERNAL_ERROR`).

`weighted-token-v1` applies NFKC, then casefold, then maximal Unicode
alphanumeric runs (`[^\W_]+`; underscore separates). Query tokens are unique.
For each token present in name/alternate-term/description token sets, weights
are 8/4/1; repeat occurrences add nothing. Canonical whole trimmed `CWE-N`
queries prioritize an exact Weakness. Ordering is exact match descending,
score descending, numeric ID ascending. Zero-score non-exact records are
excluded. Categories/Views are exact-lookup only. No stemming, generated
synonyms, embeddings, model ranking or semantic variants are involved.

## Trust, minimization and operator UX

The audited deployment (including dependencies), reviewed manifest and explicit
operator configuration are trusted code/configuration. Returned corpus hashes
are independently compared with the expected identity; a claimed hash is **not**
cryptographic authentication of an arbitrary tool response. The controller
checks exact MCPTool/config/server/session/tool/schema/ExecutionPolicy identity,
then snapshots configuration, deployment code, manifest and pinned XML integrity.
Changed source/tool/configuration during retrieval or review invalidates it.
The native file-tool write gate also protects the imported component source and
the explicitly configured CWE deployment as control-plane resources, including
under YOLO.
Native writes to legacy `findings/` are also blocked, so models cannot forge
historical report bindings or erase an existing classification. Read-only
worker mounts, network authority and general MCP permissions are unchanged. Setup/maintenance is an external operator operation; model file
tools cannot replace these trust anchors before an enrichment action.

Responses are untrusted data. The client independently rejects malformed types,
extra/duplicate JSON keys, duplicate candidate IDs, invalid ranks/order,
inconsistent ID/status/completeness/truncation fields, wrong schema/corpus/hash/
adapter/search algorithm, and oversized content. Accepted normalized candidate
sets exist only in the controller closure. Models cannot supply promotion
candidate/provenance objects, invoke a promotion tool, or select free-form IDs.

The minimized query uses only the persisted canonical class and bounded title. A fixed mechanism-word allowlist excludes unknown tokens,
URLs, target identifiers and credential-labelled fragments **before** the
existing redactor. Both bounded input fragments are Unicode-normalized; terminal
escape sequences and format controls are removed before credential detection,
while whitespace remains a separator. A credential label or Bearer scheme
discards the remaining fragment, including quoted values and continuation lines.
Unlabelled dictionary words cannot be distinguished from mechanism words by
this lexical minimizer; it is not a universal secret detector.
Evidence, HTTP traffic, payloads and impact bodies are not
used for search. Empty safe queries are rejected. No LLM is invoked for query
construction and no raw query/candidate set is durable classification state.

The command first reads the existing report. A classified report returns before
source access or review. An unresolved report must have unambiguous metadata,
matching Candidate identity/class/endpoint/origin/method/parameter, exact
historically recorded current confirmed result binding, matching evidence refs
and freshly verified evidence. Failure preserves the existing finding.

Only complete, untruncated, non-Deprecated/non-Obsolete Weakness entries with
`Mapping Usage = Allowed` are displayed for numbered selection (or `0` to
abstain). Draft/Incomplete/Usable maturity and Variant abstraction can be valid.
Allowed-with-Review stays distinct and non-promotable in this initial policy.
For example, official CWE-862 is Allowed-with-Review; it is correctly rejected.

The bounded selection dialog shows plain escaped source metadata and supports
PageUp/PageDown. Cancelled operator input clears its own overlay; overlapping
input cannot replace another caller's pending question. A separate explicit mechanism-fit review uses the underlying
operator prompter, bypassing YOLO auto-approval. Ranking is a lexical score,
never confidence/proof. Source URLs/instructions are displayed as data and
never followed/executed. Selection/review authorizes classification only.
The TUI owns command tasks and cancels/drains them before shutdown closes
runtime resources, including any outstanding temporary-report preparation.

After selection, a separate normal Registry invocation/permission/receipt calls
exact `get_cwe`. It must return the selected ID, expected identity, renewed
eligibility and exactly the reviewed normalized classification metadata
(including name/description/notes/status/abstraction/structure/completeness).
Search-only rank/score flags are excluded from that comparison. No substitute
lookup record is silently promoted.

## One-artifact transaction and recovery

New reports record canonical class and a historical confirmation binding to the
complete Candidate/current result/result position/evidence snapshot. Verified
local provenance/revision are recorded only when Phase 1 actually assigns a CWE.
Legacy reports remain readable without provenance; missing origin is presented
as `legacy/unknown` and no classification/history is inferred or migrated on load. A
legacy unresolved report without provable historical bindings cannot be enriched.

Primary CWE, minimal external provenance and revision are all stored as metadata
in the **same Markdown report**. External provenance retains selected CWE,
operator-reviewed origin, server/search/lookup identity, pinned corpus identity,
adapter/algorithm, revision and a digest binding report/result/evidence/reviewed
candidates/source/ticket/policy. It stores no queries, raw traffic, credentials,
large candidate sets or fabricated historical timestamps.

`Store.promote_classification` is distinct from ordinary write-once `save`.
It modifies only CWE, classification provenance and revision header rows,
preserving all unrelated Markdown bytes (including CRLF), report path, creation
time, title, severity, URL, type/class, OWASP, impact, evidence, reproduction,
remediation and one-report-per-Candidate behavior. Ambiguous metadata fails
safely before retrieval/mutation.

The shared project/store asyncio lock coordinates cooperating Store instances,
ordinary save/retry and promotions in **one process/event loop**. It covers
read -> verify -> derive -> prepare -> final guard -> replace -> publish. No
lock is held during operator input or MCP calls. Evidence uses the existing
workflow receipt/read gate without invoking `record_result`, writing proof
certificates or changing workflow/coverage.

A collision-safe same-directory temporary file is written/flushed/fsynced in an
offloaded preparation step; that thread **cannot replace the report**. A
cancelled preparation is drained under the lock and its temporary file removed.
After that await, full report digest/revision/unresolved state and Candidate/
result/evidence/ticket/source/policy bindings are rechecked, as is cancellation.
Synchronous `os.replace` on the controller loop is the atomic visibility/
linearization point. No await separates the final guards from replacement and
snapshot publication. Directory fsync confirms rename durability where
supported. No cross-process CAS, multi-file transaction or global ACID guarantee
is claimed; uncoordinated external writers/processes are outside this boundary.

Before replace: failure/cancellation leaves the old report authoritative, with
no promoted runtime state or success notification. After replace: the new
visible artifact is authoritative. Directory-fsync failure is reported as
visible replacement with uncertain durability. Snapshot-refresh failure reports
committed replacement and instructs reload. Notifier failure never rolls back.
Cancellation after commit preserves the committed classification; retry/resume
recover from persisted data without retrieval or taxonomy reclassification.
Overlapping/stale attempts cannot clear or replace a successful promotion.

## Verification record

Focused tests cover server/strict client schemas, bounds and search behavior,
local-first/legacy handling, operator-only selection/fit, actual Registry receipt
and denial paths, source/result/evidence/policy changes, overlapping reviews,
classification-only byte preservation, retry/resume, cancellation before/after
replace and failure/durability/notification behavior. Existing live/external
skip semantics are preserved.

Real acceptance runs `scripts/check_cwe_mcp.py --deployment <absolute-path>`
with the official corpus and separately installed server. It uses the
repository's real mounts, configured
MCP discovery and Registry execution, and verifies denial, namespace/protection/
read-only mounts, no target HTTP grants, and process cleanup on cancellation and
timeout. Cleanup tests deliberately stall controller delivery **after a real
server lookup**, rather than changing server behavior or isolation. A separate
temporary project/config exercises real retrieval -> operator abstention/denial
under YOLO -> explicit selection/fit -> exact lookup -> persisted promotion ->
ordinary retry. Only synthetic mechanisms are used. The active user config is
never modified. Cold preparation/initialization/discovery measurements and
acceptance assertions are written to `artifacts/cwe-integration.json`.

Final test totals, timing and readiness verdict are recorded after verification
in `docs/phase3-cwe-verification.md`.
