# KAgent

KAgent is an LLM-powered web penetration-testing research project. It is under
active development and is not presented as production-ready.

It is intended for explicitly authorized web-security testing in local or
private labs, such as OWASP Juice Shop and DVWA. A name such as `juice.lab` is
an operator-defined local alias, not a hard-coded KAgent target.

KAgent uses one lab response policy: bounded HTTP bodies from native requests
and scoped Browser/Burp getters remain exact for Agent and validator analysis.
The configured LLM may receive application credentials present in those bodies.
Scope and execution permissions establish access rights; they do not establish
that a target is a lab. Operators must use authorized lab applications only.

Private observations, workflow manifests and sessions can retain these bounded
raw bodies, including target credentials. Hex body encoding is not encryption.
Body hashes and excerpt offsets describe the retained producer representation:
native decoded bytes or a bounded captured string, rather than original wire
bytes. Resume restores retained proof only when its source store is available;
historical findings remain historical and grant no new execution rights.
Request credential previews, provider configuration, reusable memory, findings
and report exports keep their existing protection. A known managed internal
secret echoed in a body causes outbound analysis to omit that body explicitly;
the raw source is unchanged. Tool display/debug events show source metadata.

## Architecture and workflow

The Python 3.11+ runtime provides a CLI and Textual TUI. The CLI loads
configuration, target and session state, then connects an LLM provider to the
agent, tool registry, workflow state, skills, and local stores. Skills guide a
high-level flow from discovery through confirmation and reporting; permission
and target-scope checks remain part of the runtime.

The five built-in skills are:

- recon
- web-enumeration
- web-input-analysis
- sql-injection
- cross-site-scripting

## Setup

KAgent requires Python 3.11 or newer. Runtime dependencies are defined in
`pyproject.toml`; `requirements.txt` installs that same project metadata.

```bash
python -m pip install .
```

For local development and tests:

```bash
python -m pip install -e ".[dev]"
```

Optional resilience and syntax-highlighting enhancements can be installed with
`.[enhanced]` (or combined with `.[dev,enhanced]`).

## Running

After installation, start the Textual interface with:

```bash
kagent
```

To declare an authorized target at startup, pass `--target <url>`. Its exact
origin is the default scope; use `/scope add <origin>` in the TUI only when an
additional origin is authorized.

Use `kagent --help` to see supported flags, including provider configuration,
extra skill directories, session resume, and local Burp integration.

Shell runs through a direct asyncio subprocess in the project directory, with
account filesystem/network rights and no OS sandbox. Run KAgent in a dedicated
lab VM/container. Registry approvals, native HTTP scope checks, file-tool roots,
redaction and evidence requirements still apply to their own tools. Shell
stdout is not broker-attested HTTP evidence.

Native `service_discovery` checks the active target's effective TCP port;
`content_discovery` performs bounded same-origin HTTP path discovery. Their
existing scope, request/rate/timeout limits and provenance remain in force.
Nmap/ffuf integration, external wordlist catalog, and integrated Browser MCP
have been removed. Configured command plugins/MCP requiring the old executor
are unavailable; configuration is retained without launching a host fallback.
The old `--browser` and `--scanner-wordlist` flags are rejected.

The module entry point is also available for a checkout-based run:

```bash
python -m src.cli.main --help
```

## Select captured Burp requests

Start the local bridge with `/burp [port]` and configure the Burp extension's
bridge URL and token. Both **Send to KAgent** and enabled **Auto-capture Proxy
traffic / Auto-capture Repeater traffic** feed the same in-memory CaptureStore.
Ingest alone does not start the Agent.

Set `/target <authorized-lab-url>`, then use:

- `/burp list`: show the newest 20 readable Burp records at the exact active
  origin, with retrieval ID, method, redacted endpoint and `Showing M/N requests`.
- `/burp use`: select the latest matching record for the next Agent turn.
- `/burp use <id>`: select that exact retrieval ID.
- `/burp use cancel`: cancel the pending selection and retain captures.
- `/burp all`: select **at most 50 most recent matching records**, with
  `Selected M/N requests`. This does not select the complete Burp history.

Enter an ordinary prompt after selecting, for example “Analyze this request”
or “Test this request for SQL injection.” Selection supplies a source; the prompt
determines the work. It does not choose an input, prove a vulnerability, start
batch testing or grant HTTP/credential replay permission. Scope may contain
additional origins, but selection always uses the active target's exact scheme,
hostname and effective port. Counts describe retained records, not HTTP sends.

Selection is consumed once when a tools-enabled turn starts. Its frozen IDs and
baseline references survive retries and compaction of that turn only. Pending
selection is not saved in sessions or memory. Target/Scope/permission changes,
reset and resume invalidate it; a tools-disabled turn such as `/plan` cancels it
with a notice. Capture eviction, clear or changed bindings stop the handoff;
the Agent never substitutes a newer request. Unsupported baselines can still
provide redacted context, but replay needs a fresh supported capture. Follow-up
uses actual tool history and Workflow/evidence records; resume does not restore
live capture data or replay availability.

For a manual check, send one request from Burp, run `/burp list` and
`/burp use <id>`, then request analysis and verify `browser_capture_get` reads
that ID. Repeat with Auto-capture enabled, select `/burp all`, and request only
one request's analysis; selection alone should send no test traffic. For replay,
explicitly request bounded testing and review captured credentials through the
normal permission dialog. Send later traffic after selection to check that the
selected set stays fixed. Test cancel, `/plan`, target/scope changes and reset;
reset should retain captures, while restarting requires recapture for new replay.

## Repository layout

- `src/` — CLI, TUI, agent loop, providers, tools, workflow, and persistence
- `skills/` — skill metadata, playbooks, and payload assets
- `tests/` — focused, integration, skill-contract, and regression tests
- `.kagent/` — local project runtime data when created

Confirmed Findings retain their canonical Markdown under `artifacts/findings/`.
Normal KAgent runs also export compact reader reports under
`artifacts/reports/findings/`, with links to the canonical Finding and registered
evidence. A compact export failure leaves canonical persistence intact; retrying
`confirm_finding` for the same Candidate regenerates the reader report.
`/report` continues to produce a PDF assessment under `artifacts/reports/` from
canonical Findings and workflow state; it does not read the compact Markdown.
Scenario 1 exports compact Findings directly to `<benchmark-output>/findings/`
and keeps only canonical Findings in each execution workspace.

## Testing

`pytest.ini` collects tests under `tests/` and excludes
`tests/integration/test_kagent_burp.py` by default. Live checks retain their
existing opt-in requirements and skips.

```bash
pytest -q
```

Skill contracts and runtime behavior are still being refined through testing.
See [test contract synchronization](tests/CONTRACT_SYNC_REPORT.md) for the
21 October 2026 audit follow-up, intentional retirement of obsolete script tests
and offline verification.

## Cleaning project outputs

From the repository root, after stopping KAgent and benchmark runs:

```bash
python3 scripts/cleanup.py --dry-run
python3 scripts/cleanup.py
```

The cleanup removes all `docs/` and `artifacts/` contents, including audits,
reports, findings, checkpoints, benchmark results and archived runs. It also
removes historical benchmark evidence, project-local transient state and Python
and test caches. No age filter is applied: all files in these output locations
are removed. Saved runs must be copied outside the project outputs to retain them.

Source code, tests, skills, configuration, virtual environments, project
memory/intelligence/custom skills and `~/.kagent/` are retained.

Use the same script for narrower resets:

```bash
python3 scripts/cleanup.py --scope runtime
python3 scripts/cleanup.py --scope benchmark
python3 scripts/cleanup.py --scope benchmark --reset-intelligence
```

`runtime` clears transient project state (including tool-result files) and known
skill/finding outputs and historical worker output paths. `benchmark` additionally clears benchmark outputs
under `.kagent/` and `artifacts/benchmarks/`. Both retain docs, audits, checkpoints,
archived runs, caches and the containing runtime directories. Intelligence is
retained unless `--reset-intelligence` is explicitly passed with `all` or `benchmark`;
this deletes only project `scenarios.jsonl` and its lock. Every scope supports `--dry-run`.

After cleanup, recreate a benchmark selection before using its manifest;
historical audit provenance is optional through `--reset-audit <path>`.

`scripts/cleanup.py` implements the cleanup scopes above. Run Scenario 1 directly
with `venv-linux/bin/python -m benchmarks.scenario1 --help`.

`scripts/setup.sh`, `scripts/doctor.sh` and `scripts/check_cwe_mcp.py` were removed
in commit `ce05271`. Use the package installation instructions under Setup.
The checkout currently has no equivalent read-only environment-health or CWE
deployment-check command. The five tests dedicated to the retired setup/doctor
scripts were intentionally removed; those scripts are no longer required by
the test suite.

## Local CWE catalog

`src/findings/cwe_enrichment.py` now queries the packaged `Catalog` parser
in process. It uses no Worker, MCP connection, subprocess, network request or
code from the configured deployment. The existing configuration key
`cwe_mcp_deployment_path` is retained for compatibility and selects a canonical
absolute directory containing only the required data:

- `manifest.json`, matching the controller's pinned manifest;
- `corpus/cwec_v4.20.xml`, matching the controller's pinned SHA-256.

An existing deployment with those files remains usable; its launcher, runtime
archive and Python sources are ignored. Missing, modified, oversized or
symlinked data fail closed. Corpus acquisition remains an explicit operator
setup step; runtime never downloads it. File-tool write protection for the
configured deployment and packaged controller contract remains in place.
As with all control-plane files after removal of Worker, direct shell and
other processes running as the account can modify these files; file-tool
write protection is not operating-system containment.

`confirm_finding` automatically attempts local CWE enrichment after it has
persisted a confirmed Finding without a mapping. Existing CWE mappings are
retained. Automatic selection requires one exact catalog-name match for the
bound, confirmed mechanism class, complete supported mapping metadata, a
search response with no omitted matches, and unchanged confirmation/evidence. Search rank and
impact prose alone cannot select a CWE. Broad classes such as `access-control`,
ambiguous metadata and unavailable catalogs stay unresolved with a saved reason.

Use `/cwe <candidate_id>` to review a persisted Finding manually. Keep a suitable
mapping, or explain the mismatch, search by mechanism and select an exact CWE
ID after comparing its description/mapping notes with the confirmed evidence.
Assignment requires an explicit rationale citing a registered Evidence ref.
Choosing 0 records why the mapping remains unresolved. Manual unresolved
reviews are not overridden automatically. An existing mapping is never replaced:
a review annotation records the alternative, original mapping, reason, corpus
identity, source fingerprint, confirmation binding and evidence refs. Reports
show the reviewed CWE separately from the original mapping. A missing mapping
uses the existing revisioned classification promotion transaction.

Neither path creates Findings, validates vulnerabilities, changes severity or
rewrites evidence. Protected evidence must already be available through the
normal verified-evidence contract; `/cwe` grants no new read permissions.
Session/Continue reads the persisted classification and annotation rather than
reclassifying historical reports. Old reports without review metadata remain
readable with their original provenance.

A caller can use the local helper asynchronously:

```python
from src.async_io import run_sync
from src.findings.cwe_enrichment import TrustedSource

source = await run_sync(TrustedSource, execution_policy)
candidates = await source.retrieve("search", {"query": "missing authorization"})
entry = await source.retrieve("get", {"id": 862})
```

Retired external scanner adapters, result normalization, artifact I/O, triage
and UI events have been removed. Bounded legacy `scanner_jobs` and
`scanner_observations` metadata survive session round trips as opaque history;
they grant no artifact access, authority, workflow progress or coverage.
Historical files are left on disk. Native discovery and its provenance remain
active. New scanner source admission is unavailable; existing source records
retain their original provenance and unresolved limitations.

## Authorized use and scope

Use KAgent only against targets you are authorized to test. Keep activity
within the declared target origin and preserve the runtime's permission
prompts; a private address or local-looking hostname alone is not an
authorization grant.
