# YOLO execution policy — implementation status, 2026-10-02

This is a **partial implementation**, not an all-tools YOLO release. The CLI
binds a controller-owned execution profile to Registry and executors. YOLO
auto-approves covered operations after independent checks. Ordinary mode
retains review and still-valid manual HTTP grants. Neither mode overrides
scope, protected paths, explicit revocation, receipts or execution limits.

| Operation | YOLO ON | YOLO OFF | Current boundary |
|---|---|---|---|
| Native HTTP in declared scope, new endpoints/payloads/mutations | No permission dialog or manual grant needed | Exact review or valid manual rights; confirm-each restored | Exact origin, pinned native transport, shared budgets and revokes |
| Native discovery, target fetch, configured public search | No permission dialog | Existing ordinary operation gates | Shared network authority; separate fixed research destination |
| Lab files, source, payloads, evidence | No permission dialog in approved lab root | Existing sensitive/write reviews | Resolved root, protected controller paths, evidence source checks; no general race-proof filesystem broker |
| Shell/Bash/command plugin, Linux worker available | Offline and broker-compatible HTTP operations auto-approve | Exact ordinary review | Isolated namespaces, read-only lab, artifacts/worker writable; scoped/accounted plaintext HTTP broker, direct network denied |
| Local stdio MCP, compatible operator configuration | Auto-approve, fresh isolated server per invocation | Exact ordinary review | Offline startup discovery; actual call uses isolated worker/broker. Persistent server state and environment export unsupported |
| ffuf HTTP adapter | Auto-approve within full tooling profile/runtime discovery gap | Ordinary review | Worker + explicit proxy + shared accounting; no raw network; 4 GiB AS, GOMAXPROCS 2, real-UID NPROC 1024 |
| nmap, CONNECT/raw TCP, remote MCP, missing worker/adapter | Blocked with reason | Blocked with reason | No ambient fallback; not positive acceptance |
| Confirmed/negative results and canonical findings | Agent assessment of admissible evidence | Same evidence contract | Runtime checks provenance/identity/completeness; Agent applies the skill. Optional /review-result creates operator authority, independently of YOLO |
| Outside profile, revoked, invalid/expired/replayed receipt | Blocked | Blocked | Approval cannot extend authority |

The operator accepts unknown server effects on the declared disposable lab.
There is no promise to avoid bulk deletion, email, real-data changes or other
server-side effects. Phase/method/endpoint/payload/model labels confer no rights.

## Operator controls

- `/yolo on`, `/yolo off`: change review mode. Mode changes invalidate queued
  receipts. Turning ON does not override revokes or refill limits.
- `/permissions` or `/permissions show`: view roots, adapter status, tool-call
  limits and HTTP grants. `permissions_status` is the read-only model-facing
  query; it accepts no authority changes.
- `/permissions limits <calls> <concurrency>`: adjust total controller calls and
  concurrent operations. Defaults are 10,000 calls and 16 concurrent operations.
- `/permissions revoke-tool <name>` / `restore-tool <name>`: operator tool rule;
  use `*` for the session-wide rule. Restoration does not create a missing adapter.
- `/permissions deny`: deny shared native network. `/permissions revoke <id>`:
  revoke that exact origin's HTTP grant, including alternate native transports.
- `/permissions retry <origin>`: explicitly reopen that HTTP issue.
  `/permissions retry-tools`: explicitly reopen exact declined tool
  reviews and input questions; durable revokes remain.
- `/permissions network-refresh`: explicitly re-vet DNS bindings next time;
  does not refill a budget or extend scope.
- `/permissions grant <spec>` remains an optional operator-initiated reviewed
  way to adjust HTTP limits or ordinary review policy. It is not needed for ON.
  The existing `ORIGIN,MODE,SECONDS,REQUESTS,RATE,BURST,CONCURRENCY,REQUEST_BYTES,RESPONSE_BYTES`
  syntax remains; CLI `--http-lab-grant` requires `--accept-unknown-http-effects`.

Native defaults per origin: 500 requests, 20 minutes, 3/s with burst 3,
concurrency 2, request 128 KiB, retained response 64 KiB. This contains traffic
and repeated attempts, not unknown application effects or all wire bytes.
HTTP/fetch/discovery share accounting. The research provider has separate
accounting. Controller constraints/deny rules are stored under
`.kagent/permissions/<session-id>.json`. Grants and one-use receipts are not
restored from this journal, summary or intelligence. Constraints may survive
resume without granting authority; a fresh trusted operator grant can change
them. After dispatch, remote side effects cannot be rolled back by revoke.

DENY_ONCE suppresses equivalent review within the current controller-created
turn, not future independent turns or the whole session. Cancellation cancels
only that invocation and never becomes an operator decline. A new Agent turn
receives fresh review identity; independent Registry/direct HTTP calls outside
an Agent turn receive their own scope. Models cannot choose that identity.
Origin/private-host/lab-grant decisions, session denies and tool/grant revokes
remain separate; changing turns does not clear them, reset quotas or grant rights.
HTTP receipts bind the effective request and a unique invocation identity; an
unused receipt is discarded on exit, including cancellation and timeout.
Different actions remain eligible. Concurrent identical reviews return pending
instead of sharing an exact receipt. Actual missing-input questions are cached
in memory and coalesced; the runtime does not fabricate OTP/account answers or
use question keywords as authority. Skill guidance queries runtime rights;
unstructured model questions can still require further UI/protocol work.

## Unfinished requirements and operational effects

Scoped plaintext HTTP is implemented for shell/plugin, compatible local stdio
MCP and the ffuf discovery adapter. CONNECT/HTTPS tunnelling, raw-network nmap,
remote MCP, persistent MCP application state, explicit MCP environment export,
browser actor execution, approved proxy/Burp transport, research redirects and
OAST roles still need enforcing adapters. On Windows/macOS the worker is unavailable. Installed Linux
`bwrap`/`prlimit` must pass an actual startup probe; no dependency is installed.
The startup probe uses a tiny controller-owned `/tmp` tree with a five-second
async subprocess deadline; it never traverses the project. Actual tool dispatch
still inspects the mounted project for hardlinks/host IPC/devices and fails closed
on inspection errors. The CLI opens the normal interface without a startup
splash; worker/provider/session initialization is unchanged. Large real
dispatch trees can still take time to inspect; no unsafe inspection cache is used.
Shell, plugin, stdio MCP and ffuf prepare their worker off the UI event loop.
Inspection has a 120-second budget, separate from process execution timeout;
Esc/task cancellation and changed/revoked execution authority stop preparation
before process launch. Root/output paths are checked again after preparation.
An uninterruptible filesystem syscall can outlive cancellation in a read-only
inspection thread; it cannot launch a child. This keeps the UI responsive but
does not make a full project/virtualenv scan on `/mnt/d` fast or remove existing
filesystem race limitations.
Inspection prunes `venv-linux`, `venv`, `.venv`, `.git`, `node_modules`,
`__pycache__`, `.pytest_cache`, `.mypy_cache`, `dist`, and `build` before descending,
at every level. The worker mounts these uninspected trees as empty read-only
directories so skipping inspection cannot expose unchecked host IPC/hardlinks.
Worker commands cannot consume files/executables within them; source/payload/
wordlist inputs must be outside those excluded trees. Native file tools retain
their existing root/provenance permission checks. Excluded directory symlinks
are blocked rather than followed. Full filesystem race protection is still absent.
Per-process AS/CPU, real-UID NPROC and per-file bounds do not provide cgroup
aggregate memory/CPU/disk quotas. Linux isolation relies on OS correctness and
trusted system binaries; preflight checks do not eliminate filesystem races.

Protected host/controller data is refused before model/tool admission on the
checked paths. The lab root is assumed operator-approved input. There is no
complete source/sink egress engine, credential-handle/actor adapter, external
resource import UI or context-domain separation. Secrets unknown inside allowed
lab files are not comprehensively identified. DNS pinning reduces native
transport re-resolution but does not prove a trustworthy first binding, lab
provenance or all proxy/browser/MCP routing.

Observations attest captured bytes, not vulnerability truth. Up to 256 observations
and result bindings persist in protected `.kagent/observations/<session-id>.json`.
Narratives/body/URL are redacted; opaque IDs/hashes retain their controller binding.
Historical certificates remain compatibility records, never execution rights or receipts.
New durable attempts and versioned source manifests bind actual execution/import
provenance. Agent assessments need no class certificate; canonical Finding impact
and severity come from the latest accepted structured assessment. Optional
`/review-result <candidate-id> <confirmed|not-confirmed> <severity> <observed impact>`
requires real human review even in YOLO and creates a distinct operator revision.
Browser views filter current scope/revokes; imports retain their bridge provenance
and unknown original ownership. They do not authenticate actors or attest native
execution. See [Agent-assessed evidence](agent-assessed-evidence.md) for the current
result, persistence, compatibility and completion contract.

Summary, recalled memory catalog and workflow values are supplied as untrusted
turn data; automatic learning writes project observations rather than personal
preferences. These role changes are guidance, not model-instruction immunity.
Runtime does not obtain rights from them. Typed verified-fact persistence,
trusted preference promotion and poisoned-record retraction remain unfinished.
Unbound public/trusted library callers retain legacy behavior
and are outside the bound CLI policy guarantee.

Full acceptance is withheld until every configured tool has both permitted
pentest execution with zero permission dialogs and forbidden-action rejection.
Tests do not establish comprehensive protection from prompt injection.
