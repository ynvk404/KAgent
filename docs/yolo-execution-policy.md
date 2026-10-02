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
| Confirmed/negative results and canonical findings | Class contract or separate operator proof review | Same proof requirement | Shipped narrow SQL boolean/JSON contract; other proofs need trusted adapter or /review-result. Human review is never autonomous verification |
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
  `/permissions retry-tools`: explicitly reopen exact declined/cancelled tool
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

DENY_ONCE suppresses equivalent invocation review, not the whole session.
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
Historical certificates restore facts only, never execution rights or receipts.
The shipped SQL contract supports repeated query boolean predicates with stable
JSON row/no-row results. It is neither every SQLi technique nor a proof against
a deceptive target. All other class results require a trusted adapter or explicit
`/review-result <candidate-id> <confirmed|not-confirmed> <severity> <observed impact>`.
The operator reviews exact immutable proof and a labeled human conclusion even
in YOLO; this is not an execution permission dialog. Canonical finding impact and
severity come from that certificate, not a model overclaim. Imported proof is
unverified until reviewed. Browser views filter current scope/revokes, but do not
authenticate an actor or turn imported payloads into runtime execution proof.
Autonomous multi-class and whole-target completion remain release blockers.

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
