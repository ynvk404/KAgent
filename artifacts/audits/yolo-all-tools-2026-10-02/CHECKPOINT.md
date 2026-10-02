# Checkpoint: verified partial YOLO repair

Operator explicitly requested this commit after reviewing implementation and
checklist results. Branch: `work/yolo-all-tools-2026-10-02`. Parent checkpoint:
`b1057dcf7de9478c1649a35612d3bebeb3824303`.

This checkpoint includes the bound execution policy/receipt lifecycle, scoped
native transports, protected file/evidence paths, Linux worker and bounded HTTP
broker, compatible local stdio MCP/ffuf, narrow SQL result verifier, labeled human
proof review, memory/resume safeguards, fast worker startup and CLI without splash.
Earlier A/B/C/M1 fixes are retained through the parent and this implementation.

It is **not a full YOLO release**. Raw TCP/nmap/CONNECT, remote/stateful/environment
MCP, complete export/actor adapters, autonomous all-class findings/whole-target
completion, general filesystem races, aggregate cgroups and non-Linux isolation
remain incomplete. See REPAIR.md and docs/yolo-execution-policy.md.

Verification history: broad offline 2,692 passed/1 skipped; focused no-splash
98 passed; latest selected checklist controls570 passed plus3 actual OFF/ALLOW
worker probes. The counts overlap across reruns and are not additive acceptance
coverage. Pyright src/tests and diff check passed. No further model/live-target
calls were made during the checklist or commit preparation.

Audit reports retain chronological claims such as "not committed" or "no API
calls in this phase". Those describe their earlier phases. A limited paid trial
preceded the later prohibition and is reported explicitly in REPAIR.md; no trial
was rerun here. Result metadata HEAD fields refer to the tested precommit tree.

Only explicitly selected source/tests/docs and audit evidence are staged. Runtime
`.kagent` data, live workspace/session content, provider credentials, virtualenvs,
raw before-state ZIP/diff archives and incidental files stay outside this commit.
Original ignored artifacts remain in the workspace. The redacted before-repair
archive is a review artifact, not an exact restore backup. No push is authorized.

The raw historical `evidence-before.xml` remains unchanged and ignored. The
versioned `evidence-before-versioned.xml` is a trailing-whitespace-normalized
review copy with identical test outcomes. Pyright log trailing blank lines and
CLI runtime trailing spaces were cleaned for the staged diff check; runtime AST
was compared before/after and is identical.
