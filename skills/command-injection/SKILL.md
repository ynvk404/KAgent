---
name: command-injection
description: >
  Validate one suspected server-side command injection candidate with a
  single benign output marker in an authorized isolated lab. Never open an
  interactive shell, alter files, access secrets, or make network callbacks.
stage: validation
triggers:
  strong:
    - command injection
    - os command injection
    - shell metacharacter injection
    - server command execution
  weak:
    - command output marker
    - shell argument boundary
    - operating system command
candidate-classes:
  - command-injection
requires:
  - web-input-analysis
completion-artifact: artifacts/command-injection/{target}/results.md
allowed-tools:
  - http
  - read_payloads
  - file_write
  - ask_user
  - workflow
  - confirm_finding
---

# Command injection validation

## Contract and authorization

Validate only a concrete `command-injection` Candidate on an explicitly
authorized isolated lab. Confirm the exact input and the harmless expected
server action. Because even a marker probe executes a process, ask once for
explicit authorization for this exact bounded check before sending it. If
authorization is absent, record `authorization-required` and stop.

Use only the marker command in `payloads.txt`, appending a unique non-secret
suffix to the marker before sending it. The probe may print a constant string
only. Do not use `shell` or
`file_write` against the target; do not invoke a shell interactively, read
files, inspect environment variables, launch programs other than the
allow-listed marker printer, sleep, create/delete files, or access the
network. Do not test a state-changing application operation.

## Validation

1. Start the Candidate and capture one baseline request with a benign value.
   Preserve method, headers, body, and auth context.
2. Read `payloads.txt` with `read_payloads(skill="command-injection",
   file="payloads.txt")`. Choose one syntax form supported by the observed
   input context; change only the candidate input and append/introduce the
   constant marker printer. Do not send all separators as a corpus.
3. A response containing the exact unique marker, absent from baseline and
   attributable to the server-side input, is a positive signal. Stop
   immediately; do not attempt a second command or impact probe. If no marker
   appears, at most one close syntax variant is allowed only when the
   candidate's known parser context justifies it. No timing probes are
   included by default.
4. Save a small redacted request/response excerpt, register it with
   `workflow(action="record_evidence", ...)`, and record the canonical
   result. Use `confirmed` only when the output marker is reproducible and
   clearly server-generated; otherwise use `not-confirmed`, `blocked`,
   `insufficient-evidence`, `deferred`, or `authorization-required` as
   appropriate.

## Stop and report

Stop on the first marker or after the bounded inconclusive attempt. No
command chaining beyond the marker printer, data reads, filesystem changes,
reverse/bind shells, persistence, credential access, lateral movement,
timing loops, or automated scanners. Record only the exact marker, request
shape, status, response excerpt, and scope limitation in
`artifacts/command-injection/<target>/results.md`; never claim broader RCE
from one harmless marker.

## Confirm an evidence-backed finding

For a confirmed result only, call `confirm_finding` with `candidate_id`,
`title`, `severity`, exact `url`, `observed_impact`, conditional
`potential_impact`, `method`, `parameter`, the benign marker probe as
`payload`, short `response_excerpt`, reproducible redacted `curl`, specific
`remediation`, and `vuln_class: command-injection`. The latest result and
registered evidence must be valid. State only that the marker command ran;
leave other command execution conditional. Recommend avoiding shell string
construction and using fixed executables with argument arrays and strict
allow-lists.

## Completion

After every handed-off Candidate has an outcome and the artifact exists, call
`workflow(action="complete_skill", skill_name="command-injection",
artifact_ref="artifacts/command-injection/<target>/results.md")`.
