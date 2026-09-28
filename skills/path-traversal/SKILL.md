---
name: path-traversal
description: >
  Validate one suspected path traversal input by requesting only an
  operator-identified, harmless lab marker file and comparing bounded
  responses. Never read secrets, operating-system files, or arbitrary paths.
stage: validation
triggers:
  strong:
    - path traversal
    - directory traversal
    - path canonicalization bypass
    - dot dot slash
  weak:
    - file path parameter
    - filename parameter
    - encoded path separator
candidate-classes:
  - path-traversal
requires:
  - web-input-analysis
completion-artifact: artifacts/path-traversal/{target}/results.md
allowed-tools:
  - http
  - read_payloads
  - file_write
  - ask_user
  - workflow
  - confirm_finding
---

# Path traversal validation

## Contract and preconditions

Validate only the handed-off `path-traversal` Candidate. Before any probe,
identify the exact method, endpoint, path/filename parameter, and one harmless
marker file that the operator confirms exists in the authorized lab. If a
known marker path is unavailable, stop with `insufficient-evidence`; do not
guess common system paths or use `/etc/passwd`, application configuration,
credentials, source files, or user data as markers.

Prefer a read-only endpoint. Keep the baseline request shape and auth context
fixed; begin with the ordinary in-scope marker path. Use a marker file with a
small known content (preferably at most 1 KiB). The HTTP tool has a global
response cap, which is not permission to retrieve larger files.

## Validation

1. Start the Candidate with `workflow(action="start_validation", ...)` and
   capture a baseline for the known marker path. Record status, returned byte
   length, and only the expected harmless marker.
2. Read `payloads.txt` with `read_payloads(skill="path-traversal",
   file="payloads.txt")`. Substitute only the operator-approved marker path
   for `LAB_MARKER_RELATIVE_PATH`; never send that placeholder literally.
   Try one plain relative form first. If needed, try at most one encoded or
   separator variant that represents the same marker path. These compare
   canonicalization behavior; do not use encoding to evade a WAF or expand
   scope.
3. A repeatable response containing the exact known marker outside its
   expected in-scope location confirms traversal. A `200`, file-like content,
   or changed length without the marker is not enough. Stop on confirmation.
4. Record `confirmed`, `not-confirmed`, `blocked`, `insufficient-evidence`,
   `deferred`, or `authorization-required` via `workflow(record_result)` as
   supported by the evidence. Register a small redacted proof artifact before
   recording `confirmed`; do not persist file contents beyond the short
   non-sensitive marker needed to show the result.

## Stop and report

This default proof does not vary roots, walk directories, enumerate filenames,
read secrets, or follow a traversal into another vulnerability class. That is
not a blanket ban on authorized impact validation: if the objective requires
access to a different non-sensitive, operator-designated fixture after the
result is recorded, ask `ask_user` to name the candidate, exact target and
fixture, one action, maximum bytes, and risk tier. Proceed only with that
specific approval and an exact-action runtime permission prompt that `/yolo`
cannot bypass; ask again before increasing the tier. If the available HTTP
path cannot enforce the gate, record `authorization-required` and stop.
Record the exact
operator-approved marker, representation tried, status/byte count, whether
the expected marker appeared, and the bounded response limit in
`artifacts/path-traversal/<target>/results.md`. Keep workflow evidence
referential and redact sensitive values. Call `confirm_finding` only for a
confirmed Candidate with registered evidence.

## Confirm an evidence-backed finding

For a confirmed result only, call `confirm_finding` with `candidate_id`,
`title`, `severity`, exact `url`, `observed_impact`, and conditional
`potential_impact`, plus `method`, `parameter`, the exact safe marker input
as `payload`, a short `response_excerpt`, reproducible redacted `curl`,
specific `remediation`, and `vuln_class: path-traversal`. The latest result
and registered evidence must be valid. Describe only access to the named
harmless marker, not access to arbitrary files. Recommend canonicalizing the
resolved path and enforcing that it remains beneath an allow-listed storage
root.

## Completion

When every handed-off Candidate has a result and the artifact exists, call
`workflow(action="complete_skill", skill_name="path-traversal",
artifact_ref="artifacts/path-traversal/<target>/results.md")`.
