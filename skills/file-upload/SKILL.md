---
name: file-upload
description: >
  Evaluate one file-upload candidate using a harmless text marker in a
  designated disposable lab account. Uploads are state-changing and require
  exact user authorization plus separate cleanup authorization. The generic
  runtime does not currently provide a high-impact gate for active content.
stage: validation
triggers:
  strong:
    - unrestricted file upload
    - file upload validation
    - upload extension validation
    - uploaded file retrievable
  weak:
    - multipart upload
    - filename validation
    - upload content type
candidate-classes:
  - file-upload
requires:
  - web-input-analysis
completion-artifact: artifacts/file-upload/{target}/results.md
allowed-tools:
  - http
  - read_payloads
  - file_write
  - ask_user
  - workflow
  - confirm_finding
---

# File upload validation

## Contract and authorization

Validate only the handed-off Candidate and designated disposable lab account.
An upload changes application state: before the first upload, ask for explicit
authorization for one harmless marker file, the exact endpoint/account, and
the permitted test count. Do not infer upload authorization from permission
to test the application. Deletion/cleanup is a separate action and requires
its own explicit authorization and normal tool permission gate.

Use only plain-text content such as `KAGENT_UPLOAD_MARKER`, with a neutral
`.txt` or operator-approved non-executable extension. Never upload HTML,
SVG, script, executable, archive, polyglot, web shell, or backdoor content;
never use a path-bearing filename. If the endpoint's only proof requires
active content or execution, stop this default flow with
`authorization-required`.

This bounded flow is not a blanket prohibition on authorized upload-impact
testing. If the engagement objective specifically requires an active-content
or execution check after harmless upload behavior is recorded, first ask
`ask_user` to name the candidate, disposable account, exact file/action,
single endpoint, execution bound, cleanup action, and risk tier. Proceed only
if a runtime permission prompt classifies that exact action as high-impact,
is non-cacheable, and cannot be bypassed by `/yolo`; get separate approval for
cleanup and any higher tier. The current generic HTTP gate does not reliably
classify active content in a request body, so do not run this branch until
that classification is available.

## Validation

1. Record the Candidate and inspect the expected upload fields, accepted
   extension/MIME rules, returned filename/path, and available delete action
   without uploading. Capture a baseline only if it is non-mutating.
2. Read `payloads.txt` with `read_payloads(skill="file-upload",
   file="payloads.txt")`. Once authorized, send one plain-text marker file
   preserving the real request shape. To test content-type handling, change
   only the declared MIME type on a separately authorized probe; do not
   change the content to active bytes. Do not send more than two uploads for
   this Candidate.
3. If accepted, retrieve only that known marker using the returned path and
   the same test account, if the lab provides a read-only retrieval route.
   Record accepted/rejected, normalized filename, response MIME, and whether
   the exact marker is retrievable. A `200` alone does not establish unsafe
   execution or public access. Never enumerate upload directories.
4. Register redacted evidence and call `workflow(action="record_result", ...)`.
   If an upload occurred, set `mutation_performed: true` and an accurate
   `cleanup_state`; keep `pending` until deletion is separately authorized
   and verified. Do not mark cleanup successful from a delete response alone.
   If cleanup is not authorized or cannot be verified, record
   `requires-user-action` in the cleanup fields and tell the operator exactly
   what remains. The finding may remain confirmed, but do not claim the lab is
   clean or complete while cleanup is unresolved.

## Stop and report

Stop this default flow after at most two harmless marker uploads and one
retrieval per accepted file. Do not automatically test execution, path
traversal in filenames, overwrite behavior, public-user access, or
persistence. Record exact authorization, test account role, safe file
metadata, result, and cleanup state in
`artifacts/file-upload/<target>/results.md`; do not retain actual user files
or credentials. A confirmed finding must have registered evidence and must
describe only the behavior shown by the harmless marker.

## Confirm an evidence-backed finding

For a confirmed result only, call `confirm_finding` with `candidate_id`,
`title`, `severity`, exact `url`, `observed_impact`, conditional
`potential_impact`, `method`, `parameter` when applicable, the harmless
marker metadata as `payload`, short `response_excerpt`, redacted reproducible
`curl`, specific `remediation`, and `vuln_class: file-upload`. The latest
result and registered evidence must be valid. Never describe code execution
unless a separately authorized safe validation actually established it.
Recommend server-side extension/content validation, generated storage names,
and storage outside directly executable web roots with controlled retrieval.

## Completion

When every handed-off Candidate has a result and cleanup obligations are
resolved or clearly handed back to the operator, call
`workflow(action="complete_skill", skill_name="file-upload",
artifact_ref="artifacts/file-upload/<target>/results.md")`.
