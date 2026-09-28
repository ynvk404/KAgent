---
name: nosql-injection
description: >
  Validate a specific suspected NoSQL query/operator injection candidate with
  a small type-aware differential against an authorized lab endpoint. The
  default flow uses read-only operations or tester-owned fixtures; any
  separate impact check requires fresh bounded approval and a hard runtime
  permission gate.
stage: validation
triggers:
  strong:
    - nosql injection
    - no-sql injection
    - mongodb injection
    - mongodb operator injection
    - mongo query injection
  weak:
    - json query operator
    - mongodb filter
    - document database query
candidate-classes:
  - nosql-injection
requires:
  - web-input-analysis
completion-artifact: artifacts/nosql-injection/{target}/results.md
allowed-tools:
  - http
  - read_payloads
  - file_write
  - ask_user
  - workflow
  - confirm_finding
---

# NoSQL injection validation

## Contract and scope

Work one existing `nosql-injection` Candidate at a time. Confirm the active
target, method, endpoint, parameter, location, and the suspected document-query
sink before probing. If any of these are missing, ask once or record
`insufficient-evidence`; do not discover adjacent inputs from this skill.

Use only an authorized lab and a read-only query whose handoff says the
candidate is expected to be a scalar, or a fixture containing only
tester-owned synthetic records. Keep the same authentication context and
request shape for baseline and probes. Never send a broad operator intended to
return every record, enumerate collections/fields, extract data, or test a
write/delete operation. For an authentication candidate, do not expose real
credentials in tool arguments; without a secret-safe path and an explicitly
designated test account, stop with `insufficient-evidence`. Do not treat a
login bypass as permission to use the resulting session.

## Validation

1. Call `workflow(action="start_validation", candidate_id="...")` for the
   matching Candidate. Capture one benign baseline using its original input
   type and record status plus a non-sensitive marker/count only.
2. Read `payloads.txt` with `read_payloads(skill="nosql-injection",
   file="payloads.txt")`. Change only the candidate value: compare a scalar
   marker with a narrowly scoped JSON operator matching a known, tester-owned
   marker. Preserve method, content type, other fields, and auth context.
3. Repeat the minimal pair once only when the first comparison differs. A
   repeatable parser/query-behavior differential tied to the operator is
   sufficient; stop immediately. A parse error or status change alone is not
   confirmation unless it distinguishes operator evaluation from ordinary
   input validation.
4. Record the canonical outcome with `workflow(action="record_result", ...)`.
   Use `confirmed` only for reproducible behavior demonstrating operator
   interpretation; use `not-confirmed` when tested behavior does not establish
   injection, `blocked` for verified upstream interception,
   `insufficient-evidence` for missing baseline/fixture, `deferred` when the
   sink is not NoSQL, or `authorization-required` when a needed safe fixture
   or action was not authorized. Store proof in a small redacted artifact and
   register it with `record_evidence` before a confirmed result.

## Stop and report

Stop at the first clear signal or after the bounded pair is inconclusive. Do
not enumerate results, dump database contents, infer arbitrary query control,
or chain into authentication or access-control testing. Record endpoint,
input type/location, baseline/probe status and marker/count, repeatability,
and limits in `artifacts/nosql-injection/<target>/results.md`. Redact all
identifiers and secrets; retain references rather than full traffic in
workflow state. Call `confirm_finding` only for a confirmed Candidate with
registered evidence, and state only what the differential proves.

These limits define the default validator, not a blanket prohibition on
authorized impact work. If the engagement objective needs a separate,
bounded read from a tester-owned fixture after confirmation, first record
the current result, then use `ask_user` to name the candidate, exact target
and input, action, maximum data scope, and risk tier. Proceed only after that
specific approval and an exact-action runtime permission prompt that `/yolo`
cannot bypass; get fresh approval for any higher tier. If the available HTTP
path cannot provide that gate, record `authorization-required` and stop.

## Confirm an evidence-backed finding

For a confirmed result only, call `confirm_finding` with `candidate_id`,
`title`, `severity`, exact `url`, `observed_impact`, and conditional
`potential_impact`, plus `method`, `parameter`, the minimal `payload`, a
short `response_excerpt`, reproducible redacted `curl`, specific
`remediation`, and `vuln_class: nosql-injection`. The latest result and
registered evidence must be valid; do not claim arbitrary query control or
data extraction unless the evidence directly demonstrates it. Recommend
strict input-shape validation and constructing database filters from
allow-listed fields/operators rather than accepting client-supplied operator
objects.

## Completion

After every handed-off Candidate has one recorded outcome and the artifact
exists, call `workflow(action="complete_skill", skill_name="nosql-injection",
artifact_ref="artifacts/nosql-injection/<target>/results.md")`.
