---
name: open-redirect
description: >
  Validate a specific redirect parameter with a reserved safe destination and
  inspect the first response only. Confirm only when the server actually
  returns an off-origin Location; never follow or weaponize the redirect.
stage: validation
triggers:
  strong:
    - open redirect
    - unvalidated redirect
    - redirect parameter
    - url redirect issue
    - untrusted location header
  weak:
    - return url
    - continue url
    - next parameter
candidate-classes:
  - open-redirect
requires:
  - web-input-analysis
completion-artifact: artifacts/open-redirect/{target}/results.md
allowed-tools:
  - http
  - read_payloads
  - file_write
  - ask_user
  - workflow
  - confirm_finding
---

# Open redirect validation

## Contract and scope

Validate only the supplied `open-redirect` Candidate and its named parameter.
Use the reserved marker destination in `payloads.txt`; it is a `Location`
value to inspect, not a site to visit. The HTTP tool does not follow redirects;
preserve that behavior and never use an automatic redirect-following client.
Do not send credentials to the marker or build a phishing flow.

## Validation

1. Start the Candidate and record the normal response for its benign,
   in-scope return path. Keep method, other parameters, and auth context fixed.
2. Read `payloads.txt` with `read_payloads(skill="open-redirect",
   file="payloads.txt")`; change only the candidate value to
   `https://example.com/`. Inspect status and the first `Location` header.
   The file's `IN_SCOPE_RETURN_PATH` line is a template only; use the
   observed baseline value and never send that placeholder literally.
   If the server returns a relative or same-origin location, stop; do not
   cycle through encodings, schemes, or nested redirect tricks.
3. `confirmed` requires a reproducible redirect response whose normalized
   `Location` resolves to an origin different from the active target.
   Reflection in HTML/JSON, a `200`, or a redirect to the same origin is not
   confirmation. Register a redacted response-header proof before recording
   a confirmed result.
4. Record the canonical outcome with workflow. A verified upstream block is
   `blocked`; missing endpoint/parameter context is `insufficient-evidence`;
   a different sink is `deferred`.

## Stop and report

The default proof does not follow the redirect, add user-controlled
credentials, test external domains other than the reserved marker, or chain
into another flow. This is not a blanket ban on authorized chained-impact
testing: if the engagement objective requires it after the redirect is
confirmed and recorded, ask `ask_user` to name the candidate, exact lab
endpoints/accounts, single chain/action, bound, and risk tier. Proceed only
with that approval and an exact-action runtime permission prompt that `/yolo`
cannot bypass; get fresh approval before increasing the tier. If the runtime
cannot enforce the gate or the chain leaves the active target's scope, record
`authorization-required` and stop. Record the exact input, status, raw and resolved `Location`, and same-origin
comparison in `artifacts/open-redirect/<target>/results.md`. Call
`confirm_finding` only for confirmed evidence, describing the redirect
behavior observed and leaving downstream abuse conditional.

## Confirm an evidence-backed finding

For a confirmed result only, call `confirm_finding` with `candidate_id`,
`title`, `severity`, exact `url`, `observed_impact`, and conditional
`potential_impact`, plus `method`, `parameter`, the safe external marker as
`payload`, a short status/`Location` `response_excerpt`, reproducible
redacted `curl`, specific `remediation`, and `vuln_class: open-redirect`.
The latest result and registered evidence must be valid. Report only the
off-origin redirect shown by the response; do not follow it. Recommend
allow-listing permitted destinations or accepting only validated relative
paths that resolve to the active origin.

## Completion

When all handed-off candidates have a result and the artifact exists, call
`workflow(action="complete_skill", skill_name="open-redirect",
artifact_ref="artifacts/open-redirect/<target>/results.md")`.
