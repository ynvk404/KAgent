---
name: csrf
description: >
  Validate suspected Cross-Site Request Forgery (CSRF) vulnerabilities by
  identifying state-changing requests, evaluating CSRF defenses, and using
  minimal non-destructive validation to determine whether a cross-site
  request can be accepted. Use when a state-changing action appears to
  rely on browser ambient authority such as cookies or session credentials
  and may lack effective CSRF protection.
stage: validation
triggers:
  strong:
    - csrf
    - cross site request forgery
  weak:
    - csrf token
    - anti csrf
    - state changing request
    - samesite
    - double submit cookie
    - forged request
candidate-classes:
  - csrf
requires: []
allowed-tools:
  - http
  - shell
  - file_write
  - ask_user
  - confirm_finding
  - workflow
---

# CSRF validation

## Structured workflow contract

Before recording a `confirmed` result, save a minimal redacted proof artifact,
call `workflow(action="record_evidence", candidate_id="...",
evidence_path="...")`, and use its returned `ev_...` ID in `evidence_refs`.
If coverage sync is `pending`, retry `workflow(action="sync_coverage",
candidate_id="...")` before `confirm_finding`.

Consume a matching Candidate with `workflow(action="start_validation",
candidate_id="...")`. A concrete direct request may be validated immediately;
record its supplied details for result linkage without requiring prior stages. Record a
canonical ValidationResult after a meaningful attempt, using evidence
references rather than raw bodies. Use `browser-required` when HTTP-only
evidence cannot establish browser behavior and `authorization-required` when
the safe state change is not authorized. Only `confirmed` may proceed to
`confirm_finding` with the Candidate ID.

Scope: determine whether a state-changing request can be triggered from a
cross-site context without an effective CSRF defense. This skill confirms
the vulnerability and records the evidence needed for a finding.

This skill is validation-only. It does not perform account takeover,
password changes, destructive actions, financial transactions, data
deletion, or other harmful impact chaining. Deeper impact validation is
outside this skill.

Execution rule: use the actual target URL, HTTP method, parameter/body
location, and authenticated test context before running requests. Do not
invent credentials, tokens, origins, or target endpoints.

## Preconditions

Do not begin CSRF validation until all of the following are known:

1. Target URL
2. The actual state-changing endpoint
3. HTTP method
4. Where the relevant values are supplied (query, form body, JSON body,
   headers, etc.)
5. The authenticated context in which the request normally succeeds
6. A safe, user-authorized test action that can be used for validation

Prefer a harmless state change or a dedicated test endpoint.

If validation requires a cross-site origin or a browser-like PoC context,
use a user-authorized origin controlled for the engagement. Do not invent
an external domain or reuse an unrelated origin from memory.

## Scope checkpoint

Before sending a request that could change account state, confirm that the
action is explicitly authorized for this engagement.

Use `ask_user` when:

- the proposed validation would modify persistent state,
- the endpoint performs a sensitive action,
- the safe test action is not already established, or
- the intended test origin is outside the in-scope application.

Do not infer authorization merely because the endpoint is reachable.

Do not proceed with a state-changing validation request until the safe
test action and its expected observable result are known.

## 1. Identify the state-changing request

Start from a legitimate request that performs a state change.

Record:

- method
- URL
- parameters/body
- relevant cookies/session context
- CSRF token, if present
- Origin header, if present
- Referer header, if present
- SameSite-relevant cookie behavior when observable

Classify the action as:

- state-changing and relevant, or
- non-state-changing / out of scope for CSRF validation

Do not continue with CSRF testing against requests that have no meaningful
state change.

## 2. Evaluate CSRF defenses

Check whether the request relies on one or more defenses:

- synchronizer CSRF token
- double-submit cookie pattern
- Origin validation
- Referer validation
- SameSite cookie restrictions
- another explicit anti-CSRF mechanism documented by the application

For token-based defenses, determine at minimum whether the token is:

- required,
- bound to the expected request,
- rejected when absent, or
- rejected when invalid.

Do not attempt token theft or authentication bypass.

Treat SameSite as one part of the CSRF defense model. Do not mark a
request as protected solely because a SameSite attribute is present;
consider the request context and browser behavior relevant to the tested
cross-site scenario.

## 3. Minimal validation

Use the smallest non-destructive modification needed to test the suspected
defense.

Examples:

- remove the CSRF token,
- replace the token with an invalid value,
- change the request Origin where the application normally validates it,
- remove or alter the Referer where applicable.

Compare each probe with the known-good baseline.

A request is strong evidence of CSRF when the state-changing operation is
accepted despite removal or invalidation of the expected anti-CSRF defense,
and the behavior is consistent with a cross-site request being accepted.

Do not perform the real-world action if the only available endpoint has
destructive or high-impact consequences.

## 4. Cross-site request validation

When a safe test action is available, validate the server's handling of a
cross-site request context by using the minimal browser-relevant headers
and request shape available to the tool.

Do not claim full browser-level exploitability unless the evidence
includes an actual browser-mediated cross-site execution. An HTTP client
replaying an `Origin`/`Referer` header approximates what a browser would
send, but it is not equivalent to a real browser enforcing cookie
attachment, CORS, and same-site policy — report the distinction
explicitly rather than treating a successful replay as full browser-level
proof.

Use a minimal proof of concept containing only the parameters necessary for
the test action.

Prefer a controlled test origin and a harmless state change.

Do not use:

- password reset,
- email change,
- account deletion,
- fund transfer,
- privilege modification,
- destructive administration actions,
- or other high-impact operations

as the default proof.

## 5. Determine the result

Classify the result as one of:

- **CSRF-1** — state-changing endpoint identified and relevant to CSRF
  testing.
- **CSRF-2** — CSRF defense appears missing or incorrectly validated, but
  cross-site execution has not yet been conclusively demonstrated.
- **CSRF-3** — a safe state-changing action was accepted from a cross-site
  context without an effective CSRF defense.

Do not report CSRF-3 solely because a token field appears absent. Require
behavioral evidence that the request is actually accepted without the
expected defense.

Do not treat a successful HTTP status alone as evidence of CSRF. Confirm
that the intended state-changing operation was actually accepted.

If the available evidence is inconclusive, do not conclude that CSRF is
absent. Report that CSRF could not be confirmed with the available evidence.

## 6. Stop when CSRF is confirmed

Stop at the lowest level that provides conclusive evidence.

Once **CSRF-3** is established:

- do not perform additional account actions,
- do not chain into account takeover,
- do not test destructive endpoints,
- do not attempt privilege escalation.

Deeper impact validation belongs to a separate, explicitly authorized
workflow.

## Reporting

Write validation details and redacted supporting evidence to
`artifacts/csrf/<target>/results.md` (using the target identifier convention from
`recon`). This is a validation artifact, not an official finding.
`confirm_finding` alone creates the report under `artifacts/findings/`.

Include:

- target URL
- HTTP method
- state-changing action
- baseline request
- validation request(s)
- CSRF defense observed
- exact response/result
- CSRF level reached (1–3)
- whether cross-site execution was conclusively demonstrated
- a note when evidence is inconclusive
- a note that deeper impact validation requires separate authorization

## Confirm an evidence-backed finding

After recording a `confirmed` ValidationResult, call `confirm_finding` with
its required `candidate_id`, `title`, `severity`, `url`, `observed_impact`,
and `potential_impact`,
plus method, parameter, reproducible request, response excerpt, remediation,
and canonical `vuln_class` when available. `observed_impact` states only what
the linked evidence demonstrates; put untested consequences in
`potential_impact` as conditional possibilities. The candidate's latest
confirmed result and registered evidence must be valid. Do not call it for any
other structured outcome.
