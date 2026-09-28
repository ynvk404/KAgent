---
name: cors-misconfiguration
description: >
  Assess CORS response policy on one candidate endpoint using harmless Origin
  and preflight headers. Distinguish a permissive header from demonstrated
  cross-origin access to protected data; do not perform state-changing calls.
stage: validation
triggers:
  strong:
    - cors misconfiguration
    - cross-origin resource sharing
    - access-control-allow-origin
    - access-control-allow-credentials
  weak:
    - cors policy
    - preflight response
    - origin reflection
candidate-classes:
  - cors-misconfiguration
requires:
  - web-input-analysis
completion-artifact: artifacts/cors-misconfiguration/{target}/results.md
allowed-tools:
  - http
  - read_payloads
  - file_write
  - ask_user
  - workflow
  - confirm_finding
---

# CORS misconfiguration validation

## Contract and scope

Test only the handed-off endpoint and method. Use `https://example.com` as a
non-credentialed Origin marker; it is a header value, not a destination to
visit. Do not send a browser request, credentials, or a state-changing method
to that origin. Keep the request read-only and in scope. Do not use real user
cookies or tokens in a request unless the runtime provides a secret-safe
mechanism and the operator authorized that exact test.

## Validation

1. Start the matching Candidate. Capture the ordinary response without an
   `Origin` header, then make the same read-only request with the marker
   Origin from `payloads.txt`. Record `Access-Control-Allow-Origin`,
   `Access-Control-Allow-Credentials`, `Vary: Origin`, status, and whether
   the response is public or contains protected data. Do not copy sensitive
   body content.
2. If the candidate concerns preflight, send one `OPTIONS` request with
   `Origin`, `Access-Control-Request-Method: GET`, and only the specific
   harmless request header under review. Do not ask permission to preflight
   `POST`, `PUT`, `PATCH`, or `DELETE` unless the candidate and operator
   explicitly scope a non-mutating preflight-only check.
3. Treat `Access-Control-Allow-Origin: *` on public data as a policy
   observation, not proof of sensitive exposure. A confirmed risky policy
   requires reproducible acceptance of an untrusted Origin together with
   credential allowance on the relevant protected response. Without safe
   browser-level evidence, use `browser-required` if actual credentialed
   cross-origin readability is the unresolved question; never infer it from
   headers alone. A reflected origin without `Vary: Origin` is a cache-risk
   signal, not proof of cross-user data exposure.
4. Record a canonical outcome with `workflow(action="record_result", ...)`.
   Register a small redacted header-only proof artifact before `confirmed`.

## Stop and report

Stop the default flow after the baseline, one Origin request, and at most one
relevant preflight. It does not automatically test credential theft,
private-network access, cache poisoning, or application actions. If the
engagement objective requires a separate browser-readable impact check on a
disposable account, first record the current result and ask `ask_user` to name
the candidate, exact endpoint/account, read-only action, data bound, and risk
tier. Proceed only with that approval and an exact-action runtime permission
prompt that `/yolo` cannot bypass; get fresh approval for any higher tier.
This skill currently has no browser-execution tool, so use
`browser-required` rather than simulate the check. If an impact action has no
exact, non-`/yolo`-bypassable runtime permission gate, record
`authorization-required` and stop. Report exact request headers and CORS
response headers in `artifacts/cors-misconfiguration/<target>/results.md`;
state whether the resource was public/protected and what browser behavior was
not tested. Call `confirm_finding` only when the Candidate is `confirmed`
with registered evidence, and state observed configuration separately from
conditional impact.

## Confirm an evidence-backed finding

For a confirmed result only, call `confirm_finding` with `candidate_id`,
`title`, `severity`, exact `url`, `observed_impact`, and conditional
`potential_impact`, plus `method`, `parameter` when present, the harmless
Origin marker as `payload`, a short header `response_excerpt`, reproducible
redacted `curl`, specific `remediation`, and
`vuln_class: cors-misconfiguration`. The latest result and registered
evidence must be valid. Keep browser-dependent consequences conditional.
Recommend an explicit Origin allowlist, avoiding credentialed wildcard or
reflection policies, and returning `Vary: Origin` when responses vary by it.

## Completion

After all handed-off candidates are recorded, call
`workflow(action="complete_skill", skill_name="cors-misconfiguration",
artifact_ref="artifacts/cors-misconfiguration/<target>/results.md")`.
