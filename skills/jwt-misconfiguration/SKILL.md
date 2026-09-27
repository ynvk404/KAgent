---
name: jwt-misconfiguration
description: >
  Validate JWT parsing and claim/signature enforcement for a specific
  authorized lab candidate using only a disposable tester-owned subject and a
  read-only endpoint. Never expose real tokens, guess keys, or impersonate
  another user or role.
stage: validation
triggers:
  strong:
    - jwt misconfiguration
    - json web token validation
    - unsigned jwt accepted
    - jwt algorithm confusion
  weak:
    - jwt claim validation
    - token expiration
    - jwt issuer audience
candidate-classes:
  - jwt-misconfiguration
requires:
  - web-input-analysis
completion-artifact: artifacts/jwt-misconfiguration/{target}/results.md
allowed-tools:
  - http
  - read_payloads
  - file_write
  - ask_user
  - workflow
  - confirm_finding
---

# JWT misconfiguration validation

## Contract and secret handling

Validate only the supplied Candidate's JWT verification behavior. Use an
operator-designated disposable lab subject and a read-only endpoint. Never
request, copy, decode, or persist another person's token; never include a raw
JWT, signature, cookie, or credential in results or evidence. Do not use
third-party token-decoding websites.

The current HTTP tool accepts literal headers/bodies and its permission
summary can expose them. Therefore do not pass a real or reusable JWT through
the tool. If the candidate requires a valid real test token and no
secret-safe runtime reference is available, stop with
`insufficient-evidence`. A synthetic unsigned token containing only a
tester-owned fixture subject is not a credential, but testing its acceptance
is an authentication-bypass probe: ask once for explicit authorization for
that exact read-only lab check before sending it.

## Validation

1. Start the Candidate. Record only token format, algorithm label, and
   non-sensitive claim-presence/validation behavior; never retain token
   bytes. Confirm the endpoint is read-only and the subject is the tester's
   disposable fixture.
2. Read `payloads.txt` with `read_payloads(skill="jwt-misconfiguration",
   file="payloads.txt")`. A synthetic unsigned token can test only whether
   unsigned input is accepted. To test an algorithm allowlist or an individual
   `exp`, `nbf`, `iss`, or `aud` rule, use a separately issued disposable
   fixture token with a valid signature for that specific case and a
   secret-safe transport. Never edit a signed token's claims and interpret
   the expected signature failure as claim validation. The current HTTP tool
   has no secret-safe token reference, so if the only valid fixtures are raw
   tokens, do not send them and record the untested property as
   `insufficient-evidence`. Do not combine claim changes. Do not attempt key
   guessing, weak-secret dictionaries, `kid` path/URL tricks, algorithm
   confusion using guessed keys, claim changes to another user/admin, or
   token replay to other APIs.
3. A status code alone is not enough. Confirm only if a tampered synthetic
   fixture token is accepted by the protected read-only endpoint and the
   returned marker belongs to the designated fixture subject. Stop at that
   first reproducible result. If browser/session state or a real token would
   be needed to interpret the response, use `insufficient-evidence` rather
   than exposing it.
4. Record the canonical outcome via `workflow(action="record_result", ...)`.
   Use `authorization-required` if the exact synthetic-token probe was not
   authorized, `blocked` only for verified upstream interception, and
   `deferred` if the issue is not JWT verification. Register a redacted,
   token-free proof artifact before `confirmed`.

## Stop and report

Do not test token theft, account takeover, privilege changes, signing-key
recovery, or session replay. Report the algorithm/claim rule observed, the
protected fixture action, status and a non-sensitive marker, and explicitly
state token material was not retained in
`artifacts/jwt-misconfiguration/<target>/results.md`. Keep workflow evidence
referential and redacted.

## Confirm an evidence-backed finding

For a confirmed result only, call `confirm_finding` with `candidate_id`,
`title`, `severity`, exact `url`, `observed_impact`, conditional
`potential_impact`, `method`, `parameter` when applicable, a safe synthetic
`payload` description (never a real token), short `response_excerpt`,
reproducible token-free `curl`, `remediation`, and
`vuln_class: jwt-misconfiguration`. The latest result and registered evidence
must be valid. State only the validation behavior proved for the fixture.
Recommend a fixed algorithm allowlist, signature verification, and strict
`exp`/`nbf`/`iss`/`aud` validation; never recommend accepting unsigned tokens.

## Completion

After each handed-off Candidate has an outcome and the artifact exists, call
`workflow(action="complete_skill", skill_name="jwt-misconfiguration",
artifact_ref="artifacts/jwt-misconfiguration/<target>/results.md")`.
