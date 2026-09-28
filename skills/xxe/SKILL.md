---
name: xxe
description: >
  Assess XML entity processing for one authorized lab candidate, starting
  with a harmless internal marker entity. External resolution is out of
  bounds unless a user-designated non-sensitive fixture or callback and the
  exact action are explicitly authorized.
stage: validation
triggers:
  strong:
    - xml external entity
    - xxe
    - external entity resolution
    - xml entity expansion
  weak:
    - dtd processing
    - xml parser configuration
    - external general entity
candidate-classes:
  - xxe
requires:
  - web-input-analysis
completion-artifact: artifacts/xxe/{target}/results.md
allowed-tools:
  - http
  - read_payloads
  - file_write
  - ask_user
  - workflow
  - confirm_finding
---

# XXE validation

## Contract and preconditions

Validate only the handed-off XML endpoint and input. Confirm the target,
method, content type, and parser context. Start with the internal entity
marker in `payloads.txt`; it performs no file or network access. Internal
entity expansion by itself shows parser behavior, not external-entity
resolution and is not enough to claim XXE.

Do not read system files, application configuration, credentials, cloud
metadata, or user data. Do not probe an external URL, private host, or
loopback destination through an entity. External-entity confirmation may use
only a harmless marker file already designated by the operator inside the
isolated lab, or a user-controlled callback host. Ask once for explicit
authorization naming that exact fixture/host and the single permitted probe.
If none is supplied, record `authorization-required` or
`insufficient-evidence` and stop. Never use a public/shared callback service
without explicit approval. A callback caused by XML parsing is an external
side effect and must not be inferred as covered by permission for the HTTP
request to the application.

## Validation

1. Start the Candidate and capture a benign XML baseline using the same
   method, endpoint, content type, and auth context.
2. Read `payloads.txt` with `read_payloads(skill="xxe",
   file="payloads.txt")`. Send the internal literal marker entity first.
   If the marker is returned, record it as a parser signal only; do not call
   it external-entity XXE.
3. Only after the exact external-resolution check is authorized, replace
   `AUTHORIZED_LAB_MARKER_URI` in the template with the operator-provided
   non-sensitive fixture URI or controlled callback URL and a unique random
   label. Never send the placeholder literally. Send one probe, observe only
   the expected marker or matching callback, then stop. Do not use nested,
   recursive, parameter-entity, expansion-amplification, or blind extraction
   techniques.
4. Confirm external entity resolution only when the exact harmless fixture
   marker is returned or the authorized callback records the unique label.
   A parse error, `DOCTYPE` acceptance, or internal entity output is not
   enough. Record a redacted proof artifact and a canonical workflow result;
   keep callback and fixture details to the minimum needed for reproduction.

## Stop and report

The default proof does not read secret files, reach arbitrary destinations or
cloud metadata, perform OOB exfiltration, use expansion bombs, or extract
data. This is not a blanket prohibition on authorized impact validation: if
the engagement objective needs a separate non-sensitive fixture or controlled
callback check after the current result is recorded, ask `ask_user` to name
the candidate, exact target and fixture/callback, single action, bound, and
risk tier. Proceed only after that approval and an exact-action runtime
permission prompt that `/yolo` cannot bypass; a new tier needs fresh approval.
If the runtime cannot enforce that gate, record `authorization-required` and
stop. Report whether
internal entity expansion and external resolution were independently
observed, the exact authorized marker source, and any untested behavior in
`artifacts/xxe/<target>/results.md`. Register only redacted evidence; call
`confirm_finding` only after external resolution is confirmed.

## Confirm an evidence-backed finding

For a confirmed result only, call `confirm_finding` with `candidate_id`,
`title`, `severity`, exact `url`, `observed_impact`, conditional
`potential_impact`, `method`, `parameter`, the harmless fixture marker
probe as `payload`, short `response_excerpt`, reproducible redacted `curl`,
specific `remediation`, and `vuln_class: xxe`. The latest result and
registered evidence must be valid. Do not state file disclosure or SSRF
impact beyond the exact marker behavior observed. Recommend disabling
external general/parameter entities and external DTD retrieval in the XML
parser, with a safe parser configuration appropriate to the verified stack.

## Completion

After every handed-off Candidate has an outcome and the artifact exists, call
`workflow(action="complete_skill", skill_name="xxe",
artifact_ref="artifacts/xxe/<target>/results.md")`.
