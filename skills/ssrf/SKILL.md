---
name: ssrf
description: >
  Validate suspected server-side URL fetching and determine whether a
  parameter is vulnerable to SSRF. Confirm the fetch primitive first,
  characterize URL validation and redirect behavior, then perform minimal,
  authorized checks against explicitly identified internal destinations to
  establish impact. Use after web-input-analysis when a parameter appears
  to accept a URL, URI, hostname, redirect target, webhook, image URL, or
  similar remote resource reference.
stage: validation
triggers:
  strong:
    - ssrf
    - server side request forgery
  weak:
    - url fetch
    - webhook
    - callback url
    - image url
    - remote url
    - redirect url
candidate-classes:
  - ssrf
requires:
  - web-input-analysis
allowed-tools:
  - http
  - shell
  - file_write
  - ask_user
---

# SSRF validation

Scope: confirm whether a parameter causes the server to make a request you
control the destination of, and characterize how far that reach extends.
This skill stops once SSRF is conclusively demonstrated. It does not chain
into credential theft, RCE, or broad internal network scanning — that is
a separately scoped follow-up that requires explicit authorization.

Execution rule: use the actual target URL, parameter, and (if needed)
callback/canary host before running commands. Never write literal
placeholders such as `<endpoint>` or `<role>` to files or requests.

## Preconditions

Do not begin SSRF confirmation until all of the following are known:
1. Target URL
2. The actual parameter (or body field / header) that accepts the URL-like value
3. HTTP method and where the value goes (query, JSON body, form field, header)
4. A user-authorized callback/canary URL — **only if** blind SSRF confirmation
   is required (i.e. the application does not reflect fetch results directly)

If #4 is missing and blind confirmation is necessary, `ask_user` once for a
canary host they control (interactsh, Burp Collaborator, a listener they own).
Do not invent or reuse a canary domain from memory or prior sessions.

## Scope checkpoint (ask_user)

Before sending any request that targets:
- private/internal IP ranges (`127.0.0.1`, `10.0.0.0/8`, `169.254.0.0/16`, etc.)
- cloud metadata endpoints
- `localhost` or loopback in any encoding
- any host that is not the in-scope target and not a user-provided canary

confirm authorization/scope with `ask_user` if it has not already been
established for this engagement. Do not assume permission from the fact
that a parameter merely accepts a URL.

## 1. Confirm the primitive

Send the request with the parameter pointing at:
- A user-authorized canary (if blind), or
- A control value you can distinguish from a normal response (if the
  application reflects fetch results, timing, or errors)

Compare against a baseline request. If the canary fires, or the response
demonstrably differs in a way only explained by a server-side fetch, the
primitive is confirmed. If neither happens, do not conclude that SSRF is
absent. Stop this validation path and report that SSRF could not be
confirmed with the available evidence — the null result may be caused by
blind behavior without a matching canary, active filtering, a timeout, or
a response that simply doesn't reflect the fetch outcome.

## 2. Phase A — safe validation

Only after the primitive is confirmed, probe minimally to characterize
behavior:
- `http://127.0.0.1`, `http://localhost`, `http://[::1]`
- One user-controlled redirect target, to see if redirects are followed

Classify each as: accepted / rejected / normalized / redirected /
server-fetched. This is enough to know whether there is a filter at all.

## 3. Phase B — filter bypass (conditional)

Only proceed here if Phase A shows **both**:
- the parameter performs a server-side fetch, **and**
- there is evidence of active URL filtering (i.e. plain loopback was rejected)

If both hold, try a small, targeted set of bypasses relevant to the
observed filter (e.g. an alternate loopback representation, or the
specific redirect/DNS trick that would plausibly evade what you saw
rejected) — not the full bypass corpus by default.

## 4. Minimal internal-access validation

Do not perform broad internal network scans. Only validate destinations
you have explicit evidence for (from recon, config leakage, or user input),
using the minimal set of ports/paths needed to demonstrate impact.

Example: if evidence points to `localhost:6379`, test that service.
Do not sweep `127.0.0.1:1-65535` or `10.0.0.0/8`.

## 5. Minimal metadata validation

If the target environment is plausibly cloud-hosted, a single request to
the relevant metadata root (e.g. `http://169.254.169.254/latest/meta-data/`)
is sufficient to demonstrate metadata-endpoint reachability. Do not
enumerate IAM roles or retrieve credential material — that is impact work,
not validation, and requires a separately scoped authorization.

## 6. Stop when impact is proven

Stop at the first point you have conclusive evidence, using the lowest
step number that applies:

- **SSRF-1** — external callback confirmed (canary fired)
- **SSRF-2** — localhost/private-network fetch confirmed (response
  differs in a way only explained by reaching that destination)
- **SSRF-3** — an explicitly identified internal service reached
  (e.g. confirmed `:6379` response)
- **SSRF-4** — a cloud metadata endpoint confirmed reachable

Do not continue toward credential retrieval, credential use, RCE
chaining, or file disclosure. If the finding warrants deeper impact
validation, say so in the report and stop — do not perform that work here,
even if it looks like "just one more step."

## Reporting

Write a report to `findings/ssrf-{sanitized-parameter-or-path}.md`. The
filename must be derived from the actual target/parameter and sanitized
for filesystem safety (lowercase, non-alphanumeric characters replaced
with `-`). Never write a literal placeholder as the filename.

Include: the exact request(s), the exact response(s) or canary evidence,
the SSRF level reached (1–4), and — if applicable — a one-line note that
deeper impact validation would require separate scope and authorization.
