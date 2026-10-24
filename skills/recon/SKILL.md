---
name: recon
description: >
  Initial reconnaissance of a target: identify the reachable service,
  fingerprint the technology stack, and collect obvious attack-surface
  clues. Works for a domain, IP, URL, or localhost target (e.g.
  http://localhost:3000). Use when the agent has just received a new
  target and has no prior information about it — before endpoint-level
  enumeration or vulnerability testing.
stage: reconnaissance
triggers:
  strong:
    - recon
    - reconnaissance
    - enumerate subdomains
    - certificate transparency
    - fingerprint live hosts
    - new target
  weak:
    - attack surface
    - technology stack
    - reachable service
    - apex domain
candidate-classes: []
completion-artifact: artifacts/recon/{target}/summary.md
requires: []
allowed-tools:
  - shell
  - http
  - service_discovery
  - file_write
  - workflow
---

# Recon playbook

You have been asked to establish an initial picture of a target the user is
authorized to test. This phase answers "what is this target and what is it
running?" It does not map endpoints, parameters, or forms. That belongs to
`web-enumeration`.

Prefer the built-in `http` tool with `phase: recon` for reachability and
fingerprinting. Use `curl` only when the native tool cannot express a necessary
request detail; shell requests do not enforce target-origin scope.
Use `service_discovery` only when the active target's service/port coverage is
unclear and resolving it is relevant. If the active URL already establishes the
web port and no broader service question remains, record service discovery as
`not_applicable` with a reason. The semantic tool uses bounded native TCP checks.
Choose HTTP, native service discovery or no extra probe from current observations.
External scanner integration is unavailable; do not substitute shell scan loops.
Do not automatically invoke generic-shell `nmap`, `subfinder`, `httpx`, `ffuf`,
`gobuster`, `amass` or `assetfinder` for reconnaissance.
The semantic tool is limited to the active URL's effective port. It resolves
the target once, checks every resulting address against the private-host policy,
and pins the scan to a vetted numeric address; do not supply another host or
port to broaden scope.

Execution rule: substitute the real target into commands before running them.
Never write literal placeholders such as `<TARGET>`, `<HOST>`, or `<APEX>`
to files. If the target is unclear or its scope was not already stated in
the conversation, ask once before running commands.

## Target identifier convention

Before writing any output path, derive a single, stable identifier from the
target and reuse it for every file this skill (and downstream skills) write.
This must be deterministic — the same target must always produce the same
identifier, so `recon`, `web-enumeration`, and `web-input-analysis` land in
the same directory.

1. Start from `agent.target.base_url()` if set, otherwise
   `agent.target.name()`.
2. Strip the scheme (`http://`, `https://`).
3. Lowercase everything.
4. Replace any run of characters outside `[a-z0-9]` with a single `-`.
5. Trim leading/trailing `-`.
6. Truncate to 64 characters.

This mirrors the charset and normalization already enforced for finding
slugs in `src/findings/store.py` (`_SAFE_SLUG_RE`, `slugify()`) — lowercase
alphanumerics and hyphens only, no underscores, no path separators, 64-char
cap. Do not invent a different charset per skill.

Example: `https://App.Example.com:8443/` → `app-example-com-8443`.

Below, `<target>` always refers to this derived identifier, not the raw
target string.

## 1. Confirm the target and its shape

Restate the target and confirm that it is in scope, but only ask for
confirmation when scope has not already been made explicit.

Classify the target because this determines which reconnaissance steps apply:

- **Single URL** such as `http://localhost:3000` or
  `https://app.example.com`: proceed directly to step 2.
- **Bare domain/apex** such as `example.com`: this may represent multiple
  hosts. Consider step 1b when broader surface mapping is explicitly needed.
- **IP address**: skip subdomain discovery and proceed to step 2.

Do not perform external-domain reconnaissance against a target that is clearly
a single local URL, localhost service, or standalone IP.

## 1b. Passive subdomain discovery for a root domain

Only perform this step when all of the following are true:

- the target is a bare apex domain;
- broader attack-surface mapping is intended;
- the discovered subdomains remain within the authorized scope.

Skip this step entirely for single URLs, localhost targets, and IP addresses.

Prefer certificate-transparency data already supplied by the operator.
crt.sh is a separate origin from the target: for a fresh lookup, the operator
must explicitly add the lookup origin to scope and its native HTTP request
must pass runtime permission. Then use one bounded native `http` GET with
`phase: recon`, the real scoped apex in the query and an explicit response cap.
Do not use shell/curl to bypass a missing scope entry, denied request or
unavailable lookup. Without those prerequisites, record the lookup as omitted.
`crt.sh` may return `502`, HTML, empty or truncated JSON. Validate the retained
response before parsing; accept only a complete JSON array before extracting
`name_value` fields. Record unavailable/partial data without shell retry
loops or fetching again merely to recover omitted content.

Save the deduplicated list with `file_write` to:

`artifacts/recon/<target>/subs.txt`

(using the identifier derived above for the apex, not the raw domain string).

Record discovered hostnames as untested references. Reachability checks require
the operator to add each exact origin to scope; discovery alone grants no rights.

Do not automatically escalate to `subfinder`, `amass`, or `assetfinder`.
Use them only when the operator explicitly authorizes domain/subdomain
enumeration and identifies the in-scope domain; the active hostname alone
does not authorize sibling hosts. A coverage gap is
not sufficient authorization to broaden the target set.

## 2. Establish reachability

For a single target, one request is normally sufficient.

Capture the HTTP status, final URL, response headers, and basic page metadata
through the native HTTP tool. This example assumes the target's initial path
is its root; preserve a supplied application base path when relevant:

```json
{
  "tool": "http",
  "arguments": {
    "method": "GET",
    "url": "/",
    "phase": "recon",
    "max_response_bytes": 8192
  }
}
```

Inspect the retained status, URL, headers and bounded page body for title,
Server and X-Powered-By clues. Avoid repeated requests when the initial
response already provides sufficient information. Do not re-fetch the body
just to extract a header or title.

If the first response is ambiguous, choose one relevant follow-up from
observed evidence. For example, if the application references an API health
path:

```json
{
  "tool": "http",
  "arguments": {
    "method": "GET",
    "url": "/api/health",
    "phase": "recon",
    "max_response_bytes": 8192
  }
}
```

An OPTIONS request may answer an actual method question:

```json
{
  "tool": "http",
  "arguments": {
    "method": "OPTIONS",
    "url": "/",
    "phase": "recon",
    "max_response_bytes": 8192
  }
}
```

Do not turn these probes into broad endpoint enumeration. Native HTTP returns
headers with the response; a separate curl/header capture is unnecessary.

### Redirect and origin handling

For this playbook keep native `http` at its default `max_redirects=0`; optional
per-hop redirect support is not a reason to use curl. Record each observed
status and `Location` explicitly. Follow a redirect manually only when its destination
is inside the active authorized origin. For a same-origin redirect, make a
separate bounded request to the recorded path and retain both response steps.
Treat an HTTP-to-HTTPS upgrade as a scheme change that needs its own in-scope
check; do not silently switch the active target. For a cross-origin or SSO
redirect, record the destination as an external reference and stop there.
Never forward cookies or authorization headers to it. If a bounded manual
check repeats a previously seen URL or redirect edge, record a redirect loop
and stop.

A `401` or `404` JSON response at a root path such as `/`, `/api`, or
`/api/v1` still proves that an HTTP service responded. Record the status, media
type, and compact error shape, then mark the application architecture as
API-only or hybrid only if other evidence supports it. Hand any API paths or
documentation clues to enumeration. Do not label the service unreachable
because a root route has no web page or API operation.

## 2b. Optional bounded service discovery

When the target is a host or IP and the exposed service is unclear, call
`service_discovery` for the active target URL's effective TCP port. It does not
accept additional ports or hosts, uses a 20-second default timeout (120-second
hard cap), and does not use UDP, NSE scripts, OS detection, host ranges, service
version probes, or raw Nmap flags. An open port may
suggest an HTTP(S) origin; do not request it or add it to scope automatically.
If service discovery is not useful or its coverage is already established,
record a `not_applicable` or `skipped` reason in the phase coverage record.

## 2c. Record target shape and security observations

Use evidence from the initial page, headers, cookies, and only the bounded
indicators above to record an architecture hypothesis:

- `traditional/SSR`: server-rendered documents, forms, or navigation links;
- `SPA`: an application shell plus client bundles or observed client routing;
- `API-only`: API-shaped responses or documentation without an observed web UI;
- `hybrid`: evidence for both a rendered application and separate API surfaces;
- `unknown`: evidence does not distinguish these shapes.

Keep each observation separate from the inference. A single status, header,
technology fingerprint, or bundle filename is not enough to confirm the
architecture.

Record security and intermediary clues as observations with their source and
evidence: cookie names and `Secure`/`HttpOnly`/`SameSite` attributes, CSP,
HSTS, observed CORS headers, and indicators such as `cf-ray` or a matching
challenge page. One header is a clue, not a `waf_detected` conclusion. Note
that a `403`, `429`, or challenge response may come from an intermediary; do
not assign it to application behavior without evidence.

## 3. Fingerprint the technology

Use the observations already collected to identify likely technologies.

Look for evidence such as:

- Server response headers;
- `X-Powered-By`;
- framework-specific cookies such as `JSESSIONID` or `.AspNetCore`;
- generator metadata;
- framework-specific static asset paths;
- recognizable error-page structures;
- authentication/session indicators;
- API indicators exposed by the initial response or a small number of
  low-noise probes.

For limited probing of obvious application indicators, select only a missing,
relevant clue, such as an observed API path or documentation reference.
Possible paths include /api, /api/health, /graphql, /swagger.json and /robots.txt;
they are alternatives, not a checklist to request blindly. For example:

```json
{
  "tool": "http",
  "arguments": {
    "method": "GET",
    "url": "/robots.txt",
    "phase": "recon",
    "max_response_bytes": 8192
  }
}
```

These probes are for technology and application-shape identification only.
Detailed API, route, endpoint, and parameter enumeration belongs to
`web-enumeration`.

Treat fingerprint results as hypotheses until supported by concrete evidence.
Do not state that a technology is confirmed without an observable indicator.

## 4. Record initial attack-surface clues

Record only the high-value clues already visible from reconnaissance.

Examples include:

- login or authentication pages referenced by the initial application;
- administrative interfaces visible from existing links or resources;
- obvious API entry points;
- exposed API documentation;
- authentication/session mechanisms;
- security-relevant response headers;
- cookie flags such as `Secure` and `HttpOnly`;
- JavaScript bundle names that reveal application structure.

Do not perform broad content discovery here.

In particular, do not run wordlist-based endpoint discovery, directory
brute-forcing, or parameter enumeration. Those tasks belong to
`web-enumeration`.

## 5. Record reconnaissance results

Immediately before `file_write`, reconcile each claim with its source/reference:
effective method/endpoint, HTTP status, response media type, redacted body marker,
capture flags and claim confidence. Observations/documents actually read take
precedence over conflicting LLM summaries. In prose distinguish direct observation,
observed from specification, inference/hypothesis and unknown; these are not new
Workflow fields or outcomes. Request Content-Type is not response Content-Type.
JSON product results do not show a SQL statement; a parser diagnostic establishes
parser sensitivity, not the full query or controlled evaluation.

Retained response completeness, ranges actually read and content still in context
are separate. Content-Length is not the number of bytes inspected. Status 200,
HTML media type, a filename or metadata-only capture proves neither body review,
SPA fallback nor operation success. Reuse trustworthy sources already in context;
list metadata or read a missing range only when needed and currently permitted.
If unavailable, state the limitation; do not refetch, raise caps, cache-bust or
switch to shell to recover content. Keep attribution short and redacted in the
canonical summary, without a mandatory artifact/ledger for every response.

Write that concise summary to:

`artifacts/recon/<target>/summary.md`

After writing it, call `workflow(action="complete_skill", skill_name="recon",
artifact_ref="artifacts/recon/<target>/summary.md", current_phase="enumeration")`;
runtime rejects completion when the canonical artifact is absent, empty, or a
different path is supplied. When a reachable web target can be enumerated,
proceed with `enumeration`. If reachability failed, set
`current_phase="blocked"` and record the failure in the summary instead.
Completion records that this bounded reconnaissance pass ended; it does not
force the next skill or prevent targeted recon later.

For whole-target work, wait for successful Workflow Recon completion before
Enumeration or `content_discovery`. Writing this summary, loading a skill, or
obtaining permission does not complete Recon. If completion is rejected, resolve
the stated missing coverage/artifact work before retrying or moving on.

For whole-target work, inspect workflow coverage before completion and account
for `target_resolution`, `reachability`, `http_fingerprint`, and
`service_discovery`. `performed` is reserved for machine-observed execution:
never call `record_phase_coverage` to self-claim it. Native `http` automatically
records reachability from a received response, target resolution from its
pinned numeric transport, and HTTP fingerprinting from inspected response
headers. This does not attest an inferred framework/database or exploit.
`service_discovery` records its own execution coverage.

For dimensions without an execution adapter, reviewed work uses
`workflow(action="record_phase_coverage", phase="recon",
coverage_dimension=..., coverage_status="observed", coverage_reason=...)`.
Include the source/artifact and the missing attestation limitation. `observed`
is an unattested review, not proof of execution. Never use `skipped` to simulate
performed work or work around a missing adapter. Use `skipped` only for work
actually omitted and `not_applicable` only when the dimension truly does not
apply, each with a short valid reason. Do not replace existing runtime
`performed` records. Retry failed/cancelled dimensions or explain an actual
skip before completing; missing observations never imply `performed`.

The summary should contain:

- target and target type (URL, apex, or IP);
- reachable service and observed status;
- final URL after redirects, when applicable;
- effective in-scope origin and redirect edges, including any unvisited
  cross-origin or scheme-upgrade destination;
- architecture hypothesis with its supporting observations, or `unknown`;
- observed technologies, explicitly marked as confirmed or hypothesis;
- authentication/session and security-header clues, without copying secrets;
- intermediary observations with evidence and confidence;
- script bundles, document/API clues, and relevant paths for enumeration;
- initial attack-surface clues;
- unresolved reachability, redirect, architecture, and intermediary ambiguity;
- other relevant uncertainties;
- recommended next phase.

Do not create a security finding from reconnaissance observations alone unless
reproducible evidence already demonstrates a vulnerability. (Findings, when
they eventually exist, are persisted and named by `confirm_finding` — do not
reuse the target identifier for a finding file name.)

## 6. Transition to the next phase

When the target is a web application:

- transition to `web-enumeration` to identify endpoints, routes, parameters,
  forms, and API surfaces;
- use `web-input-analysis` only after enumeration has produced concrete
  candidate inputs;
- do not jump directly to a vulnerability-specific skill merely because a
  technology or framework was fingerprinted.

The normal flow is:

```text
recon
  ↓
web-enumeration
  ↓
web-input-analysis
  ↓
vulnerability-specific skill
```

## Stop conditions

Stop reconnaissance when:

- the target has been classified;
- reachability has been established or the failure is clearly recorded;
- major technology indicators have been identified or explicitly marked
  unknown;
- initial attack-surface clues have been recorded;
- the next phase can be determined.

Do not escalate reconnaissance into high-volume scanning, full subdomain
brute-forcing, or deep content discovery. Those activities belong to later
phases and should only be performed when justified by the testing plan and
authorized scope.
