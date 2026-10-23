---
name: web-enumeration
description: >
  Enumerate the attack surface of a known, reachable web application: routes,
  endpoints, HTTP methods, parameters, forms, API entry points, and relevant
  static/JS resources. Builds a normalized inventory for later analysis. Use
  after `recon` has established a reachable web target and technology
  baseline, and before `web-input-analysis` or any vulnerability-specific
  testing. Does not attempt to exploit, classify, or confirm vulnerabilities.
stage: enumeration
triggers:
  strong:
    - web enumeration
    - enumerate endpoints
    - enumerate routes
    - map attack surface
    - content discovery
    - directory discovery
    - api entry points
    - swagger
    - openapi
  weak:
    - endpoint
    - route
    - parameter
    - form
    - inventory
    - static resources
    - javascript resources
candidate-classes: []
completion-artifact: artifacts/web-enumeration/{target}/inventory.md
requires:
  - recon
allowed-tools:
  - shell
  - http
  - content_discovery
  - file_write
  - workflow
---

# Web enumeration playbook

**Objective:** map the web application's reachable attack surface — routes,
endpoints, parameters, forms, API surfaces, and relevant static/JS resources
— without attempting vulnerability exploitation or drawing vulnerability-
class conclusions.

Whole-target flow: reuse sources → read and establish structure → `record_input`
→ reconcile canonical records → inventory and coverage → `complete_skill` →
Input Analysis. Native HTTP obtains a new source only when needed; Content
Discovery fills a concrete path gap. In Direct mode, discover only what the
specific request needs; do not force all phases or whole-target source actions.

Prefer the built-in `http` tool with `phase: recon` for known-source
enumeration. Use `curl` only when the native tool cannot express a necessary
request detail; shell requests do not enforce target-origin scope.
For a necessary new source via shell, keep the exact active origin, one GET,
no redirects, timeout ≤8 seconds and download cap ≤64 KiB. Shell approval
does not authorize another origin or a replacement fetch for omitted content.
Use `content_discovery` only when steps 2–5 leave a concrete path-coverage gap.
`content_discovery` uses native HTTP through the runtime permission gate.
Discovery stays on the active origin, is bounded, and requires
permission. Do not run generic-shell `ffuf`, `gobuster`, or `dirsearch`
automatically.

Use native `content_discovery` only for an actual path gap; no additional
probe is required when known/documented/captured inventory is sufficient.
External scanner integration is unavailable; do not substitute shell scan loops.

Execution rule: substitute the real target into commands before running them.
Never write literal placeholders such as `<TARGET>`, `<HOST>`, or `<endpoint>`
to files. If the target or scope is unclear, ask once before running commands.

## Target identifier

`<target>` below always refers to the identifier derived by the convention
defined in `recon/SKILL.md` ("Target identifier convention"). Reuse that
identifier exactly — do not re-derive it differently here, and do not invent
a different naming scheme for this skill's output paths.

## Preconditions

For whole-target work, complete Recon through Workflow before Enumeration,
including the first `content_discovery` call. A summary file or loaded skill
alone is not completion. Run discovery only for a real remaining path-coverage
gap, never just to obtain a receipt. If earlier work lacks machine attestation,
record its source and limitation as `observed` under the coverage contract;
never backfill `performed`, invent a skip, or repeat discovery solely for it.

Before starting, you should have from `recon` or the user:

- a confirmed, reachable target (URL, host, or set of hosts);
- observed technology signals;
- confirmation that the target is in scope.

If the target itself is unknown or scope is unclear, return to `recon` first.

If the target is known but the recon output is unavailable, perform only the
single lightweight request in step 1 to recover the minimum baseline. Do not
repeat full reconnaissance or technology fingerprinting here.

## Incremental structured handoff (throughout steps 1–6)

As soon as an endpoint and input are supported by an observed request, form,
API schema, or network call site, call `workflow(action="record_input", ...)`
immediately, before fetching another resource. Do not wait for the final
inventory or for an entire Swagger document, directory listing, or bundle.
Reuse sufficiently specific evidence from recon. A route name or a GET error
on a login path does not establish a POST body field: record only the method,
parameter, and location actually observed. Documented inputs may be recorded
without submitting a form; retain their source and unknown reachability in the
inventory. Record each newly established input once; reuse its returned ID.

For a whole-target objective, record every discovered request input
surface with `workflow(action="record_input", method=..., endpoint=...,
parameter=..., location=..., input_type=..., content_type=...,
sample_payload=...)` when those details are known. Use one compact record per
method/endpoint/parameter/location/type/media combination. `content_type` is
optional, but known media types distinguish input identities; charset and
multipart boundary parameters do not. `sample_payload` does not change identity. Store a
small body skeleton, not raw traffic: retain the structure and replace values
with inert examples or `{INJECTION_POINT}`. Omit passwords, tokens, cookies,
PII, and unrelated fields. Record query, body, path, header, and cookie inputs
that were actually observed. The runtime assigns the active objective and
target origin and deduplicates semantic duplicates.

Keep these inputs pending for `web-input-analysis`. Do not call
`record_candidate`, assign a vulnerability class, or mark an input analyzed
in enumeration. Input recording does not complete the phase: write the
inventory and account for coverage before `complete_skill`.

## Large responses: bounded reading, then move on

A response truncation marker or context-guard omission is a strategy signal.
Do not repeatedly fetch the same large resource, increase `max_response_bytes`,
or add empty queries/cache-busters to obtain the whole blob. Check status and
Content-Type first: HTML at a guessed Swagger URL is not a JSON specification.
Use already visible input/schema/link clues and record them immediately.

Reuse content already seen or search a retained local artifact under existing
read permissions, with at most 40 matches and 4,000 output characters.
Native HTTP returns a bounded response
inline; its raw ObservationStore bytes are not a general discovery reader or
an automatic `read_tool_result` cache. Context omission and response truncation
are different: `complete=true` does not mean omitted text is still visible.
Do not fetch again, increase caps or cache-bust just because context lacks a
part that was already retained. `read_http_observation` keeps its validation
ownership contract: do not use it for an unowned discovery observation, create
a Candidate/validation attempt to gain read rights, or infer authority from a
source ID. If content is unavailable, evicted, outside limits or unreadable
under current rights, record that limitation and work with known inputs.
Do not raise the bound or restart retrieval.
Use `content_discovery` only for an actual path gap, not to download a blob.
Partial review is sufficient for a bounded inventory; do not make complete
large-resource ingestion a prerequisite for handoff. Once the known input
surface and coverage are accounted for, write the inventory and transition to
`web-input-analysis`, retaining unresolved source limitations.

## 1. Build the target baseline

Reuse `artifacts/recon/<target>/summary.md` when it exists — do not repeat
reachability or fingerprinting work `recon` already did. Before re-probing
anything, check whether `recon`'s summary already recorded a definitive
result for it (e.g. `/robots.txt` status, `/graphql` presence); only
re-probe if that result was inconclusive or missing.

The JSON examples below name the KAgent tool and its arguments. Relative URLs
resolve on the active target. Preserve its supplied base path where relevant;
never copy an example origin or path as an authorization declaration.

If recon output is unavailable, perform one lightweight request:

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

Record the API style only when it is already apparent from recon or this
single request (for example REST, GraphQL, or server-rendered HTML). This
observation only determines which enumeration steps are relevant.

## 2. Enumerate routes and endpoints from known sources

Prefer routes the application already exposes before guessing paths.
Check high-signal discovery files first — skip any of these already recorded
with a definitive result in `artifacts/recon/<target>/summary.md`:

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

```json
{
  "tool": "http",
  "arguments": {
    "method": "GET",
    "url": "/sitemap.xml",
    "phase": "recon",
    "max_response_bytes": 8192
  }
}
```

```json
{
  "tool": "http",
  "arguments": {
    "method": "GET",
    "url": "/.well-known/security.txt",
    "phase": "recon",
    "max_response_bytes": 8192
  }
}
```

Parse the landing page for internal links, form actions, and script sources:

Use the already retained landing-page body: collect `href`, `src` and `action` values,
resolve them against that page URL, and deduplicate the same-origin references.
Parsing the retained response does not require another request.

Follow same-origin links one level deep when necessary to collect additional
application routes. Do not recursively crawl the entire application here.
Only retain URLs within the authorized target scope. Skip clearly external
origins unless they are explicitly in scope.

Use recon's architecture hypothesis to choose sources. For a traditional or
SSR application, prioritize anchors, forms, actions, hidden fields, and
navigation. For an SPA, inspect the shell, referenced bundles, observed router
configuration, and fetch/XHR/axios call sites for API base URLs. For an
API-only target, prioritize exposed OpenAPI/Swagger documents and API clues
already recorded by recon. Keep a `client_route`, `backend_endpoint`, or
`unknown_route_reference` label for each route clue. A router path or a string
found in JavaScript alone is not a backend endpoint.

For a JavaScript clue to count as a backend endpoint reference, record the
surrounding evidence that it is used as a network request (for example a
fetch/XHR/axios call or a configured API client). A route used by the frontend
router is a client route. If context is unclear, keep it as an
`unknown_route_reference`. A reference becomes `reachable` only after a
same-origin request observes a response; a linked or documented path that has
not been requested remains `observed` or `inferred` with its source. Record
`probed` for a deliberate request and `inaccessible` only for an observed
access failure. A `403` may reflect an intermediary noted by recon.

## 3. Enumerate parameters and forms

For each relevant HTML page already collected, extract form structure:

Reuse retained HTML first. If a previously linked `/login` page has not been
collected, a bounded fetch looks like this:

```json
{
  "tool": "http",
  "arguments": {
    "method": "GET",
    "url": "/login",
    "phase": "recon",
    "max_response_bytes": 8192
  }
}
```

For each form, record:

- HTTP method;
- action URL;
- content type from `enctype` or the documented request format;
- field name;
- field type;
- hidden/required state when observable;
- presence of CSRF or similar hidden fields.

Collect query parameters from links, forms, sitemap entries, or API
documentation when present. Record the parameter name and its location:

- query;
- path;
- form body;
- JSON body;
- header;
- cookie.

Do not submit forms or inject test values at this stage. Enumeration records
structure only.
For JSON/API bodies, prefer the documented schema or observed field structure
and write a compact payload skeleton with inert placeholders. Do not copy
actual submitted values, credentials, tokens, or session material.

## 4. Enumerate API surfaces

Check common API documentation and entry points with lightweight requests —
again, skip any already recorded with a definitive result by `recon`:

Choose only unresolved paths that fit the observed application, such as
`/api`, `/api/v1`, `/swagger.json`, `/swagger/v1/swagger.json`, `/openapi.json`, `/api-docs`, `/graphql`, `/.well-known/openapi.json`.
Do not run them as a blind batch. For example, retrieve a relevant spec once:

```json
{
  "tool": "http",
  "arguments": {
    "method": "GET",
    "url": "/openapi.json",
    "phase": "recon",
    "max_response_bytes": 8192
  }
}
```

If a Swagger/OpenAPI document is found, parse documented routes, methods,
parameters, each operation's `requestBody.content` media type/schema, and any
operation-level security requirement. Record their provenance as `observed
from the specification`; do not say they are reachable until requested.

Read operation keys from the retained `.paths` object and record supported
request shapes incrementally. Reuse the same retained response for parsing;
do not fetch a specification again merely to list its paths.

### Inline OpenAPI in Swagger UI

Inspect already visible Swagger UI HTML and its retained initializer before
guessing another spec URL. A definition can be a literal object supplied to
`SwaggerUIBundle({spec: ...})`, or passed through `options.swaggerDoc`, an
intermediate variable, and `swaggerOptions.spec`. Follow only the visible
literal bindings to the object containing `openapi` and `paths`. A separate
JSON download is not required for an inline definition. Swagger UI `url` and
`urls[].url` identify definition-download locations; `servers[].url` identifies
an API base, not a spec URL. A configured inline `spec` can supersede `url`;
do not fetch that URL merely because it appears beside an inline definition.

URL-only extraction from HTML/JS does not enumerate an embedded `paths`
object. No extracted URLs, or a `401`/`403` from an API base, does not establish
that documented operations are absent. Retain the distinction between a
documented operation, an observed response at a particular URL/method,
reachability of that operation, and authenticated access. A successful UI
page response does not establish API-operation reachability either.

Review the visible request syntax without executing JavaScript, `eval`,
deobfuscation, or resolving computed/dynamic values. Enumerate every visible
`paths` method, including operations with no parameters. Read path-item and
operation parameters (name/location, type and required state), operation
overrides, and `requestBody.content` media types and schema fields. Preserve
unresolved `$ref`, truncated definitions and unseen fields as limitations;
never invent missing operations or request fields. Read applicable document
`security` and operation overrides, including `security: []`, alongside
`components.securitySchemes`. Bearer/JWT declarations describe documented
security, not available credentials or successful authentication; a scheme
definition alone does not apply it to every operation. Never copy token values.

Apply `servers` precedence from operation to path-item to document. Append
the operation path to the selected API-base path; do not drop the base prefix
by resolving a leading `/` as a new root. Resolve relative server URLs using
the actual document location and known UI base context; when an inline
definition's relative base is ambiguous, record that uncertainty rather than
inventing a spec URL. Check scheme, host and effective port against exact
authorized scope. An off-origin server is an external documentation clue,
not authority to request it or rebase its operations onto the active target.
Unresolved server variables remain limitations.

### Record documentation and retain attribution

Read visible HTML/JSON/JS yourself under the bounded-reading rules above.
There is no automatic HTML/OpenAPI extraction action. Never execute JavaScript
or register a copied object as a replacement authoritative source.
Runtime retains Discovery Sources for traceability; an unselected pending
source is not a mandatory backlog. Reuse known metadata; use `list` sources or
`get_source` only when an exact reference/hash or limitation is missing.
There is no required select_source → get_source → processing sequence for each
response. Select a source only for deliberate further review, not to tidy the
frontier. Recording an input never selects or dispositions its source.

For each known request field, use `record_input` incrementally under the
active whole-target objective, reusing returned input IDs. For example, only
if this method/base/path/field is actually documented on the active origin:

```json
{
  "tool": "workflow",
  "arguments": {
    "action": "record_input",
    "method": "POST",
    "endpoint": "/service/v4/widgets",
    "parameter": "label",
    "location": "json",
    "input_type": "string",
    "content_type": "application/json",
    "sample_payload": "{\"label\":\"{INJECTION_POINT}\"}"
  }
}
```

Do not manufacture a dummy input for an operation without request fields.
Optionally supply `source_attribution` on the same `record_input` call with
the admitted HTTP/capture source's exact `discovery_source_id`, `retained_ref`,
`retained_hash` and a non-secret `document_location` (JSON pointer, HTML
selector or visible JS binding). Copy actual returned metadata, never IDs from
an example. For GET /openapi.json documenting POST /orders JSON `cid`, attribute
the field to that document and its schema location. The runtime atomically
admits the input's endpoint and a `manual:` provenance linkage. A bad attribution
rejects the whole call; do not drop a reference to bypass an admission error.
This is a caller declaration, not a machine extraction receipt or verification
that the field exists. It proves neither reachability, accepted request shape,
authentication nor testing. Metadata grants no bytes, replay or evidence rights.

`source_ref`, `baseline_request_ref` and `auth_context_ref` keep their separate
request-context contracts; the GET document capture is not POST request context.
Documented inputs do not require request captures. Keep all documented endpoints
in Markdown, including operations without inputs and unknown reachability/auth.
There is no public `record_endpoint`: do not manufacture dummy inputs or claim
structured endpoint/provenance rows that were not admitted. In Direct mode,
retain attribution in the inventory without whole-target-only actions.

When `source_ref` is an HTTP observation used as request context, take method,
normalized origin and path from that checked source; they must match the input.
For example, a `/robots.txt` observation is not request context for an API path
listed in its body. OpenAPI, JavaScript and documentation can establish inputs
without `source_ref`; use document attribution, not an unrelated HTTP reference.
Keep a concrete path unless documentation or compatible observed paths establish
a template. Never remove source_ref on retry to turn a concrete capture into
wildcard/template authority. An unexpected path does not prove an endpoint works, and HTTP
500 alone does not prove it absent. Do not silently change `product` to
`products`. If an input is wrong, use the existing disposition/correction and
replacement flow with the actual evidence; never rewrite history or fake a ref.

For a selected source, use `set_source_disposition` with its real
`discovery_source_id` and `retained_ref`. Mark `processed` only after the
complete visible source has actually been reviewed; unsupported or dynamic JS
is not `not_applicable` or proof of zero operations. Use `partial` or
`blocked` with `source_reason` and `source_limitations` for missing/truncated,
dynamic, inaccessible or unsupported portions. Only acknowledge an actual
bounded stop with `acknowledge_bounded_stop=true`, `source_disposition="partial"`,
a reason, limitations and `source_bounds` containing the real limits applied
(for example `max_bytes` or `max_operations`); never invent bounds to close a
source. Selected unresolved sources still block completion. Source disposition is
not `complete_skill`: satisfy the current frontier, coverage and artifact
gates in step 7 without claiming unperformed work as `performed`. On Continue,
preserve historical extraction IDs, provenance, content identity and bounds;
continue selected unresolved reviews with readable material or an honest
limitation. Persisted metadata never restores read or execution authority.

If a GraphQL endpoint is identified, record:

- endpoint path;
- whether it accepts the expected HTTP method;
- whether a minimal introspection check is explicitly justified by the
  enumeration objective.

A minimal check may be used only to determine whether introspection is
enabled:

```json
{
  "tool": "http",
  "arguments": {
    "method": "POST",
    "url": "/graphql",
    "phase": "recon",
    "max_response_bytes": 8192,
    "headers": {
      "Content-Type": "application/json"
    },
    "body": "{\"query\":\"{__schema{types{name}}}\"}"
  }
}
```

Recording that introspection succeeded or is disabled is still enumeration.
Do not retrieve the full schema, walk the complete type graph, fuzz queries,
or attempt exploitation here. Those tasks belong to web-input-analysis or a
vulnerability-specific skill when justified.

## 5. Enumerate static resources and JavaScript

Collect JavaScript and static resources referenced by pages already fetched.
Extract route/API clues that the application itself exposes.
The src value may be an absolute URL, root-relative path, or relative path,
so normalize it against the referencing page URL before requesting.

Resolve relative sources against the referencing page URL, including its
subpath. For example, if a retained page actually references the same-origin
`/assets/app.js`, fetch that resource once:

```json
{
  "tool": "http",
  "arguments": {
    "method": "GET",
    "url": "/assets/app.js",
    "phase": "recon",
    "max_response_bytes": 8192
  }
}
```

Inspect bounded retained content for fetch/XHR/axios calls, API base URLs
and router definitions. Keep surrounding call-site evidence; a path string
alone is insufficient. Apply the large-response strategy if content is cut.

Skip JavaScript or other resources that resolve to clearly unauthorized
cross-origin domains.
Keep the source bundle and call-site evidence with each clue, then classify it as a client
route, a backend endpoint reference, or unknown. Do not deobfuscate or
reverse-engineer bundles, and do not treat every `/...` string as an API.
This step extracts route and endpoint strings already known by the frontend.
Treat them as clues; a string alone does not establish a backend endpoint.

## 5b. Calibrate ambiguous responses and group route shapes

When a guessed path or content-discovery hit returns `200`, compare it with a
small number of nonexistent same-origin paths. Use a fresh random path and
compare content type, normalized body hash or length, and redirect behavior.
Matching an SPA shell or wildcard response does not make a backend endpoint
valid. The bounded `content_discovery` tool already performs this calibration;
do not repeat it manually when its result is definitive.

Group REST identifiers as `/users/{id}` only after at least two observed paths
with different values share the same method, surrounding route shape, and
response/source pattern. Preserve the concrete paths as examples. Do not
replace every numeric or UUID-like segment automatically; IDs can select
semantically different routes or versions.

## 6. Focused content discovery (optional, bounded)

Use this step only when steps 2–5 leave clear discovery gaps, such as an
administrative path referenced by the application but not directly reachable,
or an application whose routes cannot be mapped from passive sources.

This is still enumeration, not vulnerability testing. Requests remain GET-only
and target paths on the active origin. Call `content_discovery` with `mode="auto"`
when a bounded discovery pass is justified. The runtime uses a curated wordlist,
checks two independent random nonexistent paths and compares modest normalized
response fingerprints to identify wildcard/SPA responses, does not
follow redirects, and records observations directly from native HTTP. The tool's hard
limits are 1,000 total requests, 10 requests/second, and 120 seconds; use a
smaller budget when sufficient. It does not recurse or accept raw scanner flags.

`content_discovery` uses native HTTP.
Reuse suitable native discovery observations before another pass. A failed or
partial pass retains its coverage limitations. Source paths/statuses alone do
not establish input schemas, reachability of documented operations or findings.
If coverage is already sufficient, record a `skipped` or `not_applicable` reason
instead of repeating discovery. Stop when requests stop producing useful routes.

If enumeration begins to resemble testing for a particular vulnerability
class rather than discovering paths or resources, stop and hand off to the
next phase.

## 7. Build the normalized inventory

Write the inventory to:

`artifacts/web-enumeration/<target>/inventory.md`

using the same target identifier defined in `recon/SKILL.md`.
Record one endpoint or route per entry. Prefer a consistent Markdown format:

After writing the inventory, call `workflow(action="complete_skill",
skill_name="web-enumeration",
artifact_ref="artifacts/web-enumeration/<target>/inventory.md",
current_phase="analysis")`; runtime rejects completion when the canonical
artifact is absent, empty, or a different path is supplied. This marks the
bounded inventory pass complete; newly discovered routes may still justify
another focused pass.

For whole-target work, inspect coverage and account for `html_navigation`,
`standard_metadata`, `api_documentation`, `javascript_endpoint_extraction`,
`browser_burp_capture`, and `active_content_discovery` before completion.
`performed` is reserved for machine-observed execution; never self-claim it
through `record_phase_coverage`. Native `http` records `html_navigation` only
when its captured successful HTML contains parsed link, script, or form
references. A truncated prefix without those references does not attest it.
`content_discovery` records `active_content_discovery` after execution.

For reviewed work without a matching adapter, use
`workflow(action="record_phase_coverage", phase="enumeration",
coverage_dimension=..., coverage_status="observed", coverage_reason=...)` with
its source/artifact and missing attestation limitation. `observed` means
unattested review, not machine-attested execution. Never use `skipped` to
simulate performed work or work around missing attestation. Use `skipped` only
for genuinely omitted work and `not_applicable` only for a dimension that
truly does not apply, each with a short valid reason. Do not overwrite runtime
`performed` records. Retry failed/cancelled dimensions or explain an actual
skip before completion; a missing observation never implies `performed`.

Reconcile the inventory with the input records already committed incrementally.
Do not re-record unchanged inputs or wait until this step to record them.
Record every actually known request field separately, including password fields
and secondary fields recovered at a visible JS call site; keep field names and
redact secret values. Reuse existing input identities and provenance. A path
name, GET collection or general application knowledge supplies no POST body
schema. Check missing fields, speculative fields, concrete/template identities
and attribution against sources actually read; fields nested in a sample do
not replace separate records. Compare structured inputs/endpoints/provenance
with readable retained sources before closing; manual Markdown inventory entries are
not automatically synchronized. Phase completion checks the workflow contract,
not semantic completeness of Markdown. State any remaining reconciliation gap.

`Unexpected path` does not establish a handler, method or body schema. A 401
alone does not establish a missing-session prerequisite: invalid credentials,
missing session and format validation are distinct observations. Record only
the observed response and verified prerequisite. API documentation not observed
is not proof that documentation does not exist. Keep `source_reason` within
240 characters; do not truncate an explanation silently or invent a disposition.

### GET /search

- route_type: backend_endpoint
- parameter: `q`
- location: query
- content_type: -
- auth: public
- source: application JS (`main.js`)
- provenance: reachable; same-origin response observed
- observed_response: `200`, HTML page with results
- notes: parameter observed in application flow

### POST /api/orders

- route_type: backend_endpoint
- parameter: `items`, `address`
- location: body (JSON)
- content_type: application/json
- sample_payload: `{"items":[{"productId":"{id}","quantity":"{number}"}],"address":"{INJECTION_POINT}"}`
- auth: session cookie required
- source: form action + `swagger.json`
- provenance: observed from specification; not requested, so reachability is unknown
- observed_response: not probed
- notes: request not submitted during enumeration; no cookie value stored

Each entry should record only observed facts, such as:

- method;
- path;
- parameter;
- parameter location;
- content type;
- authentication state;
- source;
- observed response;
- notes.

Do not add fields such as:
- suspected_vulnerability;
- vulnerability_class;
- exploitability;
- severity.

Classification and vulnerability assessment are outside this skill.

## 8. Handoff to web-input-analysis

When the inventory is stable, add a short summary at the beginning containing:

- total routes/endpoints found;
- sources used (application links, forms, JS, API docs, crawl, focused discovery);
- notable API surfaces such as Swagger/OpenAPI or GraphQL;
- endpoints referenced but not currently reachable;
- recommendation to proceed to web-input-analysis.

Do not select the "most interesting" parameters yourself and do not recommend
a vulnerability class for a specific endpoint.
web-input-analysis must perform that classification from the inventory.

The normal flow is:

```
recon
  ↓
web-enumeration
  ↓
web-input-analysis
  ↓
vulnerability-specific skill
```

### Stop conditions

Stop enumeration when:

- known routes and resources from application links, documentation, and JS have been collected;
- forms and parameter-bearing endpoints are inventoried;
- API entry points are identified;
- focused content discovery no longer produces useful new routes;
- further enumeration would become high-volume without a clear objective.

Do not escalate into full crawling, large wordlist sweeps across multiple
hosts, GraphQL schema fuzzing, or payload-based probing. Those activities
belong to web-input-analysis or a vulnerability-specific skill and should
only be performed when justified by the testing plan and authorized scope.
