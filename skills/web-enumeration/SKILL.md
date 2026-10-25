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
→ check canonical inputs → inventory and coverage → `complete_skill` →
Input Analysis. Native HTTP obtains a new source only when needed; Content
Discovery fills a concrete path gap. In Direct mode, discover only what the
specific request needs; do not force all phases or whole-target source actions.

Prefer the built-in `http` tool with `phase: recon` for known-source
enumeration. Use `curl` only when the native tool cannot express a necessary
request detail; shell requests do not enforce target-origin scope.
For a necessary new source via shell, keep the exact active origin, one GET,
no redirects, timeout ≤8 seconds and download cap ≤64 KiB. Shell approval
does not authorize another origin or a replacement fetch for omitted content.
Shell HTTP is not a truncation fallback. A normal GET is already expressible
by native HTTP; a local output filename or desire to parse a whole bundle does
not justify another download through shell. Describe the action actually taken,
not a new fetch as processing a retained response.
Use `content_discovery` only when steps 2–5 leave a concrete path-coverage gap.
`content_discovery` uses native HTTP through the runtime permission gate.
Discovery stays on the active origin, is bounded, and requires
permission. Do not run generic-shell `ffuf`, `gobuster`, or `dirsearch`
automatically.

External scanner integration is unavailable; do not substitute shell scan loops.

Execution rule: substitute the real target into commands before running them.
Never write literal placeholders such as `<TARGET>`, `<HOST>`, or `<endpoint>`
to files. If the target or scope is unclear, ask once before running commands.

## Choose the next discovery question

Sections 2–6 are a source menu, not a checklist or required order. Select the
next discovery question from current evidence: what missing method, request
field, media type, API base or access limitation would a source clarify?
Compare expected information gain with request, retained-reading and LLM cost.
Reuse visible evidence first; choose the branch most likely to add useful
request structure. No branch, Swagger document or bundle set is mandatory.

| Signal already observed | Useful branch | Bounded outcome |
|---|---|---|
| HTML navigation/form/action | Extract fields and follow a useful same-origin link | Form/request records, or a specific unreadable portion |
| Captured HTTP traffic | Reuse available request structure | Inputs with checked request provenance; no replay authority inferred |
| API definition/initializer reference | Read visible operations/schema/security | Documented inputs, with unknown reachability/auth preserved |
| SPA scripts, imports or network call sites | Inspect a relevant retained call-site window | Method/field clues; unresolved API-base/config binding stays unknown |
| Concrete route gap with no sufficient exposed source | Optional content_discovery | Calibrated paths, not inferred body schemas |

After a bounded review, ask what new request structure was gained. Switch
branches or hand off when further reading only repeats metadata/vendor text.
Keep valuable unpursued clues and their omission reason; do not declare them
absent. Register evidenced inputs promptly under the structured handoff contract
below, including arrays: they do not require a scalar sink or a vulnerability
hypothesis. Auth requirements belong
in discovery limitations; Input Analysis decides whether a real prerequisite
prevents triage. Do not send a documented create/update operation just to prove
its fields exist or obtain a receipt.

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

For documentation, first read enough of the relevant endpoint, request body and
reachable schema definitions under the existing bounded-reading rules before
declaring an input type. Reuse facts already in context. An unresolved `$ref`
alone does not mean object. If the type remains unknown after reasonable bounded
reading, omit `input_type` when the required request attributes are grounded,
and retain the limitation.

As soon as an endpoint and input are supported by an observed request, form,
API schema, or network call site under this rule, call
`workflow(action="record_input", ...)` promptly. Do not wait for the final
inventory or for an entire Swagger document, directory listing, or bundle.
Reuse sufficiently specific evidence from recon. A route name or a GET error
on a login path does not establish a POST body field: record only the method,
parameter, and location actually observed. Documented inputs may be recorded
without sending the documented operation, including login/order submission;
retain specification attribution and unknown reachability in the inventory.
Record each newly established input once; reuse its returned ID.

For a whole-target objective, record every discovered request input
surface with `workflow(action="record_input", method=..., endpoint=...,
parameter=..., location=..., input_type=..., content_type=...,
sample_payload=...)` when those details are known. Use one compact record per
method/endpoint/parameter/location/type/media combination. `content_type` is
optional, but known media types distinguish input identities; charset and
multipart boundary parameters do not. `sample_payload` does not change identity. Store a
small body skeleton, not raw traffic: keep evidenced field names and structure,
including password/token/cookie fields; redact secret values and PII, using inert
examples or `{INJECTION_POINT}` only where appropriate. Omit unrelated fields;
never store real passwords, tokens or cookies. Record query, body, path, header,
and cookie inputs actually evidenced. `content_type` describes request
Content-Type, never response Content-Type. The runtime assigns the active objective and
target origin and deduplicates semantic duplicates.

Keep these inputs pending for `web-input-analysis`. Do not call
`record_candidate`, assign a vulnerability class, or mark an input analyzed
in enumeration. Input recording does not complete the phase: write the
inventory and account for coverage before `complete_skill`.

## Large responses: bounded reading, then move on

Choose capture bounds for the intended review before the first fetch within HTTP
limits. Do not repeatedly fetch the same large resource, increase caps or use
cache-busters after truncation. HTML at a guessed Swagger URL is not a JSON spec.
Reuse visible content; local artifact searches retain existing read permissions,
at most 40 matches and 4,000 output characters. The raw ObservationStore bytes are not a general discovery reader or an automatic read_tool_result cache.

Retained response completeness, ranges actually read and content still in context
are separate. complete=true does not restore omitted text. Content-Length is not
the number of bytes inspected. list(view="sources") supplies method, document_url,
status/media and retained size; get_source is metadata only. A redirect, Swagger
UI, initializer and JSON definition are different sources. Use known metadata;
list only missing IDs, never guess or convert obs_ to ds_. For pagination copy
next_discovery_cursor into discovery_cursor, never cursor; restart a stale cursor
without it. Do not re-read every observation.

Read only missing retained ranges with read_discovery_source, exact ds_ ID,
start_char and max_chars ≤2,000. Follow next_start_char: metadata shares this
output cap, so max_chars is not the returned body length. Optional find_text
performs one literal lookup within retained text, returning bounded call-site
context, with no HTTP. Prefer a meaningful API/method/field clue over walking
vendor prefixes; a miss proves nothing about uncaptured content. Use the actual
returned range, never claim the whole source was reviewed.

Each read requires current scope, provenance, HTTP capability and permission;
selection grants no access. It reads only the existing ≤64 KiB body and grants
no Candidate/Attempt ownership or terminal evidence. read_http_observation keeps
its validation ownership contract: do not use it for an unowned discovery observation or create a Candidate/validation attempt to gain read rights.
Do not fetch again, increase caps or cache-bust for omitted retained material;
Shell HTTP is not a truncation fallback. If unavailable, evicted, outside limits
or unreadable, retain the limitation and continue known inputs. Do not repeat
an identical rejected read. Swagger is not a prerequisite for Enumeration.
Do not raise the bound or restart retrieval. Content discovery answers a path
gap, not blob retrieval. Partial review is sufficient; hand off inventory and
coverage while retaining unresolved source limitations.

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
{"tool":"http","arguments":{"method":"GET","url":"/","phase":"recon","max_response_bytes":8192}}
```

Record the API style only when it is already apparent from recon or this
single request (for example REST, GraphQL, or server-rendered HTML). This
observation only determines which enumeration steps are relevant.

## 2. Enumerate routes and endpoints from known sources

Prefer routes the application already exposes before guessing paths.
For a navigation/metadata gap, consider relevant high-signal discovery files;
skip those already recorded with a definitive result in `artifacts/recon/<target>/summary.md`:

```json
{"tool":"http","arguments":{"method":"GET","url":"/robots.txt","phase":"recon","max_response_bytes":8192}}
```

```json
{"tool":"http","arguments":{"method":"GET","url":"/sitemap.xml","phase":"recon","max_response_bytes":8192}}
```

```json
{"tool":"http","arguments":{"method":"GET","url":"/.well-known/security.txt","phase":"recon","max_response_bytes":8192}}
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
{"tool":"http","arguments":{"method":"GET","url":"/login","phase":"recon","max_response_bytes":8192}}
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
{"tool":"http","arguments":{"method":"GET","url":"/openapi.json","phase":"recon","max_response_bytes":8192}}
```

If a Swagger/OpenAPI document is found, parse documented routes, methods,
parameters, each operation's `requestBody.content` media type/schema, and any
operation-level security requirement. Record their provenance as `observed
from the specification`; do not say they are reachable until requested.

Read operation keys from the retained `.paths` object and record supported
request shapes incrementally. Reuse the same retained response for parsing;
do not fetch a specification again merely to list its paths.

### Inline OpenAPI in Swagger UI

Inspect retained Swagger UI HTML/initializer before guessing definition URLs.
An inline `spec` can supersede `url`; API `servers` are not definition URLs.
When this branch needs inline binding, relative API-base/server precedence,
security inheritance/overrides, unresolved `$ref` or selected-source dispositions,
read the conditional reference with
`read_skill_file(skill="web-enumeration", path="source-reference.md")`.
It includes literal/intermediate bindings; never execute JavaScript or guess
computed values. Preserve unresolved API-base/auth uncertainty and exact origin.
No definition, authenticated access or whole-document review is implied by 200 HTML.

### Record documentation and retain attribution

There is no automatic HTML/OpenAPI extraction action. Do not execute JavaScript
or register a copied object as a replacement authoritative source. An unselected
pending source is not a mandatory backlog. There is no required select_source →
get_source → processing sequence: select only for deliberate further review,
`get_source` only when exact metadata is missing. Recording an input never
selects or dispositions its source. Use the bounded reader contract above.

For each known request field, use `record_input` incrementally under the
active whole-target objective, reusing returned input IDs. For example, only
if this method/base/path/field is actually documented on the active origin:

```json
{"tool":"workflow","arguments":{"action":"record_input","method":"POST","endpoint":"/service/v4/widgets","parameter":"label","location":"json","input_type":"string","content_type":"application/json","sample_payload":"{\"label\":\"{INJECTION_POINT}\"}"}}
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

Before handoff, check discovered input names and types against canonical state,
reusing information already in context; use `list`/`get_input` only for missing
details. Record newly discovered fields, including arrays; a string containing
JSON remains a string. Preserve unresolved references and incomplete interpretation
as limitations: complete retained bytes or corrected inventory prose alone do not
establish agreement. For an actual discrepancy, use the existing correction/recovery
instructions below.

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
`products`. If an already recorded input is wrong, use the existing
disposition/replacement flow with actual evidence and honest attribution. This is
exceptional recovery: a name/type change has a different canonical identity.
Preserve terminal analyzed/dropped records, Candidate links and provenance;
never rewrite IDs, history or refs.

Selected unresolved sources still block completion. Use set_source_disposition
with actual IDs/retained_ref, source_limitations and real source_bounds; never
invent bounds or claim processed for unread content. The conditional source-reference.md
preserves partial/blocked and acknowledge_bounded_stop contracts.

If a GraphQL endpoint is identified, record:

- endpoint path;
- whether it accepts the expected HTTP method;
- whether a minimal introspection check is explicitly justified by the
  enumeration objective.

A minimal check may be used only to determine whether introspection is
enabled:

```json
{"tool":"http","arguments":{"method":"POST","url":"/graphql","phase":"recon","max_response_bytes":8192,"headers":{"Content-Type":"application/json"},"body":"{\"query\":\"{__schema{types{name}}}\"}"}}
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
{"tool":"http","arguments":{"method":"GET","url":"/assets/app.js","phase":"recon","max_response_bytes":8192}}
```

Inspect bounded retained content for fetch/XHR/axios calls, API base URLs
and router definitions. A vendor prefix does not characterize an entire
bundle. Use a bounded find_text lookup for a visible API/client-method clue
before claiming no application call sites; preserve an unknown API-base binding
or import reference rather than resolving it from product knowledge. Keep surrounding call-site evidence; a path string
alone is insufficient. Apply the large-response strategy if content is cut.
Trace visible method, URL construction, query parameters and field assignments
at a call site, including separate frontend object construction passed to a
service. Record those sourced fields incrementally; if the service's transport
binding or media type is unresolved, retain that limitation instead of guessing
POST or claiming no field-level evidence exists. Appending a guessed parameter
without an error does not establish that the server consumes it.

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

Reconcile each retained discovery row before grouping endpoints. If the output
publishes a `tr_` result_ref, use bounded `read_tool_result` pages under the
producer's current capability to inspect omitted rows; do not rerun discovery.
A completed request count and a truncated output/body are separate facts.
Keep observed JSON, 401/403, handler errors such as 500, and calibrated wildcard
matches distinct. Never label a whole group SPA or unknown just because some
rows were omitted. A 500 response alone establishes neither an expected POST
body nor an authentication requirement. Do not infer body schemas from JSON
response fields or claim unseen contents were reviewed.

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

Count distinct documented method/path operations from the definition, not schema
objects or query variants. A directory-listing title is a listing clue, not an
SPA fallback; wildcard classification needs calibration. Preserve the actual
status for each route rather than grouping handler errors with auth failures.
A manual attribution locator must copy the visible binding/schema path; a valid
source hash does not verify that locator or operation count.

Immediately before `file_write`, reconcile each claim with its source/reference:
effective method/endpoint, HTTP status, response media type, redacted body marker,
capture flags and claim confidence. Observations/documents actually read take
precedence over conflicting LLM summaries. Distinguish direct observation, observed
from specification, inference/hypothesis and unknown in prose, not new Workflow
fields. Status 200, HTML media type, a filename or metadata-only capture does not
prove body review, SPA calibration or operation success. A partial body supports
only its inspected markers; unknown content stays a limitation under the bounded
reading rules. Keep the attributed inventory concise and redacted; no mandatory
per-response artifact or extra ledger.

Write the inventory to:

`artifacts/web-enumeration/<target>/inventory.md`

using the same target identifier defined in `recon/SKILL.md`.
Record one endpoint or route per entry. Prefer a consistent Markdown format:

Before closing Whole-target Enumeration, apply this checkpoint:

- SQLi-only narrows vulnerability class, not endpoint/input discovery. A bounded
  pass can hand off useful inputs without claiming a survey of the whole target.
- Reconcile valuable clues actually seen: Swagger initializer/definition references,
  relevant robots entries, script/module references and visible network call
  sites, API base/schema references. Follow a clue within existing bounds for a
  concrete discovery question, or record its omission reason and specific limitation
  in the inventory. A guessed spec URL returning HTML does not close the documentation
  branch while retained HTML still has an initializer/definition clue. Resolve
  relative references against the document URL; reuse retained content or permitted
  missing-range reads under the bounded-reading rules.
- Account for these clues without selecting every source or reading every link/chunk.
  Known sources sufficient for the next step need no broad scan or endpoint/input
  quota. References alone supply no input fields; commit each evidenced request
  shape incrementally under the structured handoff contract.

Inspect the overall workflow state, reusing it if already visible:

```json
{"tool":"workflow","arguments":{"action":"list"}}
```

Use its `phase_coverage`, `completed_phases` and input records to reconcile
the work below. `view="sources"` pages only discovery metadata; it does not
show phase coverage. Write the bounded inventory from facts actually reviewed,
account for missing coverage with supported review/omission reasons, then call
`complete_skill`. Reading another source does not perform these closing actions.
Coverage skips and truncation limit this pass; completion does not survey the
entire target or require every bundle, endpoint or documented operation to be read
or requested.

After writing the inventory, call `workflow(action="complete_skill",
skill_name="web-enumeration",
artifact_ref="artifacts/web-enumeration/<target>/inventory.md",
current_phase="analysis")`; runtime rejects completion when the canonical
artifact is absent, empty, or a different path is supplied. This marks the
bounded inventory pass complete; newly discovered routes may still justify
another focused pass.

Before whole-target completion, account for html_navigation, standard_metadata,
api_documentation, javascript_endpoint_extraction, browser_burp_capture and
active_content_discovery. `performed` is reserved for machine-observed execution; never self-claim
it through record_phase_coverage or overwrite an adapter receipt. Native HTTP
attests html_navigation only when successful captured HTML contains references,
not that navigation was followed. content_discovery attests its executed pass.

For unattested review, record_phase_coverage with phase="enumeration",
coverage_dimension, coverage_status="observed" and coverage_reason naming the
source and attestation limitation. Never use `skipped` to simulate performed work.
Use skipped only for genuinely omitted work, not_applicable only for real
inapplicability, each with a reason. Retry failed/cancelled dimensions or explain
an actual skip; missing observations never mean performed.

Reconcile each evidenced field with the input records already committed;
do not re-record unchanged inputs. Record fields separately, including password fields
and secondary fields at a visible JS call site: keep names, redact values. Reuse canonical
identities and provenance. Check missing/speculative fields, concrete/template
identities and attribution against sources actually read; fields nested in a
sample do not replace separate records. Manual Markdown entries are not
automatically synchronized. Phase completion checks the workflow contract,
not semantic completeness of Markdown; state reconciliation gaps. Documented or
referenced-only, reachable, authenticated and tested are distinct claims. Even a
successful request you sent does not establish that every submitted field was
consumed. A path name or GET collection supplies no POST body schema.

`Unexpected path` does not establish a handler, method or body schema. A 401
alone does not establish a missing-session prerequisite: invalid credentials,
missing session and format validation are distinct observations. Record only
the observed response and verified prerequisite. API documentation not observed
is not proof that documentation does not exist. Keep `source_reason` within
240 characters; do not truncate an explanation silently or invent a disposition.

### GET /search

`q` (query), backend_endpoint; observed application network call and same-origin
200 HTML results. Keep the actual source and inspected response marker.

### POST /api/orders

Documented JSON `items` array and `address` string; record each field separately.
Request not submitted: reachability and authenticated access unknown. Keep the
specification binding/location and a compact redacted payload skeleton.

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

Derive summary totals from the reconciled entries using an explicit counting
unit (for example method plus endpoint); distinguish templates, concrete probes,
inputs and sources. Keep observed, referenced-only, wildcard and partial groups
consistent with their individual rows. Unknown authentication/method/schema is
a limitation, not a simulated requirement or proof of absence.

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

Stop this bounded pass when:

- useful request fields from the selected sources are inventoried;
- valuable observed clues are followed within bounds or have a specific omission reason;
- API entry points and unresolved API-base/auth limitations are distinguished;
- further work has low expected information gain or would exceed existing bounds;
- canonical input records, inventory, source obligations and coverage agree.

Optional content discovery need not run to establish this stopping condition.
Partial review never means a whole bundle, directory or target was surveyed.

Do not escalate into full crawling, large wordlist sweeps across multiple
hosts, GraphQL schema fuzzing, or payload-based probing. Those activities
belong to web-input-analysis or a vulnerability-specific skill and should
only be performed when justified by the testing plan and authorized scope.
