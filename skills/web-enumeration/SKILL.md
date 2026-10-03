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

You have been handed a target that `recon` has already classified and shown
to be reachable. This phase answers "what does this application expose that
could be tested?" It does not decide which exposed item is vulnerable and
does not attempt vulnerability testing. Those tasks belong to
`web-input-analysis` and the vulnerability-specific skills.

**Objective:** map the web application's reachable attack surface — routes,
endpoints, parameters, forms, API surfaces, and relevant static/JS resources
— without attempting vulnerability exploitation or drawing vulnerability-
class conclusions.

Prefer the built-in `http` tool with `phase: recon` for known-source
enumeration. Use `curl` only when the native tool cannot express a necessary
request detail; shell requests do not enforce target-origin scope.
Use `content_discovery` only when steps 2–5 leave a concrete path-coverage gap.
Minimal profile uses native HTTP; full profile may select installed ffuf through
the semantic tool. Discovery stays on the active origin, is bounded, and requires
permission. Do not run generic-shell `ffuf`, `gobuster`, or `dirsearch`
automatically.

Execution rule: substitute the real target into commands before running them.
Never write literal placeholders such as `<TARGET>`, `<HOST>`, or `<endpoint>`
to files. If the target or scope is unclear, ask once before running commands.

## Target identifier

`<target>` below always refers to the identifier derived by the convention
defined in `recon/SKILL.md` ("Target identifier convention"). Reuse that
identifier exactly — do not re-derive it differently here, and do not invent
a different naming scheme for this skill's output paths.

## Preconditions

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
method/endpoint/parameter/location/type combination; `content_type` and
`sample_payload` are optional and do not change the input identity. Store a
small body skeleton, not raw traffic: retain the structure and replace values
with inert examples or `{INJECTION_POINT}`. Omit passwords, tokens, cookies,
PII, and unrelated fields. Record query, body, path, header, and cookie inputs
that were actually observed. The runtime assigns the active objective and
target origin and deduplicates semantic duplicates.

Keep these inputs pending for `web-input-analysis`. Do not call
`record_candidate`, assign a vulnerability class, or mark an input analyzed
in enumeration. Input recording does not complete the phase: write the
inventory and account for coverage before `complete_skill`.

## Large responses: bounded extraction, then move on

A response truncation marker or context-guard omission is a strategy signal.
Do not repeatedly fetch the same large resource, increase `max_response_bytes`,
or add empty queries/cache-busters to obtain the whole blob. Check status and
Content-Type first: HTML at a guessed Swagger URL is not a JSON specification.
Use already visible input/schema/link clues and record them immediately.

Prefer searching/grepping a previously retained local artifact. If the needed
information lies outside the retained prefix and the native tool cannot
extract it, the allowed `shell` tool may perform at most one targeted
extraction attempt per resource. Explain the exact purpose (e.g. form names,
same-origin directory anchors, or one documented operation). Use the exact
active scheme/host/effective port, no redirect following, one GET, a timeout
of at most 8 seconds, and a fixed download bound of at most 64 KiB (for example
curl `--max-time 8 --max-filesize 65536`). Bound parsing to that prefix and
output to at most 40 matches and 4,000 characters. Extract only the needed
structure; never print or persist raw credentials or complete traffic.
Do not run a recursive loop, arbitrary URL batch, or generic shell scanner.
Shell approval does not authorize an off-origin URL.

If that bounded attempt fails, returns a wildcard shell, or yields no useful
new structure, record the remaining source limitation in the inventory and
move to other known inputs. Do not raise the bound or restart retrieval.
Use `content_discovery` only for an actual path gap, not to download a blob.
Partial extraction is sufficient for a bounded inventory; do not make complete
large-resource ingestion a prerequisite for handoff. Once the known input
surface and coverage are accounted for, write the inventory and transition to
`web-input-analysis`, retaining unresolved source limitations.

## 1. Build the target baseline

Reuse `artifacts/recon/<target>/summary.md` when it exists — do not repeat
reachability or fingerprinting work `recon` already did. Before re-probing
anything, check whether `recon`'s summary already recorded a definitive
result for it (e.g. `/robots.txt` status, `/graphql` presence); only
re-probe if that result was inconclusive or missing.

If recon output is unavailable, perform one lightweight request:

```sh
TARGET="http://localhost:3000"  # replace with the real target

curl -ksS \
  -o /tmp/body \
  -w '%{http_code}\t%{url_effective}\n' \
  --max-time 8 \
  "$TARGET/"
```

Record the API style only when it is already apparent from recon or this
single request (for example REST, GraphQL, or server-rendered HTML). This
observation only determines which enumeration steps are relevant.

## 2. Enumerate routes and endpoints from known sources

Prefer routes the application already exposes before guessing paths.
Check high-signal discovery files first — skip any of these already recorded
with a definitive result in `artifacts/recon/<target>/summary.md`:

```sh
TARGET="http://localhost:3000"  # replace with the real target

curl -ksS --max-time 5 "$TARGET/robots.txt"
curl -ksS --max-time 5 "$TARGET/sitemap.xml"
curl -ksS --max-time 5 "$TARGET/.well-known/security.txt"
```

Parse the landing page for internal links, form actions, and script sources:

```sh
curl -ksS --max-time 8 "$TARGET/" \
  | grep -oE '(href|src|action)="[^"]+"' \
  | sed -E 's/^(href|src|action)="//; s/"$//' \
  | sort -u
```

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

```sh
curl -ksS --max-time 8 "$TARGET/login" \
  | grep -oE '<(form|input|select|textarea)[^>]*>'
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

```sh
TARGET="http://localhost:3000"

for p in /api /api/v1 /swagger.json /swagger/v1/swagger.json \
         /openapi.json /api-docs /graphql /.well-known/openapi.json; do
  code=$(curl -ksS \
    -o /tmp/api_body \
    -w "%{http_code}" \
    --max-time 5 \
    "$TARGET$p")

  echo "$code $p"
done
```

If a Swagger/OpenAPI document is found, parse documented routes, methods,
parameters, each operation's `requestBody.content` media type/schema, and any
operation-level security requirement. Record their provenance as `observed
from the specification`; do not say they are reachable until requested.

For an API-only target with a useful specification, inventory the documented
surface before considering focused discovery. Do not run a default wordlist
pass while the specification covers the route gap.

```sh
curl -ksS --max-time 8 "$TARGET/swagger.json" \
  | jq -r '.paths | keys[]' 2>/dev/null
```

If a GraphQL endpoint is identified, record:

- endpoint path;
- whether it accepts the expected HTTP method;
- whether a minimal introspection check is explicitly justified by the
  enumeration objective.

A minimal check may be used only to determine whether introspection is
enabled:

```sh
curl -ksS \
  -X POST \
  "$TARGET/graphql" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name}}}"}'
```

Recording that introspection succeeded or is disabled is still enumeration.
Do not retrieve the full schema, walk the complete type graph, fuzz queries,
or attempt exploitation here. Those tasks belong to web-input-analysis or a
vulnerability-specific skill when justified.

## 5. Enumerate static resources and JavaScript

Collect JavaScript and static resources referenced by pages already fetched.
Extract route/API clues that the application itself exposes.
The src value may be an absolute URL, root-relative path, or relative path,
so normalize it before requesting. Note: this resolution assumes the JS was
referenced from a page fetched at the target root; if you later parse pages
under a subpath, resolve relative paths against that page's own URL instead
of `$TARGET`.

```sh
TARGET="http://localhost:3000"  # no trailing slash

resolve_js_url() {
  src="$1"

  case "$src" in
    http://*|https://*)
      printf '%s\n' "$src"
      ;;
    /*)
      printf '%s%s\n' "$TARGET" "$src"
      ;;
    *)
      printf '%s/%s\n' "$TARGET" "$src"
      ;;
  esac
}

grep -oE 'src="[^"]+\.js"' /tmp/body \
  | sed -E 's/^src="//; s/"$//' \
  | while IFS= read -r js; do
      url=$(resolve_js_url "$js")

      case "$url" in
        "$TARGET"/*)
          curl -ksS --max-time 8 "$url" \
            | grep -oE '"/(api|rest)/[A-Za-z0-9/_-]+"' \
            | sort -u
          ;;
      esac
    done
```

Skip JavaScript or other resources that resolve to clearly unauthorized
cross-origin domains.
This step extracts route clues already known by the frontend. Keep the source
bundle and call-site evidence with each clue, then classify it as a client
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
follow redirects, and verifies scanner hits over native HTTP. The tool's hard
limits are 1,000 total requests, 10 requests/second, and 120 seconds; use a
smaller budget when sufficient. It does not recurse or accept raw scanner flags.

Minimal profile uses native HTTP. In full profile, runtime may select installed
ffuf only when workflow state confirms this remaining coverage gap; a model
argument cannot force the scanner. If coverage is already sufficient, record a `skipped`
or `not_applicable` reason instead of repeating the pass. Stop when additional
requests stop producing useful new routes.

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
