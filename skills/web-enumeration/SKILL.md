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
requires:
  - recon
allowed-tools:
  - shell
  - http
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

Default to `curl` and the built-in `http` tool. Do not pull in specialized
scanners such as `ffuf`, `gobuster`, `dirsearch`, unless
the user explicitly asks for them, or focused discovery in step 6 has already
been tried and clearly justifies broader coverage.

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

## 3. Enumerate parameters and forms

For each relevant HTML page already collected, extract form structure:

```sh
curl -ksS --max-time 8 "$TARGET/login" \
  | grep -oE '<(form|input|select|textarea)[^>]*>'
```

For each form, record:

- HTTP method;
- action URL;
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

If a Swagger/OpenAPI document is found, parse documented routes, methods, and
parameters directly:

```sh
curl -ksS --max-time 8 "$TARGET/swagger.json" \
  | jq -r '.paths | keys[]' 2>/dev/null
```

Use the actual discovered specification path when it is not `/swagger.json`.

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
This step extracts route and endpoint strings already known by the frontend.
Do not deobfuscate or reverse-engineer bundles.

## 6. Focused content discovery (optional, bounded)

Use this step only when steps 2–5 leave clear discovery gaps, such as an
administrative path referenced by the application but not directly reachable,
or an application whose routes cannot be mapped from passive sources.

This is still enumeration, not vulnerability testing. Requests must remain
plain GET requests against paths.
Escalate gradually and stay on one host at a time.

First use a small set of high-value guesses:

```sh
TARGET="http://localhost:3000"

for p in /admin /api /health /status /.env /config; do
  code=$(curl -ksS \
    -o /dev/null \
    -w "%{http_code}" \
    --max-time 5 \
    "$TARGET$p")

  echo "$code $p"
done
```

Only if the user has explicitly confirmed that broader discovery is wanted,
use a small wordlist against a single scoped host:

```sh
HOST="app.example.com"  # replace with the real scoped host
WORDLIST=/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt

while read -r w; do
  code=$(curl -ksS \
    -o /dev/null \
    -w "%{http_code}" \
    --max-time 5 \
    "https://$HOST/$w")

  case "$code" in
    200|204|301|302|401|403)
      echo "$code /$w"
      ;;
  esac
done < "$WORDLIST"
```

Do not escalate to ffuf, gobuster, larger wordlists, or multiple hosts
without explicit authorization. Stop when additional requests stop producing
useful new routes.

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
current_phase="analysis")`. This marks the bounded inventory pass complete;
newly discovered routes may still justify another focused pass.

### GET /search

- parameter: `q`
- location: query
- content_type: -
- auth: public
- source: application JS (`main.js`)
- observed_response: `200`, HTML page with results
- notes: parameter observed in application flow

### POST /api/orders

- parameter: `items`, `address`
- location: body (JSON)
- content_type: application/json
- auth: session cookie required
- source: form action + `swagger.json`
- observed_response: `201` on documented valid request
- notes: request not submitted during enumeration

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
