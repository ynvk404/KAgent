# Documentation bindings and selected sources

Read this only for the selected documentation/source question. It supplements
SKILL.md; it does not require following other source branches or grant rights.

## Inline definitions and API bases

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
never invent missing operations or request fields.
Treat familiar product endpoints from prior knowledge as hypotheses for bounded
in-scope verification, never as operations observed in this specification.
Read applicable document `security` and operation overrides, including
`security: []`, alongside `components.securitySchemes`. Bearer/JWT declarations describe documented
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

Copy the actual visible binding into document_location. `options.swaggerDoc`
is not `spec.swaggerDoc`; do not invent a wrapper from prose. A locator is a
caller declaration, not verified extraction. Count distinct paths/methods in
the definition actually read; schema objects and probe URLs are not operations.

## Selected-source disposition

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
