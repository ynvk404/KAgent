---
name: ssti
description: >
  Detect and validate suspected Server-Side Template Injection by
  fingerprinting the template engine, confirming expression evaluation
  beyond simple arithmetic, and — only with explicit user authorization
  after SSTI is confirmed — validating impact through a minimal,
  engine-specific execution or sensitive-read probe. Use after
  web-input-analysis when user input appears to be reflected through a
  template context, or when an expression like {{7*7}} evaluates to 49.
stage: validation
triggers:
  strong:
    - ssti
    - server side template injection
    - template injection
    - template engine injection
  weak:
    - jinja2
    - twig template
    - velocity template
    - freemarker
    - smarty template
    - erb template
    - template engine
    - template expression
    - expression evaluation
candidate-classes:
  - ssti
requires:
  - web-input-analysis
allowed-tools:
  - http
  - shell
  - read_payloads
  - file_write
  - ask_user
  - confirm_finding
  - workflow
---

# SSTI playbook

## Structured workflow contract

Consume a matching Candidate with `workflow(action="start_validation",
candidate_id="...")`. A concrete direct request may be validated immediately;
record its supplied details for result linkage without requiring prior stages. Finish a
meaningful attempt with `workflow(action="record_result", ...)`, referencing
stored evidence. An ungranted impact probe is `authorization-required`, not a
confirmed impact result. Only a reproducible `confirmed` result may call
`confirm_finding` with the Candidate ID.

This skill covers three phases in one workflow: detection, validation,
and optional impact. Phase 1 and Phase 2 run as part of normal SSTI
testing. Phase 3 (impact) is optional and gated — it does not run
automatically, even after SSTI is confirmed.

```
Phase 1: Detection / Fingerprint   — automatic, safe, arithmetic-only
        ↓
Phase 2: Validation                 — confirms SSTI (SSTI-1 / SSTI-2)
        ↓
Phase 3: Impact validation (optional) — only with explicit ask_user
                                          authorization, after SSTI-2
```

Execution rule: use the actual target URL, parameter, and injection
context before running probes. Never write literal placeholder values to
files.

## Preconditions

Do not begin SSTI testing until all of the following are known:
1. Target URL
2. The actual parameter / input field that is reflected
3. HTTP method and where the value is supplied (query, body, header, etc.)
4. The context in which the input appears to be rendered (page body,
   email, PDF, log, server-to-server message, etc.) — this determines
   whether confirmation can be observed directly or requires a blind
   channel
5. A user-authorized canary/callback, if blind SSTI confirmation is
   required (i.e. rendered output is never returned to you directly)

If #5 is missing and blind confirmation is necessary, ask_user once for a
canary/callback they control. Do not invent or reuse a canary domain from
memory or prior sessions.

## Scope checkpoint (entering Phase 2)

Before running any probe that goes beyond arithmetic expression
evaluation — object introspection, filter/attribute chains, or anything
that could read files, execute commands, or access environment state —
confirm authorization with `ask_user` if it has not already been
established for this engagement.

Use `ask_user` when:

- the fingerprint step (Phase 1) confirms the parameter is template-
  evaluated, and further probing would move past arithmetic into
  introspection,
- the target is a shared/production-like environment and the impact of
  further probing is unclear,
- blind confirmation requires an external canary not yet authorized.

Do not infer authorization merely because a fingerprint payload succeeded.

## Phase 1: Detection / fingerprint

This step is safe and non-destructive — it only evaluates arithmetic, so
it can run without a scope-checkpoint confirmation.

Use `read_payloads(skill="ssti", file="payloads.txt")` for the canonical
multi-engine probe — use only the `PHASE 1 — FINGERPRINT` section at the
top of that file:

```
${7*7}
{{7*7}}
<%= 7*7 %>
*{7*7}
{{7*'7'}}
```

Cross-reference results:

| Render result | Engine |
|---|---|
| `49` from `{{7*7}}` AND `7777777` from `{{7*'7'}}` | **Jinja2** (Python) |
| `49` from `{{7*7}}` AND `49` from `{{7*'7'}}` | **Twig** (PHP) |
| `49` from `${7*7}` | **Velocity** / **Freemarker** / Mako (probe further) |
| `49` from `<%= 7*7 %>` | **ERB** (Ruby) / EJS (Node) |
| `49` from `*{7*7}` | **Smarty** |
| Output of `{{7*7}}` literally | Not an SSTI primitive — look elsewhere |

Distinguish Velocity from Freemarker using arithmetic and parse behavior only: **Freemarker** chokes on `<#assign>` outside a template block; **Velocity** specifically renders `#set($x=7*7)$x` as `49`. Do not use introspection (e.g. `${"foo".getClass()}`) at this stage — that discriminator belongs to Phase 2, since it inspects an object rather than evaluating arithmetic.

If no probe evaluates, do not conclude that SSTI is absent. Stop this
testing path and report that SSTI could not be confirmed with the
available evidence — the null result may be caused by output escaping, a
non-template rendering path, or a blind context without a matching
canary.

A successful Phase 1 probe establishes **SSTI-1** (signal: template
expression evaluation observed and a likely engine identified) — it does
not by itself establish a confirmed SSTI finding. Additional validation is required in Phase 2 before reporting SSTI-2.

## Phase 2: Validation

Once the engine is fingerprinted, run the scope checkpoint above before
continuing. With authorization, use the minimal probe needed to confirm
evaluation extends beyond arithmetic — not to reach execution.

Examples of minimal, non-destructive confirmation:

- Object/class introspection that returns type information only (e.g.
  `${"foo".getClass()}` on Velocity/Freemarker, which returns `class
  java.lang.String` — useful both to confirm evaluation beyond
  arithmetic and, combined with the Phase 1 parse-behavior result, to
  disambiguate the two engines).
- A benign built-in or filter that returns non-sensitive output.
- An engine-specific expression that demonstrates server-side evaluation
  beyond arithmetic without traversing toward an execution primitive.

Do not attempt to enumerate or walk toward an exec-capable gadget (e.g.
subclass enumeration searching for `subprocess.Popen`) as part of Phase
2 — even without invoking it, that enumeration is already probing toward
execution and belongs to Phase 3.

Do not run engine-specific remote-code-execution payloads (subprocess
invocation, `Runtime.exec`, `system`, `popen`, `execSync`, PHP `exec`
filters, or equivalent) as part of Phase 2. Those are Phase 3 only.

For Jinja2 and Velocity/Freemarker, read_payloads(skill="ssti", file="payloads.txt") provides introspection-only probes for this
phase — use only the `PHASE 2 — VALIDATION` section of that file.
Everything in the `PHASE 3` section below it requires separate Phase 3
authorization; reading further into the file for Phase 2 does not grant
permission to use it.

### Blind SSTI validation

If rendered output is never returned to you directly (email, server-to-
server message, async job, log line), confirm using a side channel:

- a user-authorized DNS or HTTP callback, referenced from the
  Preconditions step,
- timing analysis only as a last resort, and only with a baseline
  comparison to rule out unrelated latency.

Do not perform an OS command execution to trigger the callback. Prefer an
engine built-in (e.g. a template function that performs an HTTP fetch or
DNS resolution as part of normal rendering) where the engine supports
one; if none is available without executing a command, treat this as
SSTI-2 at most and stop — reaching SSTI-3 through a blind channel still
requires Phase 3 authorization.

### Determine the result

Classify the result as one of:

- **SSTI-1** — template-expression evaluation observed and a likely
  engine identified, but additional validation is required before
  reporting a confirmed SSTI finding.
- **SSTI-2** — SSTI conclusively confirmed through non-destructive
  expression evaluation beyond simple arithmetic.
- **SSTI-3** — impact such as command execution or sensitive data access
  conclusively demonstrated through Phase 3. Only reachable via Phase 3.

Do not report SSTI-3 without direct evidence of command output or
sensitive file/data content obtained during Phase 3.

If the available evidence is inconclusive, do not conclude that SSTI is
absent. Report that SSTI could not be confirmed with the available
evidence.

**SSTI-2 is a complete, reportable finding on its own.** Do not treat it
as unfinished work that needs Phase 3 to be "real" — stop here unless the
conditions below are met.

## Phase 3: Impact validation (optional)

Do not enter this phase automatically.

Only proceed when:
1. SSTI has already been confirmed (SSTI-2), and
2. the user explicitly authorizes deeper impact validation via ask_user.

This phase may use engine-specific impact payloads from `payloads.txt`,
including command-execution or a minimal sensitive-read probe. For
Jinja2, `read_payloads(skill="ssti", file="payloads.txt")` provides
these — use the `PHASE 3 — IMPACT` section of that file, which includes
subclass-enumeration-to-`Popen` execution and the `__globals__`
attribute-proxy route via `url_for`/`lipsum`/`cycler`/`request`.

Only retrieve the minimum non-sensitive or minimally sensitive artifact
needed to demonstrate impact (e.g. the output of a harmless command like
`id`, or a single file explicitly relevant to the finding). Do not dump
environment, configuration, or request context broadly — a broad dump
(full config object, full environment, full request context) is not
"minimal impact" even when it technically executes nothing, and it risks
disclosing secrets (e.g. Flask `SECRET_KEY`) far beyond what's needed to
establish the finding.

Stop once the minimum impact necessary to establish the finding is
proven (SSTI-3). Do not continue into unrelated post-exploitation,
credential harvesting, lateral movement, or additional engines' exec
payloads "just in case." Do not chain a disclosed secret (e.g. a leaked
`SECRET_KEY`) into further exploitation (e.g. forging a session) unless
the user separately authorizes that as its own step.

## Reporting

Write a report to `findings/ssti-{sanitized-parameter-or-path}.md`. The filename must be derived from the actual target/parameter and sanitized for filesystem safety: lowercase, with non-alphanumeric characters replaced by `-` — never write a literal placeholder as the filename.

Include:

- the exact input field where the payload landed
- the fingerprint output (`{{7*7}}` → `49` etc.) and inferred engine plus
  version, with reasoning
- the SSTI level reached (1–3) and the exact probe/response evidence for
  it
- a note when evidence is inconclusive
- if Phase 3 was not run: a note that deeper impact validation is
  available but requires explicit authorization

## Confirm an evidence-backed finding

After recording a `confirmed` ValidationResult, call `confirm_finding` with
its `candidate_id` and the required `title`, `severity`, `url`, and `impact`,
plus method, parameter, reproducible request, response excerpt, remediation,
and canonical `vuln_class` when available. Do not call it for any other
structured outcome.
