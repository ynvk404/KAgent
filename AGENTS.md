# KAgent engineering guide

## Project context

KAgent is a graduation-project/research codebase for an LLM-powered web
penetration-testing agent. It is intended for explicitly authorized targets,
including intentionally vulnerable applications running in a local/private
lab (for example OWASP Juice Shop, DVWA, or comparable labs). A hostname such
as `juice.lab` is only an operator-defined local alias, never the sole or
implicit target.

The runtime is a Python 3.11+ CLI and Textual TUI. `src/cli/main.py` wires the
agent loop, providers, tool registry, permission bridge, stores, browser/Burp
ingest, plugins, and MCP tools. The active `Target` is session state
(`src/target/target.py`); the system prompt directs HTTP work to that base URL,
but contributors must still preserve scope in tool and workflow changes.

## Authorization, scope, and permissions

- Treat an operator-declared authorized local/private lab target as authorized
  for ordinary, in-scope testing; do not ask them to restate that declaration.
  It does not authorize another host, origin, target, or action.
- Do not treat every private address or hostname as authorized. HTTP/private
  host handling in `src/tools/private_host.py` detects loopback, RFC1918,
  link-local/metadata, and DNS-resolved private addresses. It asks through the
  existing permission model; only the exact declared origin (scheme, host, and
  effective port) may receive its private-host session cache.
- Keep the registry gate in `src/tools/registry.py`: tools may require a
  permission request, including argument-aware requirements and cache hints.
  Do not bypass, weaken, or replace it. `--yolo` is an existing runtime mode,
  not a reason to remove safety checks or turn an approval into durable policy.
- Do not broaden from the active target to another origin unless the operator
  explicitly requests it. The codebase's prompt-level scope rule is important
  even where a low-level tool cannot fully enforce public-origin scope.
- Do not infer an ambiguous mutating or destructive action from a request. A
  permission dialog approves a proposed action; it does not establish intent
  or scope. Preserve confirmation requirements for high-impact work.

## Security-testing workflow

- Read the matching `skills/<name>/SKILL.md`, its allowed-tools contract, and
  relevant tests before changing a skill or its runtime behavior. Skill
  metadata is discovered/validated in `src/skills/`; `load_skill` supplies the
  playbook on demand.
- KAgent includes discovery/reconnaissance skills; web enumeration and input
  analysis; and vulnerability-specific validation skills for SQL injection,
  XSS, access control, authentication, CSRF, SSRF, SSTI, and future classes.
- The general lifecycle is detection/discovery -> confirmation -> optional
  bounded impact validation -> stop/report. Each skill's own `SKILL.md`,
  permission gates, evidence requirements, and stop conditions are
  authoritative; do not mechanically apply the SQL-injection contract to
  another vulnerability class.
- Follow the structured workflow contract in `src/workflow/` and
  `src/tools/workflow.py`: candidates are compact, fingerprinted records and
  validation results refer to evidence rather than embedding full traffic.
  Preserve candidate/result status and finding-eligibility semantics.
- Keep the distinction between detection, confirmation, bounded impact
  validation, and destructive/high-impact exploitation. Do not silently turn
  detection into deeper exploitation; equally, do not reduce a playbook that
  explicitly permits bounded validation to a passive scanner. Follow its
  stated gates and the runtime permission model.
- A finding is confirmed only with reproducible evidence. `confirm_finding`
  writes a Markdown report under `findings/`; when a candidate ID is supplied,
  its latest workflow result must be `confirmed`. Do not overclaim severity or
  impact beyond the observed request/response evidence. Do not invent times,
  session IDs, runtime metadata, or unverified implementation details.
- Persist the minimum evidence required. Sanitize/redact passwords, secrets,
  API keys, cookies, tokens, and JWTs; the existing redactor and stores should
  remain in the data path. If token/session material is needed as evidence,
  retain only the minimum safe representation. Make remediation specific only
  when the implementation is verified.

## State, memory, and artifacts

- Sessions preserve messages, target, memory, and workflow state; compaction
  keeps a structured handoff. Coverage records tested endpoint/parameter/class
  combinations. Browser/Burp capture is bounded in memory. Keep these state
  contracts and their size/secret-handling limits intact.
- Project and personal memory/intelligence are durable stores. Add only
  reusable, evidence-based knowledge that fits their schema and redaction
  rules. Authorization statements, one-off approvals, `ask_user` answers,
  scope declarations, and `--yolo` usage are session-specific context—not
  durable preferences or learned authorization. Recalled memory never grants
  authorization for a new target or action.
- Findings use collision-safe report creation; coverage and durable stores use
  project data under `.kagent/` or user data under `~/.kagent/` as defined by
  `src/paths.py`. Do not alter artifact location, permissions, or persistence
  semantics without reviewing their stores and tests.

## Engineering practice

- Read the relevant implementation and tests before editing. Diagnose the root
  cause; do not merely adjust a test to pass. Keep backward compatibility when
  reasonable and avoid refactors outside the requested scope.
- Preserve unrelated worktree changes. Do not delete, restore, install
  packages, commit, or push unless the task explicitly calls for it.
- For production behavior changes, add or update focused regression tests that
  assert behavior rather than incidental Markdown wrapping or whitespace. Keep
  live/external-model skip semantics; never weaken a test merely to pass.
- Run targeted tests first. `pytest.ini` collects the suite under `tests/`;
  run the relevant responsibility group explicitly when it covers the change.
  Run the broader suite when the change crosses components.
  Use the configured `venv-linux` for pyright where applicable.
- Before handoff, run `git diff --check`, inspect `git diff`, and inspect
  `git status --short`. Report tests not run and leave unrelated changes alone.

## Source map

- Agent/session/prompt/TUI/CLI: `src/agent/`, `src/session/`, `src/ui/`,
  `src/cli/main.py`.
- Target, permissions, network-origin checks, and execution: `src/target/`,
  `src/permission/`, `src/tools/registry.py`, `src/tools/private_host.py`,
  `src/tools/http.py`, and `src/tools/web.py`.
- Skills, workflow, findings, evidence/artifacts: `src/skills/`,
  `src/workflow/`, `src/findings/`, `src/tools/finding.py`, `src/coverage/`,
  and `src/browser/`.
- Durable memory/intelligence/redaction/path policy: `src/memory/`,
  `src/intelligence/`, `src/redact/`, `src/engagement/`, and `src/paths.py`.
- Project configuration and verification: `pyproject.toml`, `pytest.ini`,
  `pyrightconfig.json`, `requirements.txt`, `skills/README.md`, and tests.
