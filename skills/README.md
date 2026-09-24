# Skills

Skills are pre-authored playbooks the agent loads on demand. The format
follows the **Agent Skills** convention: a directory containing a `SKILL.md`
file with YAML frontmatter and a Markdown body.

```
skills/
  sql-injection/
    SKILL.md
    payloads.txt
```

## SKILL.md frontmatter

| Field | Required | Notes |
| --- | --- | --- |
| `name` | yes | Lowercase-kebab (`[a-z0-9-]`), ≤64 chars. Should match the directory name. |
| `description` | yes | ≤1024 chars. Human/model-facing summary shown before the body is loaded. |
| `stage` | no | Organizational signal: `reconnaissance`, `enumeration`, `analysis`, `validation`, or `reporting`. Does not impose a rigid workflow. |
| `triggers` | no | `strong` and `weak` phrase lists used by the deterministic planner. Keep generic words out of `strong`. |
| `candidate-classes` | no | Canonical lowercase-kebab vulnerability classes handled by the skill. Common aliases such as `sqli`, `xss`, `idor`, and `bola` are normalized. |
| `requires` | no | Other skill names that provide useful prior context. These are soft ranking signals, not mandatory dependencies. |
| `allowed-tools` | yes | Declared capability list for permission-requiring tools (e.g. `http`, `shell`, `file_write`). An empty list is unrestricted. Legacy alias: `tools`. |
| `disable-model-invocation` | no | `true` = user-only: hidden from the model, invoked only via the `/<name>` slash command. |

Everything after the frontmatter is the playbook body, delivered to the
model verbatim when it calls `load_skill`. `${SKILL_DIR}` in the body is
replaced with the skill's absolute directory path.

Automatic selection is metadata-driven: discovery parses and registers the
fields above, then the planner ranks enabled/model-invokable skills using
explicit names, candidate classes, triggers, stage, and available prerequisite
context. Detailed testing methodology remains in the Markdown body.

At runtime, `allowed-tools` is checked only for tools that require permission.
When no skill is active, it does not restrict tools. Multiple active skills
combine their declared capabilities. Read-only and workflow meta tools remain
available independently; the Tool Registry still applies each tool's own
argument-aware permission checks. This is a capability hint and gate for
permission-requiring tools, not a sandbox for arbitrary shell commands.

For HTTP requests, prefer the built-in `http` tool when it can express the
request: it validates the allowed origin and private-host rules before
execution. `shell`/`curl` remains available for workflows that need it, but
its permission gate reviews the command rather than enforcing HTTP origins
inside a general shell command. Do not treat permission for one curl command
as scope for a different destination.

## Validation evidence and findings

For a confirmed result, first save a small redacted proof artifact in the
project. Call `workflow(record_evidence)` with its Candidate ID and path, then
use the returned `ev_...` ID in `workflow(record_result).evidence_refs`.
The workflow records the artifact's digest and checks that it still exists
when a linked finding is created. A result with `coverage_sync: pending` needs
`workflow(sync_coverage)` before it is finding-eligible. Only
`confirm_finding` writes an official report under `findings/`; skill
`results.md` files remain supporting validation artifacts.

These are structural checks. The validator playbook and model still judge
whether the observed proof is sufficient for its vulnerability class.

## Where skills load from

Discovered automatically, in increasing precedence (later overrides earlier
on a name collision):

1. this built-in `skills/` directory
2. `./.kagent/skills/` (project-local — scoped to the repo)
3. `~/.kagent/builtin-skills/` (installer-managed shipped skills)
4. `~/.kagent/skills/` (personal)
5. any dirs passed via `--skills <dir>` or the `skills_dirs` config

Use `~/.kagent/skills/` for personal skills you want available
everywhere, or the project-local `./.kagent/skills/` for skills
scoped to a single repo.

Just drop a `<name>/SKILL.md` into one of these — no config needed. Skills
**hot-reload** on save. Directories starting with `.` or `_` are ignored
(so `_template/` is not loaded as a skill).

## Creating a skill

- **Scaffold:** run `/skills new <name>` in the TUI — it writes a templated
  `./.kagent/skills/<name>/SKILL.md` and loads it immediately.
- **By hand:** copy [`_template/SKILL.md`](_template/SKILL.md) into
  `<name>/SKILL.md` and edit.

## Managing skills

- `/skills` — interactive enable/disable picker.
- `/skills enable|disable <name>` — toggle from the prompt.
- `/<name>` — invoke a skill explicitly for your next turn.

Shipped skill handoffs, help examples, and payload references are validated
by `tests/skills/test_conformance.py`, so stale runtime references fail CI.
