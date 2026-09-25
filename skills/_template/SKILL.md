---
name: my-skill
description: One line describing what this playbook does and when it applies. Max 1024 chars.
stage: validation
triggers:
  strong:
    - specific workflow phrase
  weak:
    - supporting signal
candidate-classes:
  - my-skill
requires: []
allowed-tools:
  - http
  - shell
  - file_write
---

# my-skill playbook

State the goal in one or two sentences — what the operator is trying to
achieve — and the scope rules (authorized targets only).

## 1. First step

Concrete, copy-pasteable commands. Default to curl + the `http` tool; only
reach for specialised scanners when the user asks.

```sh
curl -ksS "https://TARGET/..."
```

Reference bundled files (e.g. a wordlist under `payloads/`) with
`read_payloads(skill="my-skill", file="list.txt")`, or shell scripts via the
`${SKILL_DIR}` placeholder:

```sh
${SKILL_DIR}/scripts/check.sh https://TARGET
```

## 2. Next step

...

## Reporting

Describe what the evidence demonstrates in `observed_impact`; state untested
consequences conditionally in `potential_impact`. Call `confirm_finding` only
for a workflow Candidate whose latest validation is confirmed and whose
registered evidence is valid.
