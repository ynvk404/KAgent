from __future__ import annotations


def render_skill_template(name: str) -> str:
    return (
        "---\n"
        f"name: {name}\n"
        'description: One line on what this playbook does, then a "Use when ..." clause so the agent knows when to load it (e.g. "Use when the target exposes X / you see Y"). Max 1024 chars. This text is the ONLY thing the model sees until it loads the skill, so make the trigger conditions explicit.\n'
        "allowed-tools:\n"
        "  - http\n"
        "  - shell\n"
        "  - file_write\n"
        "---\n\n"
        f"# {name} playbook\n\n"
        "State the goal in one or two sentences — what the operator is trying to\n"
        "achieve, and the scope rules (authorized targets only).\n\n"
        "## 1. First step\n\n"
        "Concrete, copy-pasteable commands. Default to curl + the `http` tool.\n\n"
        "```sh\n"
        'curl -ksS "https://TARGET/..."\n'
        "```\n\n"
        "## 2. Next step\n\n"
        "...\n\n"
        "## Reporting\n\n"
        "What proves the bug, the concrete impact in one sentence, and remediation.\n"
        "When you have a reproduced finding with a real request/response, call\n"
        "`confirm_finding`.\n"
    )