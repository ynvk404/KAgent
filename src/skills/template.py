from __future__ import annotations


def render_skill_template(name: str) -> str:
    trigger = name.replace("-", " ")
    return (
        "---\n"
        f"name: {name}\n"
        'description: Describe what this playbook does and when it applies. Max 1024 chars.\n'
        "stage: validation\n"
        "triggers:\n"
        "  strong:\n"
        f"    - {trigger}\n"
        "  weak: []\n"
        "candidate-classes:\n"
        f"  - {name}\n"
        "requires: []\n"
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
