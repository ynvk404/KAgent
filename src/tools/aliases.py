TOOL_NAME_TO_CANONICAL = {
    "shell": "shell",
    "bash": "shell",
    "BashTool": "shell",
    "file_read": "file_read",
    "FileReadTool": "file_read",
    "file_write": "file_write",
    "FileWriteTool": "file_write",
    "file_edit": "file_edit",
    "FileEditTool": "file_edit",
    "glob": "GlobTool",
    "GlobTool": "GlobTool",
    "grep": "GrepTool",
    "GrepTool": "GrepTool",
    "ask": "ask_user",
    "ask_user": "ask_user",
}

def canonical_tool_name(name: str) -> str:
    return TOOL_NAME_TO_CANONICAL.get(
        name,
        name
    )

KNOWN_TOOL_NAMES = {
    "shell",
    "bash",
    "BashTool",
    "file_read",
    "FileReadTool",
    "file_write",
    "FileWriteTool",
    "file_edit",
    "FileEditTool",
    "glob",
    "GlobTool",
    "grep",
    "GrepTool",
    "http",
    "web_fetch",
    "web_search",
    "ask",
    "ask_user",
    "confirm_finding",
    "load_skill",
    "read_payloads",
    "read_skill_file",
    "coverage",
}