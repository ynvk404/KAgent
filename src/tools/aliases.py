"""
Tool-name equivalence map.

Port từ:
agent/src/tools/aliases.ts

Chức năng:
- Chuẩn hóa tên tool (canonical name)
- Kiểm tra allowed-tools trong SKILL.md
- Hỗ trợ alias PascalCase và Unix-style
"""


# ============================================================
# Tool name -> canonical name
# ============================================================

TOOL_NAME_TO_CANONICAL = {

    # -------------------------
    # Shell variants
    # -------------------------
    "shell": "shell",
    "bash": "shell",
    "BashTool": "shell",


    # -------------------------
    # File operations
    # -------------------------
    "file_read": "file_read",
    "FileReadTool": "file_read",

    "file_write": "file_write",
    "FileWriteTool": "file_write",

    "file_edit": "file_edit",
    "FileEditTool": "file_edit",


    # -------------------------
    # Search + ask
    # -------------------------
    "glob": "GlobTool",
    "GlobTool": "GlobTool",

    "grep": "GrepTool",
    "GrepTool": "GrepTool",

    "ask": "ask_user",
    "ask_user": "ask_user",
}



# ============================================================
# Canonicalize tool name
# ============================================================

def canonical_tool_name(name: str) -> str:
    """
    Trả về tên chuẩn của tool.

    Ví dụ:

    BashTool -> shell
    bash     -> shell
    shell    -> shell

    Tool không có alias:
    http -> http
    """

    return TOOL_NAME_TO_CANONICAL.get(
        name,
        name
    )



# ============================================================
# Known tool names
# ============================================================

KNOWN_TOOL_NAMES = {

    # shell
    "shell",
    "bash",
    "BashTool",


    # file
    "file_read",
    "FileReadTool",

    "file_write",
    "FileWriteTool",

    "file_edit",
    "FileEditTool",


    # search
    "glob",
    "GlobTool",

    "grep",
    "GrepTool",


    # web
    "http",
    "web_fetch",
    "web_search",


    # ask
    "ask",
    "ask_user",


    # findings
    "confirm_finding",


    # skills
    "load_skill",
    "read_payloads",
    "read_skill_file",


    # coverage
    "coverage",
}