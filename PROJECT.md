```
┌──────────────────────────────────────────────────────────────────────┐
│ src/cli/main.py — parse flags, load config, wire dependencies         │
└───────┬──────────────────────────────────────────────────────────────┘
        │ builds & injects
        ▼
┌─────────────────┐   events + bridges   ┌────────────────────────────┐
│ Agent Loop      │◄────────────────────►│ Textual TUI                │
│ src/agent/*     │                      │ src/ui/core/app.py         │
└───┬──────┬──────┘                      │ widgets · modals · banner  │
    │      │                             └────────────────────────────┘
    │      │ calls
    │      ▼
    │  ┌──────────────────────────────┐
    │  │ LLM Client Layer             │
    │  │ src/llm/*                    │
    │  │ openai-compatible · kimi     │
    │  │ groq · openrouter · deepseek │
    │  │ gemini · anthropic           │
    │  └──────────────────────────────┘
    │
    │ executes permission-gated tools
    ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Tool Registry / Tool Runtime                                          │
│ src/tools/*                                                           │
│ shell/bash · http · file read/write/edit · glob/grep · web fetch      │
│ web search · ask_user · confirm_finding · coverage · load_skill       │
│ payloads · skill_file · browser_capture_* · plugin · MCP tools        │
└──────────────────────────────────────────────────────────────────────┘
    │              │              │              │              │
    ▼              ▼              ▼              ▼              ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌──────────────┐
│ Skills   │  │ Findings │  │ Coverage │  │ Intelligence │  │ Browser/Burp │
│ Registry │  │ Store    │  │ Store    │  │ Store        │  │ Capture      │
│ SKILL.md │  │ Markdown │  │ JSON     │  │ local files  │  │ Store+Ingest │
└──────────┘  └──────────┘  └──────────┘  └──────────────┘  └──────────────┘
```
