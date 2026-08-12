```
┌──────────────────────────────────────────────────────────────────────┐
│  src/cli/main.py — parse flags, load config, wire dependencies        │
└───────┬──────────────────────────────────────────────────────────────┘
        │ builds & injects
        ▼
┌─────────────────┐   events / bridges   ┌────────────────────────────┐
│  Agent Loop     │◄────────────────────►│  Textual TUI                │
│  src/agent/*    │                      │  src/ui/core/app.py         │
│                 │                      │  transcript · modals · menu │
└───┬──────┬──────┘                      │  banner · status            │
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
│  Tool Registry / Runtime                                              │
│  src/tools/*                                                          │
│  shell/bash · http · file read/write/edit · glob/grep · web fetch     │
│  web search · ask_user · confirm_finding · coverage · load_skill      │
│  payloads · skill_file · browser_capture_* · plugin · MCP tools       │
└──────────────────────────────────────────────────────────────────────┘
    │            │            │              │              │
    ▼            ▼            ▼              ▼              ▼
 Findings    Coverage     Browser/Burp     MCP          Local Shell
 Store       Store        Capture Store    Tools        / Files
 Markdown    JSON         + ingest server   stdio        filesystem

```
