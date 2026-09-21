```
┌──────────────────────────────────────────────────────────────────────┐
│  src/cli/main.py                                                     │
│  parse flags · load config · construct providers/tools/stores        │
│  restore/create session · wire permission/UI/runtime dependencies    │
└───────────────┬──────────────────────────────────────────────────────┘
                │ builds & injects
                ▼
┌──────────────────────────────┐        events / bridges
│  Agent Core / Agent Loop     │◄──────────────────────────────┐
│  src/agent/*                 │                               │
│  planning · context · events │                               ▼
│  tool calls · stop/compact   │                    ┌───────────────────┐
└───────┬───────────┬──────────┘                    │  Textual TUI       │
        │           │                               │  src/ui/*          │
        │           │ LLM calls                     │ transcript/modals  │
        │           ▼                               │ status/permissions │
        │   ┌──────────────────────────────┐        └───────────────────┘
        │   │ LLM Client Layer             │
        │   │ src/llm/*                    │
        │   │ providers · retries · models │
        │   └──────────────────────────────┘
        │
        │ permission-gated execution
        ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Tool Registry / Execution Runtime                                   │
│  src/tools/*                                                         │
│  http · shell/files · search · ask_user · workflow · findings        │
│  coverage · load_skill · payloads · browser/Burp · plugin · MCP      │
└───────┬────────────┬──────────────┬──────────────┬───────────────────┘
        │            │              │              │
        ▼            ▼              ▼              ▼
┌────────────┐ ┌────────────┐ ┌──────────────┐ ┌──────────────────────┐
│ Workflow & │ │ Skills     │ │ Browser/Burp │ │ External/Local Tools │
│ Findings   │ │ System     │ │ Capture      │ │ MCP · shell · files  │
│ src/...    │ │ skills/*   │ │ src/browser  │ │ web/http             │
└─────┬──────┘ └─────┬──────┘ └──────────────┘ └──────────────────────┘
      │              │
      ▼              ▼
┌──────────────────────────────────────────────────────────────────────┐
│  State / Knowledge                                                   │
│  session · target · memory · intelligence · coverage · findings      │
│  .kagent/ and ~/.kagent/ stores                                      │
└──────────────────────────────────────────────────────────────────────┘
```
