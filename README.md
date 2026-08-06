# KAgent

KAgent is an AI-powered, terminal-based agent for **security penetration testing** and
software engineering. It drives an LLM through a multi-step reasoning loop, lets it
execute real system tools (shell, HTTP, file I/O, browser capture, network recon),
and maintains long-lived, structured session memory so it can work through complex,
multi-turn engagements without losing context.

The UI is a full terminal application (TUI) built with [Textual](https://textual.textualize.io/),
using a Redux-style state/reducer architecture.

## Features

- **Multi-provider LLM support** — OpenAI-compatible endpoints, Gemini, Groq,
  DeepSeek, OpenRouter, Kimi, and Anthropic, selectable at runtime.
- **Agentic tool use** — shell/bash, HTTP requests, web fetch/search, file
  read/write/edit, glob/grep search, network scanning, and more, all gated by a
  permission system.
- **Skills** — Markdown "playbooks" (`SKILL.md`) the agent loads on demand for
  domain-specific tasks (JWT, SSRF, SSTI, GraphQL, recon, subdomain takeover,
  deserialization, race conditions, web vulns, …). See [`skills/README.md`](skills/README.md).
- **Session memory & compaction** — findings, todos, and credentials are kept as
  structured state across turns; long histories are summarized to save context tokens.
- **Permission model & YOLO mode** — tool calls require approval by default, with a
  sensitive-path gate that blocks access to SSH keys and credentials. `--yolo`
  auto-approves non-sensitive calls.
- **MCP integration** — extend the agent with external Model Context Protocol servers,
  including an optional Browser MCP.
- **Burp / browser bridge** — a local HTTP ingest server for pulling in traffic and
  tasks from Burp Suite or a browser extension.
- **Findings & reporting** — capture confirmed findings, with report output via
  ReportLab / Markdown / XLSX.

## Requirements

- Python **3.11+**
- A terminal that supports a full-screen TUI
- An API key for at least one supported LLM provider

## Installation

```bash
git clone https://github.com/ynvk404/KAgent.git
cd KAgent

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt
pip install -e .                  # exposes the `kagent` command
```

## Usage

Launch the TUI:

```bash
kagent
```

Or run it directly without installing the entry point:

```bash
python -m src.cli.main
```

### Common flags

```
kagent [flags]

  --backend  openai-compat|kimi|groq|openrouter|deepseek|gemini
  --model <id>
  --base-url <url>
  --api-key <key>
  --skills <dirs>            comma-separated extra skill directories
  --resume <session-id>      resume a saved session
  --browser                  enable Browser MCP for this session only
  --burp [port]              start local Burp/KAgent bridge (default :9999)
  --no-stream                disable streaming chat (backend fallback)
  --yolo                     auto-approve non-sensitive tool calls
                             (alias: --dangerously-skip-permissions)
  --list-skills / --list-tools
  --log <path>
  --debug-session            write a complete JSONL session debug log
  --version / --help
```

### In the TUI

- **Enter** — send · **Esc** — cancel turn · **Ctrl-C** — quit · mouse wheel to scroll
- Slash commands: `/help` `/plan` `/clear` `/reset` `/exit` `/target` `/maxsteps`
  `/thinking` `/skills` `/model` `/provider`
- `@path` mentions inline a file's contents into your prompt.

## Configuration

Runtime configuration (backend, model, API keys, skill/MCP settings) is stored at:

```
~/.kagent/config.json
```

Override the location with the `kagent_CONFIG` environment variable. You can also set
the backend, model, base URL, and API key per-run via the flags above, or interactively
with the `/provider` and `/model` slash commands.

## Skills

Skills are description-driven playbooks the model loads on demand. They are discovered
automatically from (in increasing precedence):

1. the built-in [`skills/`](skills/) directory
2. `./.kagent/skills/` (project-local)
3. `~/.kagent/builtin-skills/` (installer-managed)
4. `~/.kagent/skills/` (personal)
5. any dirs passed via `--skills` or the `skills_dirs` config

Create one with `/skills new <name>` in the TUI or by copying
[`skills/_template/SKILL.md`](skills/_template/SKILL.md). See
[`skills/README.md`](skills/README.md) for the full format.

## Project structure

```
src/
  cli/          entrypoint, service init, TUI orchestration
  agent/        core reasoning loop, memory, compaction
  ui/           Textual TUI (Redux-style state/reducer), slash commands
  llm/          provider clients (OpenAI, Anthropic, Gemini, …), model discovery
  tools/        shell, http, file, search, browser-capture, mcp, findings tools
  skills/       skill discovery, loading, and registry
  browser/      HTTP bridge for Burp / browser ingestion
  session/      session persistence (save/resume)
  memory/       structured session memory store
  findings/     findings capture and storage
  permission/   permission prompting and gating
  ...
skills/         built-in security playbooks
docs/           additional documentation
```

## Development

Run the test suite with coverage:

```bash
pytest --cov=src --cov-report=term-missing
```

## Security notice

KAgent is intended for **authorized** security testing only. Only use it against
systems you own or have explicit, written permission to test. You are responsible for
complying with all applicable laws and agreements.
