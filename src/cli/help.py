"""CLI help text without runtime or UI dependencies."""

import sys

from src.version import VERSION


def print_help() -> None:
    sys.stdout.write(
        f"""kagent {VERSION}

Usage:
  kagent [flags]

Flags:
  --backend |openai|openai-compat|kimi|groq|openrouter|deepseek|gemini
  --model <id>
  --theme <dark|light>       TUI theme for this invocation (default: dark)
  --base-url <url>
  --target <url>            active target; scopes to its origin by default
  --api-key <key>
  --skills <dirs>            comma-separated extra skill directories
  --scanner-wordlist ID=FILE register an existing local wordlist for this session
                             (repeatable; model selects its ID via permissions_status)
  --resume <session-id>
  --browser                  enable verified persistent trusted-local Browser MCP
                             on Linux/WSL for this session; operator manages Chrome/Extension.
                             Use a separate lab profile without personal accounts/tabs.
                             Actions need --target, exact scope and permission or a bounded
                             operator Browser grant in YOLO; /permissions browser shows/revokes it.
                             Extension readiness has a bounded deadline; discovery needs no Chrome.
  --burp [port]              start local Burp/KAgent bridge (default :8888)
  --browser-ingest [port]    deprecated alias for --burp
  --no-stream                disable streaming chat (fallback for backends
                             whose SSE/ND-JSON path drops tool_calls)
  --yolo                     activate session native HTTP autonomy in operator scope
                             without manual grants; accept unknown server effects,
                             including bulk delete/real-data changes. Per origin:
                             no request quota or fixed grant TTL; 3/s burst 3, concurrency 2,
                             request 128KiB, retained response 64KiB. Explicit limits,
                             revocation remain enforced. Confirm-each resumes OFF.
                             Profile-covered tools auto-approve; independent resource
                             checks remain. Linux workers support brokered HTTP;
                             ordinary Shell/local stdio MCP need compatible configuration;
                             typed Nmap/ffuf require their own ready adapter and job review;
                             CONNECT and remote MCP unavailable;
                             phase never grants HTTP authority.
                             (alias: --dangerously-skip-permissions)
  --http-lab-grant <spec>     ORIGIN,MODE,SECONDS,REQUESTS,RATE,BURST,CONCURRENCY,
                             REQUEST_BYTES,RESPONSE_BYTES (repeatable, in scope only)
  --accept-unknown-http-effects
                             required with lab grant: bulk delete/real-data/server
                             effects are possible; no test-only or sandbox guarantee
  --list-skills / --list-tools
  --log <path>
  --debug-session             write a complete JSONL session debug log
  --debug-session-path <p>  custom path for --debug-session
  --version / --help

In the TUI: Enter send · Esc cancel turn · Ctrl-C quit · mouse-wheel scroll
Slash: /help /plan /clear /reset /exit /target /scope /permissions /maxsteps /thinking
"""
    )
