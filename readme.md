# KAgent

KAgent is an LLM-powered web penetration-testing research project. It is under
active development and is not presented as production-ready.

It is intended for explicitly authorized web-security testing in local or
private labs, such as OWASP Juice Shop and DVWA. A name such as `juice.lab` is
an operator-defined local alias, not a hard-coded KAgent target.

## Architecture and workflow

The Python 3.11+ runtime provides a CLI and Textual TUI. The CLI loads
configuration, target and session state, then connects an LLM provider to the
agent, tool registry, workflow state, skills, and local stores. Skills guide a
high-level flow from discovery through confirmation and reporting; permission
and target-scope checks remain part of the runtime.

Available skill categories are:

- recon
- web-enumeration
- web-input-analysis
- sql-injection
- cross-site-scripting
- access-control
- authentication
- csrf
- ssrf
- ssti

## Setup

KAgent requires Python 3.11 or newer. Runtime dependencies are defined in
`pyproject.toml`; `requirements.txt` installs that same project metadata.

```bash
python -m pip install .
```

For local development and tests:

```bash
python -m pip install -e ".[dev]"
```

Optional resilience and syntax-highlighting enhancements can be installed with
`.[enhanced]` (or combined with `.[dev,enhanced]`).

## Running

After installation, start the Textual interface with:

```bash
kagent
```

To declare an authorized target at startup, pass `--target <url>`. Its exact
origin is the default scope; use `/scope add <origin>` in the TUI only when an
additional origin is authorized.

Use `kagent --help` to see supported flags, including provider configuration,
extra skill directories, session resume, and local browser/Burp integration.
The module entry point is also available for a checkout-based run:

```bash
python -m src.cli.main --help
```

## Repository layout

- `src/` — CLI, TUI, agent loop, providers, tools, workflow, and persistence
- `skills/` — skill metadata, playbooks, and payload assets
- `tests/` — focused, integration, skill-contract, and regression tests
- `.kagent/` — local project runtime data when created

## Testing

`pytest.ini` collects the complete test suite under `tests/`.

```bash
pytest -q
```

Skill contracts and runtime behavior are still being refined through testing.

## Authorized use and scope

Use KAgent only against targets you are authorized to test. Keep activity
within the declared target origin and preserve the runtime's permission
prompts; a private address or local-looking hostname alone is not an
authorization grant.
