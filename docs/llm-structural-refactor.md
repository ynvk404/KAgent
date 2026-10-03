# LLM structural refactor audit

Starting HEAD: `1d2d26e388ec34fa0f71a6bf9f9b3ed22ca6f1fa`
(`refactor(tools): organize modules into domain packages`). The worktree was
clean before this task. No commits, pushes, dependency installations, or live
model calls are part of this refactor.

## Original source tree

```text
src/llm/
├── __init__.py
├── anthropic.py
├── client.py
├── errors.py
├── factory.py
├── gemini.py
├── metrics.py
├── model_warnings.py
├── models.py
├── openai.py
├── probe.py
├── provider_runtime.py
├── providers.py
├── reasoning.py
├── retry.py
├── transport.py
├── types.py
└── validation_budget.py
```

All 18 modules were read. The flat tree mixes protocol adapters, shared
contracts, HTTP policy, configuration lifecycle, and diagnostics. `client.py`
is an abstract client contract, not an HTTP client implementation. `models.py`
is model discovery, not a data-model contract. `providers.py` contains defaults,
model inventories, capability predicates, and URL validation, not provider
implementations or a dynamic registration mechanism.

## Responsibility and dependency audit

Names below refer to the original modules. Internal dependencies include
imports inside functions. Every module has a direct import path used by tests
except the empty root initializer; test locations stay unchanged.

| Module | Responsibility / kind | Production callers | Internal LLM dependencies | Dependencies outside LLM |
| --- | --- | --- | --- | --- |
| `__init__` | Empty package boundary | Python package imports | None | None |
| `anthropic` | Anthropic REST adapter; provider implementation | Factory | client, errors, providers, retry, transport, types | Standard library only directly; shared transport supplies HTTP |
| `openai` | OpenAI and compatible REST/SSE adapter; provider implementation | Factory | client, errors, providers, reasoning, metrics, retry, transport, types | httpx; logger; standard library |
| `gemini` | Gemini REST/SSE adapter and safe replay; provider implementation | Factory; session store (deferred replay helper) | client, errors, retry, providers, reasoning, metrics, transport, types | logger; standard library; shared transport supplies HTTP |
| `client` | Abstract Client, StreamingClient, Pinger and type guards; contract | Agent; factory; provider runtime; adapters; probe | types, reasoning | Standard library |
| `types` | Requests, responses, messages, tools and provider replay records; contract | Agent; session store; tool registry; clients; probe | reasoning, metrics | Standard library |
| `reasoning` | Provider-neutral intent, capabilities and resolution; contract | Agent; clients; types | None | Standard library |
| `factory` | Config-to-client routing; shared construction entry point | CLI; provider runtime | adapters, client, providers | Config; standard library |
| `providers` | Provider metadata, URL validation and capability predicates; shared metadata | Factory; adapters; models; provider runtime; CLI; UI app/pickers/adapter | None | Standard library |
| `models` | Synchronous model discovery and ordering; shared control-plane entry point | UI app; slash handler; provider/model pickers; custom provider adapter | providers, errors, transport | requests; Config; standard library |
| `errors` | Backend/control-plane failures, HTTP classification, transient classification and Retry-After parsing; transport/error policy | Clients; models; HTTP helpers; retry; UI pickers | None | Standard library |
| `retry` | Bounded retry, jitter, Retry-After and abort-aware wait; transport policy | All provider clients | errors | Standard library |
| `transport` | HTTP client/session factories, ping, SSE lines and cancellation; transport | Clients; models | errors; validation_budget (deferred) | httpx; requests; standard library |
| `provider_runtime` | Startup resolution and transactional provider activation/rollback; runtime lifecycle | CLI | client, factory, providers | Config; standard library |
| `probe` | Timeout/cancellation-bounded tool-support check; runtime capability diagnostic | CLI | client, types | Standard library |
| `validation_budget` | Opt-in session/attempt/cost persistence and transport wrapper; validation runtime | HTTP helpers (deferred) | None | httpx; standard library |
| `metrics` | Usage records/parsers, bounded collector and metadata export; runtime measurement | Agent; adapters; types; internal reasoning benchmark | None | Standard library |
| `model_warnings` | Model-size inference and hosted-model reliability warning; runtime diagnostic | CLI | None | Config; standard library |

The audited LLM dependency graph is acyclic. The important potential cycle is
`types -> metrics -> runtime initializer -> provider_runtime -> factory ->
client -> types` if runtime were given eager barrel exports. Core, runtime and
transport initializers therefore stay empty. Provider metadata has no internal
dependencies, so it can live in `providers/__init__.py` without loading adapters.
Metrics and model warnings share a runtime umbrella but remain separate modules;
neither is combined with the other's logic.

## Selected target structure

```text
src/llm/
├── __init__.py
├── core/
│   ├── __init__.py       # Empty
│   ├── client.py
│   ├── factory.py
│   ├── models.py
│   ├── reasoning.py
│   └── types.py
├── providers/
│   ├── __init__.py       # Existing provider metadata, same import path
│   ├── anthropic.py
│   ├── gemini.py
│   └── openai.py
├── transport/
│   ├── __init__.py       # Empty
│   ├── errors.py
│   ├── http.py           # Original transport.py
│   └── retry.py
└── runtime/
    ├── __init__.py       # Empty
    ├── metrics.py
    ├── model_warnings.py
    ├── probe.py
    ├── provider_runtime.py
    └── validation_budget.py
```

This is four domain packages. `core/` groups shared client/message/reasoning
contracts and common construction/discovery entry points. The root contains only
its empty initializer. `factory.py` still constructs clients, and `models.py`
still performs model discovery; neither changes responsibility or logic.
`errors.py` moves with HTTP/retry policy;
its classification functions are used outside transport through direct imports.
`probe.py` measures client capability at startup, so it belongs to runtime.
The budget includes runtime state and persistence as well as its transport
wrapper; HTTP policy retains deferred access to it.

## Frozen behavior

- Factory branches, backend identifiers, default model IDs, base URLs, extra
  headers, API-key requirements, Config/environment lookup and fallback errors.
- Official / Custom / Manual identities, startup overrides and transactional
  persistence, activation, rollback, locking and cancellation behavior.
- OpenAI-compatible, Anthropic and Gemini request encoding, response parsing,
  tools, finish reasons, provider-private replay and reasoning settings.
- Streaming/SSE consumption, deltas, tool fragments, callback handling and cleanup.
- Retry defaults (two retries, 500 ms base, 8,000 ms backoff cap), jitter,
  Retry-After advice/cap (30,000 ms), transient classification and cancellation.
- HTTP timeout (600 s chat; 10 s ping; 5 s model discovery), trust_env=False,
  synchronous discovery redirect policy and exception translation.
- Probe timeout (8 s), outcomes and cancellation cleanup.
- Validation-budget pricing, calculations, reservations, limits and persistence.
- Metrics field semantics, usage parsing, collector bounds and export policy.
- Model warning text, inferred size and thresholds.

Only module locations and import / mock lookup paths change. Existing business
logic is retained, including any pre-existing shortcomings.

## Loading and import strategy

Before migration, fresh-process snapshots showed:

- `import src.llm` loaded only the empty LLM root.
- `import src.llm.providers` loaded metadata only.
- `import src.llm.client` loaded types, reasoning and metrics, but no adapters.
- `import src.llm.models` loaded transport/errors/metadata, but no adapters or budget.
- `import src.llm.factory` already eagerly loaded all three REST adapters.
- `import src.llm.provider_runtime` loaded factory and those adapters.
- No adapter imported `anthropic`, `google.genai` or `google.generativeai` SDKs.
- Transport imported validation-budget state only inside HTTP factory functions.
- Session store imported Gemini's replay helper inside serialization/deserialization.

Preserve these boundaries, including the existing factory eagerness. Adding lazy
factory routing would be a separate behavior/initialization change.

All repository callers and string-based mock paths migrate to canonical modules.
The metadata path `src.llm.providers` stays stable because its implementation
moves directly into the package initializer. No wildcard re-export or duplicate
implementation is needed. The existing CLI wildcard metadata import is expanded
to explicit imports preserving its previously exposed symbols.

Repository searches covered `src.llm`, relative LLM imports, importlib,
`__module__`, patch/monkeypatch strings, configuration and serialized paths.
No LLM module path was found as a persisted provider/config/session value.
Session traffic/state is explicitly serialized rather than pickled by adapter
class path. Moved classes/functions acquire their canonical `__module__`; this
is the intentional import-location change.

## Follow-ups outside this task

- Factory already loads every adapter on import. Consider deferred adapter
  imports separately if measured startup cost warrants a behavior change.
- Existing Anthropic responses do not attach usage/retry metrics like the other
  adapters. Preserve that difference here; any parity work needs its own scope.
- Provider metadata shares its namespace with some imported standard-library
  names. Keep existing exports for compatibility; API narrowing is separate work.

## Verification

Baseline focused verification: 427 passed, 0 failed, 0 skipped, 2 existing Config
warnings. Baseline full pyright: 0 errors, 0 warnings across 327 files.

Baseline full suite: 3034 passed, 1 skipped, 2 existing Config warnings.

Each phase passed an import smoke check and focused tests:

| Phase | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| Shared import preparation | 58 | 0 | 0 | 0 |
| Providers and session replay | 138 | 0 | 0 | 0 |
| Transport/retry/errors/discovery | 144 | 0 | 0 | 0 |
| Runtime/config/CLI/budget | 183 | 0 | 0 | 2 |
| Initial focused responsibility groups (before core grouping) | 912 | 0 | 0 | 2 |
| Core grouping and shared callers | 459 | 0 | 0 | 2 |

Results extracted from the final full-suite JUnit report are below. Rows overlap
where a smaller responsibility group is already included in a larger one.

| Group | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| LLM unit tests (all `tests/llm`) | 246 | 0 | 0 | 0 |
| Provider adapters, including streaming/SSE and tool-call parsing | 38 | 0 | 0 | 0 |
| Factory | 24 | 0 | 0 | 0 |
| Transport/retry/errors | 43 | 0 | 0 | 0 |
| Model discovery | 46 | 0 | 0 | 0 |
| Reasoning/continuity | 32 | 0 | 0 | 0 |
| Metrics/model warnings | 11 | 0 | 0 | 0 |
| Probe | 6 | 0 | 0 | 0 |
| Import/shared-state regressions | 32 | 0 | 0 | 0 |
| Validation budget (including canonical identity/shared context) | 4 | 0 | 0 | 0 |
| Runtime/CLI provider selection | 48 | 0 | 0 | 0 |
| Config/custom provider adapter | 67 | 0 | 0 | 2 |
| Provider/model/slash UI | 54 | 0 | 0 | 0 |
| Agent/session store | 431 | 0 | 0 | 0 |
| Configured integration tests | 60 | 0 | 0 | 0 |
| Full suite | 3066 | 0 | 1 | 2 |

The existing live Groq characterization test remained skipped, with
`KAGENT_RUN_LIVE_TOOL_CHARACTERIZATION=0`. Tests ran through a temporary runner
outside the worktree that also rejected non-loopback socket connections in the
pytest process. Provider protocol tests used mocks or loopback HTTP fixtures.
No real external model API calls or API credits were used. The existing
`pytest.ini` exclusion of `tests/integration/test_kagent_burp.py` stayed intact;
that excluded file was not run.

Full pyright using `venv-linux/bin/pyright --outputjson`: 331 files analyzed,
0 errors, 0 warnings, compared with 327 files / 0 errors / 0 warnings before.
`git diff --check` passed.

Structural verification additionally established:

- All 18 original LLM modules and all modified existing Python files (63 files
  total including unchanged shared LLM modules) retained their AST outside
  imports and the single updated Gemini monkeypatch lookup string.
- Provider metadata was byte-identical to `HEAD:src/llm/providers.py`.
- Root, core, runtime and transport initializers were empty.
- The 21-module LLM graph was acyclic, including package-initializer edges and
  deferred imports.
- Fresh-process import graphs matched baseline after module-path normalization
  and addition of empty package namespaces. No new provider/SDK eager imports.
- All 39 previous CLI metadata symbols retained identity under explicit imports.
- Offline snapshots for all nine Backend enum values (eight configured providers
  and the empty backend) matched byte-for-byte: routing, client attributes,
  defaults, generation options and request payloads across every reasoning level,
  including OpenAI streaming/non-streaming encoding.
- Repository runtime, tests, internal benchmark and mock paths used canonical
  imports. Existing tests changed only imports/mock paths and were not moved.
- No legacy implementation shims, duplicate implementations, provider/config
  schema changes, or durable module-path rewrites were introduced.

Startup imports were also measured after the initial providers/transport/runtime
migration, before the final core grouping, using baseline and migrated source
snapshots on the same temporary filesystem, with five alternating samples after
warm-up. These timing values describe that earlier phase:

| Import | Before median (ms) | After median (ms) |
| --- | ---: | ---: |
| LLM root | 0.44 | 0.33 |
| Client contract | 32.98 | 38.19 |
| Factory | 1874.44 | 1813.73 |
| Model discovery | 1952.10 | 1781.46 |
| Provider runtime | 1941.24 | 2266.46 |

A repeat focused on provider runtime measured medians of 1672.21 / 1768.65 ms,
with individual before samples spanning 1643.93–3186.77 ms and after samples
1613.42–2843.88 ms. Import timings varied substantially between runs. These
measurements do not establish a statistically significant startup slowdown or
an end-to-end CLI/TUI latency guarantee. Import-graph and SDK-blocking tests
establish that no additional provider or optional SDK is eagerly loaded.

## Move and import map

Paths below are relative to `src/llm/`; import names are relative to `src.llm`.

| Old file | New file | New canonical import |
| --- | --- | --- |
| `client.py` | `core/client.py` | `src.llm.core.client` |
| `types.py` | `core/types.py` | `src.llm.core.types` |
| `reasoning.py` | `core/reasoning.py` | `src.llm.core.reasoning` |
| `factory.py` | `core/factory.py` | `src.llm.core.factory` |
| `models.py` | `core/models.py` | `src.llm.core.models` |
| `providers.py` | `providers/__init__.py` | `src.llm.providers` (unchanged metadata API) |
| `anthropic.py` | `providers/anthropic.py` | `src.llm.providers.anthropic` |
| `gemini.py` | `providers/gemini.py` | `src.llm.providers.gemini` |
| `openai.py` | `providers/openai.py` | `src.llm.providers.openai` |
| `errors.py` | `transport/errors.py` | `src.llm.transport.errors` |
| `retry.py` | `transport/retry.py` | `src.llm.transport.retry` |
| `transport.py` | `transport/http.py` | `src.llm.transport.http` |
| `metrics.py` | `runtime/metrics.py` | `src.llm.runtime.metrics` |
| `model_warnings.py` | `runtime/model_warnings.py` | `src.llm.runtime.model_warnings` |
| `probe.py` | `runtime/probe.py` | `src.llm.runtime.probe` |
| `provider_runtime.py` | `runtime/provider_runtime.py` | `src.llm.runtime.provider_runtime` |
| `validation_budget.py` | `runtime/validation_budget.py` | `src.llm.runtime.validation_budget` |

The metadata import path is preserved directly, not through a compatibility
layer. All other moved implementation imports were migrated throughout the
repository. No compatibility layer remains; callers outside the repository
using those old implementation paths need the same import migration, including
the shared contracts, factory and discovery entry points now under `core/`.
All four package boundaries preserve the existing provider loading semantics.

## Final assessment

The structural migration is complete. Offline regression tests found no runtime
behavior regression, and factory routing / provider inventories / deferred
import boundaries are preserved. The patch is ready for a separate structural
refactor commit after review, including the new canonical files and regression
tests. The index and HEAD were left unchanged. No unrelated worktree changes,
temporary/debug files, new secrets, or feature fixes were introduced.
