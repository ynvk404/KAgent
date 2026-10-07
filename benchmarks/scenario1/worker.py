"""Fresh-process entrypoint. stdin is an operational envelope, never a manifest."""
from __future__ import annotations

import asyncio
from dataclasses import asdict
import contextlib
import json
import os
from pathlib import Path
import sys

from benchmarks.common.contracts import CaseExecution, OperationalCaseInput, RuntimeSettings, decode, write_new
from .runtime import execute_case, BenchmarkSetupError


async def main(*, client_factory=None):
    envelope = json.load(sys.stdin)
    if set(envelope) != {'operational', 'settings', 'workspace', 'output', 'run_id', 'execution_id'}:
        raise ValueError('invalid operational worker envelope')
    op = decode(OperationalCaseInput, envelope['operational'])
    settings = decode(RuntimeSettings, envelope['settings'])
    workspace = Path(envelope['workspace']).resolve()
    workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chdir(workspace)
    os.environ['KAGENT_PROJECT_ROOT'] = str(workspace)
    os.environ.pop('KAgent_TRACE_AGENT', None)
    # Read-only production secure provider configuration. Never copy it into artifacts.
    from src.config.config import load
    from src.llm.runtime.provider_runtime import build_startup_runtime
    stage = 'provider-initialization'
    try:
        cfg = load()
        runtime = build_startup_runtime(cfg, custom_provider_id=cfg.active_custom_provider_id,
                                        client_factory=client_factory)
        stage = 'agent-execution-and-export'
        result = await execute_case(op, settings, workspace, envelope['run_id'], envelope['execution_id'],
                                    runtime.client, thinking=runtime.config.thinking_enabled,
                                    generation={'temperature': runtime.config.temperature,
                                                'max_tokens': runtime.config.max_tokens,
                                                'gemini_thinking_budget': runtime.config.gemini_thinking_budget})
    except Exception as err:
        import traceback
        trace = [{'file': Path(row.filename).name, 'line': row.lineno, 'function': row.name}
                 for row in traceback.extract_tb(err.__traceback__)[-8:]]
        status = 'setup-error' if stage == 'provider-initialization' or isinstance(err, BenchmarkSetupError) else 'runtime-error'
        write_new(Path(envelope['output']), asdict(CaseExecution(envelope['run_id'], op.case_id,
                  envelope['execution_id'], status, None, None, None,
                  {'stage': stage, 'exception_type': type(err).__name__, 'trace': trace},
                  type(err).__name__)))
        return
    write_new(Path(envelope['output']), asdict(result))


if __name__ == '__main__':
    # Agent exceptions can print provider errors; no unrestricted stderr/log artifact.
    with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        try:
            asyncio.run(main())
        except Exception:
            sys.exit(70)
