"""Opt-in authorized live validation, actual CLI/Textual + configured DeepSeek.

The fixed read-only request set is an operator-authored harness restriction for
this paid trial, not a product method classifier or a narrow-object grant.
Production mutation/endpoint freedom is tested separately with isolated fixtures.
"""
from pathlib import Path
import sys
import os
import json
import asyncio
from decimal import Decimal
from unittest.mock import patch
import importlib

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from src.config.config import load
from src.llm.validation_budget import ValidationBudget, active_validation_budget
from src.permission.execution import ExecutionBlocked
from src.ui.core.state import SetPerm
from src.agent.agent import AgentRunOptions
from tests.helpers.agent_fakes import FakeSignal

OUT = Path(__file__).parent / 'repair-2026-10-02'
LAB = 'http://juice.lab:3000'


async def main():
    if sys.argv[1:] != ['--live']:
        raise SystemExit('Explicit --live required; uses authorized configured DeepSeek and lab only.')
    cfg = load()
    if str(cfg.backend) != 'deepseek' or cfg.active_custom_provider_id:
        raise SystemExit('Configured provider differs; stop without changing configuration.')
    budget = ValidationBudget(OUT / 'deepseek-budget.json', cfg.model)
    if budget.state['unknown_usage']:
        raise SystemExit('Prior usage unavailable; do not start another live session.')
    if len(budget.state['attempts']) >= 5:
        budget.continue_after_trial()
    budget.begin_session()
    workspace = OUT / 'live-workspace'
    workspace.mkdir(exist_ok=True)
    paths = [f'/rest/products/search?q=KAGENT_SYNTHETIC_REPAIR_{n}' for n in range(4)]
    allowed = {LAB + path for path in paths}
    report = {'configured_model':cfg.model, 'configured_max_tokens':cfg.max_tokens,
              'scope':LAB, 'restricted_trial':'fixed read-only harness actions; no live mutation or test-object ownership claim',
              'approval_dialogs':0, 'native_successes':0, 'worker_http_success':False, 'events':[]}
    cli = importlib.import_module('src.cli.main')
    original_run = cli.KAgent.run_async
    token = active_validation_budget.set(budget)

    async def run_app(app):
        async with app.run_test(size=(120,40)):
            agent = app.agent
            original_dispatch = app.dispatch
            def dispatch(action):
                if isinstance(action, SetPerm) and action.req is not None:
                    report['approval_dialogs'] += 1
                    from src.permission.permission import Decision
                    action.req.resolve(Decision.DENY)
                original_dispatch(action)
            app.dispatch = dispatch
            # Independent deterministic real-worker trial, no model-selected
            # command: only the authorized lab's fixed synthetic search.
            result = await agent.tools.execute('shell', {'command':f"curl -fsS --max-time 10 '{LAB}{paths[0]}'"}, None, agent.prompter)
            report['worker_http_success'] = '"data":[]' in result or '"data": []' in result
            schemas = agent.tools.as_llm_tools()
            agent.tools.as_llm_tools = lambda:[row for row in schemas if row['function']['name'] in {'http','permissions_status'}]
            original_execute = agent.tools.execute
            async def restricted(name, args, signal, prompter):
                if name == 'http':
                    effective = agent.tools.get('http').resolve_url(args.get('url',''))
                    if effective not in allowed or args.get('method','GET').upper() != 'GET' or args.get('body','') or args.get('headers'):
                        raise ExecutionBlocked('blocked: request outside operator-authored live trial actions')
                    # The trial accepts only this already declared bounded
                    # effective request; response cap does not change effects.
                    if args.get('max_response_bytes',4096) > 4096:
                        raise ExecutionBlocked('blocked: live trial response cap')
                elif name != 'permissions_status':
                    raise ExecutionBlocked('blocked: tool outside operator-authored live trial role')
                result = await original_execute(name,args,signal,prompter)
                if name == 'http' and result.http_status == 200:
                    report['native_successes'] += 1
                return result
            agent.tools.execute = restricted
            def emit(event):
                kind = event.get('type')
                if kind == 'error':
                    report['events'].append({'type':kind,'error_type':type(event.get('err')).__name__})
                elif kind in {'tool-call','tool-result','done'}:
                    report['events'].append({'type':kind,'name':event.get('name'),'status':event.get('status')})
            # Startup's genuine API probe is counted too. No client/model/key
            # or configured output cap is replaced by this harness.
            for path in paths:
                if len(budget.state['attempts']) >= 5:
                    if budget.state['unknown_usage']:
                        break
                    report['trial_review'] = {'attempts':len(budget.state['attempts']), 'estimated_upper_usd':str(budget.cost), 'all_usage_present':True}
                    budget.continue_after_trial()
                if len(budget.state['attempts']) >= 60 or budget.cost >= Decimal('1'):
                    break
                await agent.run(f'Bounded authorized reachability check. Call http with url="{LAB}{path}", method="GET", phase="recon", max_response_bytes=1024, no body or headers. Then report the observed status briefly. Do not create vulnerability findings, use other tools or change scope.', FakeSignal(), emit, AgentRunOptions(max_steps=2))
                if budget.state['unknown_usage']:
                    break
            report['policy_calls'] = agent.prompter.execution_policy.used
            report['session_id'] = agent.store.id if hasattr(agent.store,'id') else 'see session store'

    try:
        with patch.object(cli.KAgent,'run_async',run_app), patch.object(sys,'argv',['kagent','--target',LAB,'--yolo','--no-stream']), patch.dict(os.environ,{'KAGENT_PROJECT_ROOT':str(workspace.resolve())}), patch.object(cli.session_store,'dir_from_path',lambda _:workspace/'.kagent/sessions'):
            report['cli_exit'] = await cli.main()
    except BaseException as exc:
        report['failure_type'] = type(exc).__name__
    finally:
        active_validation_budget.reset(token)
        report.update({'api_attempts_total':len(budget.state['attempts']), 'sessions_total':budget.state['sessions'],
                       'estimated_upper_usd':str(budget.cost), 'unknown_usage':budget.state['unknown_usage'], 'price_source':budget.PRICE_SOURCE})
        (OUT/'live-cli-results.json').write_text(json.dumps(report,indent=2))
        print(json.dumps(report,indent=2))


if __name__ == '__main__':
    asyncio.run(main())
