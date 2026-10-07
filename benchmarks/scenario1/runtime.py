"""Benchmark adapter using the real Agent, registry, grants and native HTTP."""
from __future__ import annotations

import asyncio
from dataclasses import asdict
from pathlib import Path
import json
import os
import time
from types import SimpleNamespace
from typing import cast
from urllib.parse import urlencode

from benchmarks.common.contracts import CaseExecution, OperationalCaseInput, RuntimeMetrics, RuntimeSettings
from benchmarks.common.metrics import llm_metrics
from .canonical import freeze

REPO = Path(__file__).resolve().parents[2]
CAPABILITY = 'scenario1-native-http-confirmation-v1'


class BenchmarkSetupError(RuntimeError):
    """Pre-Agent initialization/admission failed; chained cause is local diagnostic."""


def request_fixture(op: OperationalCaseInput, settings: RuntimeSettings) -> dict:
    endpoint = settings.context_path.rstrip('/') + op.servlet_path
    query = urlencode([(p[0], p[1]) for p in op.query])
    headers = dict(op.headers)
    if op.content_type:
        headers['Content-Type'] = op.content_type
    if op.cookies:
        headers['Cookie'] = '; '.join(f'{k}={v}' for k, v in op.cookies.items())
    return {'method': op.method, 'url': settings.target.rstrip('/') + endpoint + ('?' + query if query else ''),
            'headers': headers, 'body': urlencode([(p[0], p[1]) for p in op.body]) if op.body else None, 'phase': 'validation'}


def candidate_arguments(op: OperationalCaseInput, settings: RuntimeSettings) -> dict:
    from src.target.origin import HTTPOrigin
    fixture = request_fixture(op, settings)
    return {'candidate_class': op.vulnerability_class, 'target': HTTPOrigin.from_url(settings.target).as_url(),
            'endpoint': settings.context_path.rstrip('/') + op.servlet_path, 'method': op.method,
            'parameter': op.input_name, 'location': op.input_location, 'content_type': op.content_type,
            'request_template': json.dumps(fixture, sort_keys=True, separators=(',', ':')),
            'source_ref': 'operator-supplied-input'}


def prompt(candidate_id: str, op: OperationalCaseInput) -> str:
    return (f'Validate candidate {candidate_id} for {op.vulnerability_class}. '
            'This exact target is an explicitly authorized local/private lab. '
            'Use the supplied legitimate request fixture and the production skill. '
            f'The designated input component is {op.input_component}. '
            'Only bounded confirmation is requested. Do not perform optional deeper impact validation, '
            'persistent exploit changes, reconnaissance, enumeration, or other candidates. '
            'Native HTTP is the only network capability; shell, MCP, plugins, browser and research are unavailable. '
            'Record the native structured outcome and stop according to the skill. '
            'Retain browser-required when browser proof is needed. No answers to ask_user are available headlessly.')


class HeadlessPermissions:
    """Only predeclared exact private-origin and generated artifact grants."""
    def __init__(self, policy, target):
        self.execution_policy = policy
        self.origin = target.origin().as_url()
        self.artifacts = str(policy.root / 'artifacts')
        self.decisions: list[dict] = []

    async def ask(self, request, signal=None):
        from src.permission.permission import Decision
        allowed = request.risk_tier == 'routine' and (
            request.tool == 'http' and request.cache_key == f'private-declared://{self.origin}'
            or request.tool in {'file_write', 'file_edit'} and request.cache_key == self.artifacts)
        self.decisions.append({'tool': request.tool, 'risk_tier': request.risk_tier, 'allowed': allowed})
        return Decision.ALLOW_ONCE if allowed else Decision.DENY


class MissingInput:
    async def ask(self, q, signal=None) -> str:
        from src.permission.permission import UserControlledRefusal
        raise UserControlledRefusal('headless: operator input unavailable; record unresolved')


def build_agent(op: OperationalCaseInput, settings: RuntimeSettings, root: Path, client, *, thinking=False):
    from src.agent.agent import Agent, AgentOptions
    from src.coverage.store import CoverageStore
    from src.engagement.state import EngagementState
    from src.findings.store import Store as Findings
    from src.intelligence.store import IntelligenceStore
    from src.memory.store import MemoryStore
    from src.permission.network.grants import HTTPLimits
    from src.permission.runtime.execution import default_execution_policy
    from src.session.store import Store, new_id
    from src.skills.load_skill import LoadSkillTool
    from src.skills.registry import Registry as Skills
    from src.target.target import Target
    from src.tools.common.ask import AskUserTool
    from src.tools.common.permission_status import PermissionStatusTool
    from src.tools.common.registry import Registry
    from src.tools.execution.file import FileReadTool, FileWriteTool, FileEditTool
    from src.tools.http.http_tool import HTTPTool
    from src.tools.skills.payloads import ReadPayloadsTool
    from src.tools.skills.skill_file import ReadSkillFileTool
    from src.tools.workflow.coverage import CoverageTool
    from src.tools.workflow.finding import ConfirmFindingTool
    from src.tools.workflow.workflow_tool import WorkflowTool
    from src.workflow.state import WorkflowState
    if not settings.authorized_lab:
        raise ValueError('runtime requires explicit authorized local/private lab declaration')
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.environ['KAGENT_PROJECT_ROOT'] = str(root)
    target = Target(settings.target.rstrip('/') + settings.context_path.rstrip('/'))
    engagement = EngagementState()
    engagement.initialize_target(settings.target)
    policy = default_execution_policy(engagement, root)
    policy.max_calls = settings.tool_calls
    policy.concurrency = 4
    session_id = new_id()
    policy.load_journal(root / '.kagent/permissions' / f'{session_id}.json')
    skills = Skills()
    loaded = Skills()
    loaded.load_dir(REPO / 'skills')
    for name in ('sql-injection', 'cross-site-scripting'):
        skill = loaded.get(name)
        if skill is None:
            raise ValueError(f'missing production skill {name}')
        skills.add(skill)
    tools = Registry()
    workflow = WorkflowState()
    http = HTTPTool(target, engagement)
    engagement.http_permissions.activate(settings.target, HTTPLimits(seconds=settings.timeout_seconds,
        requests=settings.http_requests, rate=3, burst=3, concurrency=2), activation='manual')
    prompter = HeadlessPermissions(policy, target)
    coverage = CoverageStore(str(root / '.kagent/coverage' / f'{session_id}.json'))
    for tool in (http, FileReadTool(), FileWriteTool(), FileEditTool(), LoadSkillTool(skills),
                 ReadPayloadsTool(skills), ReadSkillFileTool(skills), PermissionStatusTool(), AskUserTool(MissingInput()),
                 CoverageTool(coverage), WorkflowTool(workflow, target, coverage, skills, root, session_id, http),
                 ConfirmFindingTool(Findings(project_directory=root), lambda *_: None, workflow)):
        tools.register(tool)
    # Explicit home injection isolates user-global memory/intelligence without touching HOME or config.
    personal = root / '.personal'
    agent = Agent(AgentOptions(client, tools, skills, prompter,
        Store.new_with_id(root / '.kagent/sessions', session_id), target,
        max_steps=settings.agent_calls, streaming_enabled=False, thinking_enabled=thinking,
        memory_store=MemoryStore(cwd=str(root), home=str(personal)),
        intelligence=IntelligenceStore(cwd=root, home=personal), workflow=workflow, engagement_state=engagement))
    return agent, policy, session_id


def execution_status(done: dict | None, errors: list[str], *, timed_out=False, exhausted=False, raised=False) -> str:
    if timed_out:
        return 'timeout'
    if exhausted:
        return 'budget-exhausted'
    stop = done.get('stop_reason') if done else None
    if stop == 'client_error':
        return 'provider-error'
    if stop in {'max_steps', 'context_capacity'}:
        return 'budget-exhausted'
    if raised or errors or stop in {'runtime_error', 'cancelled', 'invalid_response'} or done is None:
        return 'runtime-error'
    if stop in {'final_response', 'workflow_completed', 'workflow_blocked', 'workflow_stalled', 'all_tools_refused', 'plan_only_blocked'}:
        return 'completed'
    return 'runtime-error'


async def execute_case(op: OperationalCaseInput, settings: RuntimeSettings, root: Path,
                       run_id: str, execution_id: str, client, *, thinking=False, generation=None) -> CaseExecution:
    setup_start = time.monotonic()
    try:
        agent, policy, session_id = build_agent(op, settings, root, client, thinking=thinking)
        signal = SimpleNamespace(aborted=False)
        payload = json.loads(await agent.tools.execute('workflow', {'action': 'record_candidate',
                                     **candidate_arguments(op, settings)}, signal, agent.prompter))
        if not payload.get('ok'):
            raise ValueError('production Candidate admission failed')
    except Exception as err:
        raise BenchmarkSetupError(type(err).__name__) from err
    candidate_id = payload['candidate']['id']
    done = None
    errors: list[str] = []
    tools = {'proposed': 0, 'result_events': 0, 'blocked': 0, 'failed': 0, 'executed': None}
    first = None
    budget_denial = False
    execution_start = time.monotonic()

    def emit(event):
        nonlocal done, first, budget_denial
        kind = event.type
        if kind == 'done':
            done = asdict(event)
        elif kind == 'error':
            # Keep types, never provider exception text or model/tool prose.
            errors.append(type(event.err).__name__)
        elif kind == 'tool-call':
            tools['proposed'] += 1
        elif kind == 'tool-result':
            tools['result_events'] += 1
            if event.error_kind in {'permission_denied', 'scope_denied'}:
                tools['blocked'] += 1
            elif event.status == 'error':
                tools['failed'] += 1
            if any(marker in event.err for marker in ('session-call-budget-exhausted', 'request budget exhausted',
                                                     'grant expired', 'grant time expired')):
                budget_denial = True
        latest = agent.workflow.latest_result(candidate_id)
        if first is None and latest and latest.outcome in {'confirmed', 'not-confirmed'}:
            first = time.monotonic() - execution_start

    timed_out, raised = False, False
    try:
        # Timeout cancellation is awaited; normal terminal records never cancel Agent.run.
        async with asyncio.timeout(settings.timeout_seconds):
            await agent.run(prompt(candidate_id, op), signal, emit)
    except TimeoutError:
        timed_out = True
    except Exception as err:
        raised = True
        errors.append(type(err).__name__)
    finally:
        # Drain all runtime background work before stopping the execution timer/freezing.
        outstanding = list(agent._background_tasks)
        if outstanding:
            if timed_out or raised:
                for task in outstanding:
                    task.cancel()
            settled = await asyncio.gather(*outstanding, return_exceptions=True)
            errors.extend(type(e).__name__ for e in settled if isinstance(e, Exception))
    execution_end = time.monotonic()
    status = execution_status(done, errors, timed_out=timed_out, exhausted=budget_denial, raised=raised)
    canonical = freeze(run_id, op.case_id, execution_id, session_id, candidate_id, agent.workflow, policy, agent.target)
    tools['executed'] = policy.used - 1  # Native policy.start; exclude harness Candidate creation.
    admitted = sum(b.used for b in policy.engagement.http_permissions._budgets.values())
    metadata = {'capability_profile': CAPABILITY, 'yolo': False, 'provider': client.name(), 'model': client.model(),
                'thinking_enabled': thinking, 'generation': generation,
                'permission_decisions': cast(HeadlessPermissions, agent.prompter).decisions, 'session_id': session_id,
                'candidate_id': candidate_id, 'objective_id': canonical['objective_id']}
    metrics = RuntimeMetrics(execution_end - execution_start, execution_start - setup_start,
                             time.monotonic() - execution_end, first,
                             llm_metrics(agent.request_metrics.records, done), tools, admitted)
    return CaseExecution(run_id, op.case_id, execution_id, status, done.get('stop_reason') if done else None,
                         canonical, asdict(metrics), metadata, ','.join(errors[:12]) or None)
