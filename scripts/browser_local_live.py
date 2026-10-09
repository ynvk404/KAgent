"""Operator-driven live Browser smoke test; no LLM, no automatic action retries.

Reads one JSON command per stdin line. Uses KAgent flags, Agent gate, Registry,
policy receipts and the production trusted-local binding. Only the explicit
Juice Shop navigation/search UI envelope below can receive ALLOW_ONCE.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import time
import uuid
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agent.agent import Agent, AgentOptions
from src.cli.runtime import parse_flags
from src.engagement.state import EngagementState
from src.llm.core.client import Client
from src.permission.permission import Decision, UserControlledRefusal, YoloPrompter
from src.permission.runtime.execution import ExecutionBlocked, default_execution_policy
from src.redaction.redact import apply_evidence
from src.skills.registry import Registry as SkillRegistry
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.mcp.browser_local import BrowserLocalBinding, BrowserOwner, check_ports_free, verify_listener_owner
from src.tools.mcp.integration import discover_mcp_tools
from src.tools.mcp.session_servers import session_mcp_servers

TARGET = 'http://juice.lab:8081'
TZ = timezone(timedelta(hours=7))


class NoLLM(Client):
    def name(self):
        return 'browser-live-no-llm'

    def model(self):
        return 'none'

    async def chat(self, request, signal=None):
        raise RuntimeError('live Browser runner must never call an LLM')


class ExactOperator:
    """One explicit control command approves just its proposed invocation."""

    def __init__(self, emit):
        self.emit = emit
        self.expected: str | None = None
        self.decision = Decision.DENY
        self.asks = 0

    async def ask(self, request, signal=None):
        self.asks += 1
        if (request.tool != self.expected or not request.no_session_cache
                or request.risk_tier != 'high-impact' or not request.force_operator):
            raise RuntimeError('unexpected permission envelope')
        self.emit('permission', tool=request.tool, decision=self.decision.value,
                  no_session_cache=request.no_session_cache, risk_tier=request.risk_tier,
                  force_operator=request.force_operator)
        return self.decision


async def main():
    flags = parse_flags(sys.argv[1:])
    if not flags.browser or flags.target_url != TARGET:
        raise ValueError('requires --browser --target ' + TARGET)
    repo = Path(__file__).resolve().parents[1]
    run_id = datetime.now(TZ).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8]
    evidence = repo / 'artifacts/browser_mcp_live' / run_id
    evidence.mkdir(parents=True, exist_ok=False)
    log = evidence / 'events.jsonl'

    def emit(event, **fields):
        row = {'time': datetime.now(TZ).isoformat(), 'monotonic_ns': time.monotonic_ns(), 'event': event, **fields}
        safe = apply_evidence(json.dumps(row, ensure_ascii=False, default=str))
        with log.open('a', encoding='utf-8') as stream:
            stream.write(safe + '\n')
        print(safe, flush=True)

    engagement = EngagementState()
    engagement.add_origin(TARGET)
    policy = default_execution_policy(engagement, repo)
    policy.session_id = run_id
    # Observe existing gates in this diagnostic runner; do not change their policy.
    prepare_receipt, start_receipt = policy.prepare, policy.start

    def observed_prepare(*args, **kwargs):
        start = time.monotonic_ns()
        result = prepare_receipt(*args, **kwargs)
        emit('receipt_prepare', duration_ms=(time.monotonic_ns() - start) / 1e6)
        return result

    def observed_start(*args, **kwargs):
        start = time.monotonic_ns()
        result = start_receipt(*args, **kwargs)
        emit('receipt_start', duration_ms=(time.monotonic_ns() - start) / 1e6)
        return result

    policy.prepare, policy.start = observed_prepare, observed_start
    inner = ExactOperator(emit)
    prompter = YoloPrompter(inner, flags.yolo)
    prompter.bind_execution_policy(policy)
    server = session_mcp_servers([], flags.browser)[0]
    binding = BrowserLocalBinding(policy, server, lab_origin=flags.target_url)
    policy.browser_local = binding
    tools = Registry()
    skills = SkillRegistry()
    skills.load_dir(str(repo / 'skills'))
    target = Target(TARGET)
    agent = Agent(AgentOptions(client=NoLLM(), tools=tools, skills=skills, prompter=prompter,
                              store=None, target=target, engagement_state=engagement))
    owned_pids: set[int] = set()
    calls = 0
    dispatches = 0
    original_dispatch = binding.dispatch

    async def observed_dispatch(*args, **kwargs):
        nonlocal dispatches
        dispatches += 1
        return await original_dispatch(*args, **kwargs)

    binding.dispatch = observed_dispatch

    async def state():
        if binding.owner is None:
            return None
        result = await asyncio.wait_for(binding.owner.request('browser_status'), 3)
        verify_listener_owner(result)
        owned_pids.add(result['pid'])
        return {**result, 'owner_task': id(binding.owner.task), 'binding_epoch': binding.epoch}

    try:
        discovered = await discover_mcp_tools(server, execution_policy=policy, browser_local=binding)
        for tool in discovered['tools']:
            tools.register(tool)
        emit('ready', flags=sys.argv[1:], target=TARGET, tools=len(discovered['tools']),
             evidence=str(evidence), host_listener=False, active_skills=sorted(agent.active_skills))
        while True:
            line = await asyncio.wait_for(asyncio.to_thread(sys.stdin.readline), 180)
            if not line:
                break
            try:
                command = json.loads(line)
                action = command['action']
                if action == 'pair':
                    policy.require_network(TARGET)
                    if binding.owner is None:
                        binding.owner = await BrowserOwner.open(binding.server)
                        inventory = await binding.owner.request('list_tools')
                        if binding._schema_identity(inventory) != binding.schema_identity:
                            raise RuntimeError('tool schemas differ from verified discovery')
                    emit('listener', state=await state())
                    deadline = asyncio.get_running_loop().time() + 30
                    while True:
                        current = await state()
                        if current is not None and current['connected']:
                            emit('paired_transport', state=current, chrome_ready_proven=False)
                            break
                        if asyncio.get_running_loop().time() >= deadline:
                            raise TimeoutError('extension pairing deadline; no browser operation sent')
                        await asyncio.sleep(0.1)
                elif action == 'status':
                    emit('status', state=await state(), dispatches=dispatches, policy_active=policy.active)
                elif action == 'call':
                    name = command['name']
                    args: dict[str, Any] = deepcopy(command.get('args', {}))
                    if name not in {'navigate', 'snapshot', 'click', 'type'}:
                        raise ValueError('outside authorized live-test tool envelope')
                    if name == 'navigate' and args != {'url': TARGET}:
                        raise ValueError('navigate target must exactly match authorized URL')
                    if name == 'snapshot' and args:
                        raise ValueError('snapshot requires empty arguments')
                    if name in {'click', 'type'} and not isinstance(args.get('ref'), str):
                        raise ValueError('latest snapshot ref required')
                    if name == 'type' and args.get('submit') is not False:
                        raise ValueError('live test forbids form submission')
                    full_name = 'mcp_browser_browser_' + name
                    allowed = agent.is_tool_allowed(full_name, args)
                    if not allowed.ok:
                        raise PermissionError('Skill gate: ' + str(allowed.reason))
                    inner.expected = full_name
                    inner.decision = Decision.DENY if command.get('decision') == 'deny' else Decision.ALLOW_ONCE
                    before = await state()
                    before_dispatch = dispatches
                    calls += 1
                    emit('proposed', number=calls, tool=full_name, args=args, state=before)
                    try:
                        result = await tools.execute(full_name, args, None, prompter)
                    except UserControlledRefusal as exc:
                        after = await state()
                        emit('refused', tool=full_name, reason=str(exc), dispatches_before=before_dispatch,
                             dispatches_after=dispatches, before=before, after=after)
                        continue
                    finally:
                        inner.expected = None
                        inner.decision = Decision.DENY
                    artifact = evidence / f'{calls:02d}-{name}.txt'
                    artifact.write_text(apply_evidence(result), encoding='utf-8')
                    emit('result', number=calls, tool=full_name, result=result, artifact=str(artifact),
                         state=await state(), dispatches=dispatches, timing=binding.last_timing)
                elif action == 'reset':
                    before = await state()
                    await agent.reset()
                    await binding._drain_retired()
                    await check_ports_free()
                    emit('reset', old_state=before, epoch=binding.epoch, port_free=True,
                         old_process_gone=before is None or not Path(f"/proc/{before['pid']}").exists())
                elif action == 'queued_revoke':
                    # Hold only the controller serialization lock. An approved
                    # snapshot queues normally; revocation must prevent any RPC.
                    owner = binding.owner
                    if owner is None:
                        raise ValueError('queued revoke needs an owned paired session')
                    full_name = 'mcp_browser_browser_snapshot'
                    allowed = agent.is_tool_allowed(full_name, {})
                    if not allowed.ok:
                        raise PermissionError('Skill gate: ' + str(allowed.reason))
                    before = await state()
                    rpc_requests = 0
                    request = owner.request

                    async def observed_request(method, *args, **kwargs):
                        nonlocal rpc_requests
                        if method == 'call_tool':
                            rpc_requests += 1
                        return await request(method, *args, **kwargs)

                    owner.request = observed_request
                    await binding.lock.acquire()
                    inner.expected = full_name
                    inner.decision = Decision.ALLOW_ONCE
                    queued = asyncio.create_task(tools.execute(full_name, {}, None, prompter))
                    try:
                        async with asyncio.timeout(3):
                            while policy.active == 0:
                                if queued.done():
                                    queued.result()
                                await asyncio.sleep(0.01)
                        policy.revoke(full_name)
                        try:
                            await asyncio.wait_for(queued, 3)
                            raise RuntimeError('revoked queued operation dispatched')
                        except ExecutionBlocked as exc:
                            queued_reason = str(exc)
                    finally:
                        if not queued.done():
                            queued.cancel()
                        await asyncio.gather(queued, return_exceptions=True)
                        binding.lock.release()
                        inner.expected = None
                        inner.decision = Decision.DENY
                    try:
                        await tools.execute(full_name, {}, None, prompter)
                        raise RuntimeError('new revoked operation dispatched')
                    except ExecutionBlocked as exc:
                        new_reason = str(exc)
                    after = await state()
                    assert rpc_requests == 0 and before == after and policy.active == 0
                    emit('queued_revoke', queued_reason=queued_reason, new_reason=new_reason,
                         browser_rpc_requests=rpc_requests, before=before, after=after, policy_active=policy.active)
                elif action == 'close':
                    break
                else:
                    raise ValueError('unknown live control command')
            except Exception as exc:
                causes = []
                previous = exc.__cause__
                while previous is not None and len(causes) < 4:
                    causes.append({'kind': type(previous).__name__, 'message': apply_evidence(str(previous))[:4096]})
                    previous = previous.__cause__
                emit('error', kind=type(exc).__name__, message=str(exc), causes=causes, timing=binding.last_timing)
    finally:
        await binding.close()
        await check_ports_free()
        gone = all(not Path(f'/proc/{pid}').exists() for pid in owned_pids)
        emit('cleanup', owned_pids=sorted(owned_pids), all_processes_gone=gone,
             port_free=True, policy_active=policy.active, permission_requests=inner.asks,
             calls=calls, dispatches=dispatches)


if __name__ == '__main__':
    asyncio.run(main())
