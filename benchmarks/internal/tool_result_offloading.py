"""Offline measurements of the real Agent/store/adapter path (no model API).

Run: venv-linux/bin/python -m benchmarks.internal.tool_result_offloading
The baseline disables ONLY Phase B admission and its schema. Both sides use
current Phase A guard, actual FileReadTool execution, session saves, compaction
and resume. Requests are captured before mutable history can alter them.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import time
from typing import Any

from src.agent.agent import (Agent, AgentOptions, COMPACTION_SYSTEM_PROMPT,
                             approximate_message_tokens, ensure_system_prompt)
from src.agent.tool_results import reference_header
from src.engagement.state import EngagementState
from src.llm.core.types import ChatRequest, ChatResponse, Message, ToolCall, FunctionCall
from src.llm.providers.openai import OpenAIClient
from src.permission.permission import AlwaysAllow, YoloPrompter
from src.permission.runtime.execution import default_execution_policy
from src.session.store import Store
from src.skills.registry import Registry as Skills
from src.skills.load_skill import LoadSkillTool
from src.target.target import Target
from src.tools.common.registry import Registry
from src.tools.common.permission_status import PermissionStatusTool
from src.tools.execution.file import FileReadTool
from src.tools.execution.shell import ShellTool
from src.tools.execution.search import GrepTool, GlobTool
from src.tools.http.http_tool import HTTPTool
from src.tools.http.web import WebFetchTool, WebSearchTool
from src.tools.workflow.workflow_tool import WorkflowTool
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.agent.test_output_pipeline import source


class OfflineClient(FakeClient):
    def __init__(self):
        super().__init__([])
        self.compaction_chars: list[int] = []
        self.normal_requests: list[ChatRequest] = []

    async def chat(self, request: ChatRequest, signal=None) -> ChatResponse:
        self.requests.append(deepcopy(request))
        if request.messages[0].content == COMPACTION_SYSTEM_PROMPT:
            self.compaction_chars.append(sum(len(msg.content) for msg in request.messages))
            return ChatResponse(Message(role='assistant', content='## Current objective\n- Continue offline output inspection'), 'stop')
        self.normal_requests.append(deepcopy(request))
        response = self.scripted[self.idx]
        self.idx += 1
        return response


ENCODER = OpenAIClient('https://unused.invalid', model='offline-fixture')


def request_size(request: ChatRequest) -> dict[str, int]:
    body = ENCODER.encode_request(request, False)
    encoded = json.dumps(body, ensure_ascii=False)
    tools = len(json.dumps(request.tools, ensure_ascii=False)) // 4 if request.tools else 0
    return {'approx_tokens': approximate_message_tokens(request.messages) + tools,
            'wire_chars':len(encoded), 'wire_bytes':len(encoded.encode())}


def create(root: Path, enabled: bool, client: OfflineClient, *, core: bool, threshold=16000) -> Agent:
    state = EngagementState()
    target = Target('https://target.test')
    prompter = YoloPrompter(AlwaysAllow(), False)
    prompter.bind_execution_policy(default_execution_policy(state, root))
    tools = Registry()
    skills = Skills()
    for tool in (FileReadTool(), ShellTool(), GrepTool()): tools.register(tool)
    if core:
        for tool in (GlobTool(), HTTPTool(target, state), WebFetchTool(state, target), WebSearchTool(),
                     PermissionStatusTool(), LoadSkillTool(skills)):
            tools.register(tool)
    agent = Agent(AgentOptions(client=client,tools=tools,skills=skills,prompter=prompter,
        target=target,store=Store.new_with_id(root/'sessions','offline'), prompt_profile='compact',
        engagement_state=state,auto_compact_threshold=threshold))
    if core: tools.register(WorkflowTool(agent.workflow))
    if not enabled:
        agent.result_retention.store = None
        agent.tools.tools.pop('read_tool_result')
    return agent


async def measure(root: Path, enabled: bool, batches: list[list[int]], *, core=False,
                  near=False, relaxed=False, failure='') -> dict[str, Any]:
    root.mkdir()
    client = OfflineClient()
    agent = create(root, enabled, client, core=core, threshold=64000 if relaxed else 16000)
    events: list[Any] = []
    if near:
        baseline = approximate_message_tokens(agent.history) + agent.tools_token_estimate()
        background = max(0, (agent.auto_compact_threshold - baseline - 1600) * 4)
        agent.history.extend([Message(role='user',content='previous offline request'),
                              Message(role='assistant',content='b'*background)])
    if enabled and failure == 'quota':
        assert agent.result_retention.store is not None
        agent.result_retention.store.per_session = 1
    if enabled and failure == 'write':
        assert agent.result_retention.store is not None
        def broken(*args, **kwargs): raise OSError('offline injected write failure')
        agent.result_retention.store.put = broken
    adapter_chars: list[int] = []
    immediate_chars: list[int] = []
    immediate_anchors: list[dict[str, bool]] = []
    offloaded_gap_omitted: list[bool] = []
    first_followup: list[dict[str,int]] = []
    for turn, batch in enumerate(batches):
        calls = []
        for index, kib in enumerate(batch):
            text = source(kib*1024)
            # Gap is deliberately away from all five preview anchors.
            pos = len(text)*2//5
            text = text[:pos] + 'GAP-EVIDENCE' + text[pos+11:]
            text += '\nAuthorization: Bearer offline-synthetic-secret-123456789\n'
            path = root / f'fixture-{turn}-{index}.txt'
            path.write_text(text)
            adapter_chars.append(len(text))
            calls.append(ToolCall(f'call-{turn}-{index}', FunctionCall('file_read',json.dumps({'path':str(path)}))))
        client.scripted.extend([ChatResponse(Message(role='assistant',content='',tool_calls=calls),'tool_calls'),
                                ChatResponse(Message(role='assistant',content='offline inspection complete'),'stop')])
        first = len(client.normal_requests)
        await agent.run('inspect offline output',FakeSignal(),events.append)
        followup = client.normal_requests[first+1]
        first_followup.append(request_size(followup))
        immediate_chars.extend(len(msg.content) for msg in followup.messages if msg.role=='tool' and msg.tool_call_id in {call.id for call in calls})
        for msg in followup.messages:
            if msg.role == 'tool' and msg.tool_call_id in {call.id for call in calls}:
                immediate_anchors.append({part:part+'-CANARY' in msg.content for part in ('HEAD','MID','TAIL')})
                if msg.tool_result_refs:
                    offloaded_gap_omitted.append('GAP-EVIDENCE' not in msg.content)
    await agent.save()
    session_bytes = agent.store.path.stat().st_size if agent.store else 0
    results = list(agent.result_retention.references.values())
    artifacts = list((root/'.kagent/tool-results').rglob('*.result'))
    artifact_bytes = sum(path.stat().st_size for path in artifacts)
    snapshot_bytes = sum(path.stat().st_size for path in (root/'context').glob('*.md'))
    actual_events = [event for event in events if event.type=='tool-result']
    sanitized_chars = [len(event.result) for event in actual_events]
    agent.rebuild_system_prompt()
    agent.history = ensure_system_prompt(agent.history, agent.sys_prompt)
    preturn = agent.approx_tokens() + agent.tools_token_estimate() + len('continue offline inspection')//4
    client.scripted.append(ChatResponse(Message(role='assistant',content='continued offline'),'stop'))
    first = len(client.normal_requests)
    await agent.run('continue offline inspection',FakeSignal(),events.append)
    next_request = request_size(client.normal_requests[first])
    await agent.save()
    resumed_client = OfflineClient()
    resumed = create(root,enabled,resumed_client,core=core,threshold=64000 if relaxed else 16000)
    resumed.resume_saved()
    resumed_client.scripted.append(ChatResponse(Message(role='assistant',content='resumed offline'),'stop'))
    await resumed.run('continue after offline resume',FakeSignal(),lambda _:None)
    resume_request = request_size(resumed_client.normal_requests[-1])
    reread = None
    gap = None
    if results:
        ref = results[-1]
        # Actual retained payload position derives from the requested fixture.
        start = batches[-1][-1]*1024*2//5
        started = time.perf_counter()
        returned = await resumed.tools.execute('read_tool_result',{
            'result_ref':ref.result_ref,'start_char':start,'max_chars':128},FakeSignal(),resumed.prompter)
        gap = 'GAP-EVIDENCE' in json.loads(returned)['content']
        reread = {'reply_chars':len(returned),'approx_reply_tokens':len(returned)//4,
                  'local_elapsed_ms':round((time.perf_counter()-started)*1000,3),
                  'argument_chars':len(json.dumps({'result_ref':ref.result_ref,'start_char':start,'max_chars':128})),
                  'tool_calls':1}
    anchors = {part:all(row[part] for row in immediate_anchors) for part in ('HEAD','MID','TAIL')}
    reader = agent.tools.get('read_tool_result')
    reader_spec = next((spec for spec in agent.tools.as_llm_tools() if isinstance(spec,dict) and spec['function']['name']=='read_tool_result'), None)
    schema_chars = len(json.dumps(reader_spec,ensure_ascii=False)) if reader else 0
    # Session size before next-turn compaction is deliberately separate from
    # disk after next-turn/resume, whose snapshots can also cost storage.
    return {'adapter_retained_chars':adapter_chars,'sanitized_chars':sanitized_chars,
        'immediate_llm_chars':immediate_chars,'immediate_requests':first_followup,
        'pre_turn_trigger_tokens':preturn,'next_turn_request':next_request,
        'resume_request':resume_request,'auto_compactions':len(client.compaction_chars),
        'compaction_input_chars':client.compaction_chars,'session_json_bytes_before_next_turn':session_bytes,
        'artifact_bytes':artifact_bytes,'total_disk_bytes_before_next_turn':session_bytes+artifact_bytes+snapshot_bytes,
        'context_snapshot_bytes_before_next_turn':snapshot_bytes,
        'reference_metadata_chars':sum(len(json.dumps(asdict(ref))) for ref in results),
        'preview_envelope_chars':sum(len(reference_header(ref)) for ref in results),
        'read_schema_chars':schema_chars,'read_schema_approx_tokens':schema_chars//4,
        'reread':reread,'gap_retrieved':gap,'gap_omitted_in_offloaded_previews':offloaded_gap_omitted,
        'anchor_survival':anchors,'anchor_survival_per_result':immediate_anchors,
        'midturn_reductions':[event.summary for event in events if event.type=='decision' and 'context guard' in event.summary],
        'residual_pressure':[event.summary for event in events if event.type=='decision' and 'unresolved pressure' in event.summary],
        'core_inventory':agent.tools.names()}


async def main() -> None:
    cases = {f'{kib}KiB':([[kib]],{}) for kib in (4,10,40,100)}
    cases.update({'multiple_3x40KiB':([[40,40,40]],{}), 'sequential_3x40KiB':([[40],[40],[40]],{}),
        'core_inventory_40KiB':([[40]],{'core':True}), 'near_limit_10KiB':([[10]],{'near':True}),
        'core_inventory_100KiB':([[100]],{'core':True}),
        'relaxed_100KiB':([[100]],{'relaxed':True}), 'quota_fallback_100KiB':([[100]],{'failure':'quota'}),
        'write_fallback_100KiB':([[100]],{'failure':'write'})})
    rows = {}
    with tempfile.TemporaryDirectory(prefix='kagent-offline-b-') as temporary:
        base = Path(temporary)
        for name,(batches,options) in cases.items():
            rows[name] = {}
            for enabled in (False,True):
                rows[name]['phase_b' if enabled else 'phase_a'] = await measure(
                    base/f'{name}-{int(enabled)}',enabled,batches,**options)
    print(json.dumps({'method':'real Agent.run + FileReadTool + current Phase A guard; offline scripted model, no API',
                      'threshold_tokens':16000,'rows':rows},ensure_ascii=False,indent=2))


if __name__ == '__main__': asyncio.run(main())
