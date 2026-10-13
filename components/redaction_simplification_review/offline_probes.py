"""Synthetic offline audit probes. No production mutations, sockets or provider calls.
A/B/C below are limited representation prototypes, never implemented policies.
Run from repository: PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. venv-linux/bin/python <this-file>
"""
from __future__ import annotations
import asyncio
from copy import deepcopy
import hashlib
import json
import logging
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import httpx
from src.agent.agent import safe_tool_text, format_history_for_compaction
from src.agent.context_estimate import text_tokens
from src.browser.redacted_view import request_excerpt, request_view, snapshot_view
from src.browser.store import CaptureStore
from src.engagement.state import EngagementState
from src.llm.core.types import ChatResponse, ChatRequest, FunctionCall, Message, ToolCall
from src.llm.providers.openai import OpenAIClient
from src.logger.logger import JsonFormatter
from src.memory.store import AddMemoryInput, MemoryStore
from src.permission.permission import AlwaysAllow
from src.permission.runtime.observations import ObservationStore
from src.redaction.redact import apply, apply_evidence, redact_payload, redact_request_context, http_credential_redactor
from src.session.store import Store
from src.target.target import Target
from src.tools.common.browser_capture import BrowserCaptureGetTool
from src.tools.mcp.integration import MCPTool
from src.tools.http.context import HTTPContextStore
from src.tools.http.http_tool import HTTPTool
from src.workflow.evidence import EvidenceArtifact
from tests.helpers.agent_fakes import FakeClient, FakeSignal
from tests.helpers.burp_selection import make_runtime

ORIGIN = 'https://target.example.test'
SHA = hashlib.sha256(b'public release checksum fixture').hexdigest()
JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.fixture_signature'
FIXTURES = [
    ('sqli_true', '{"rows":[{"id":1,"name":"fixture"}],"count":1}'),
    ('sqli_false', '{"rows":[],"count":0}'),
    ('sqli_error', "SQLSTATE[42000]: syntax error near ' OR 1=1 -- at line 1"),
    ('xss_reflection', '<div>REFLECT-7 <svg onload=alert(7)></div>'),
    ('marker_exact', '{"csrf_token":"{INJECTION_POINT}"}'),
    ('marker_encoded', 'password=%7BINJECTION_POINT%7D&q=REFLECT-7'),
    ('marker_compound', '{"token":"REFLECT-7-{INJECTION_POINT}"}'),
    ('auth_response', '{"token":"fixture-login-token-123456","user":{"id":7}}'),
    ('csrf_json', '{"csrf_token":"fixture-csrf-value-7","action":"transfer"}'),
    ('idor_owner1', '{"owner":1,"profile":"first","balance":10}'),
    ('idor_owner2', '{"owner":2,"profile":"second","balance":20}'),
    ('idor_only_token1', '{"token":"red"}'),
    ('idor_only_token2', '{"token":"sky"}'),
    ('jwt', JWT),
    ('authorization', 'Authorization: Basic dXNlcjpwYXNz\nkeep'),
    ('info_disclosure', '{"debug":{"password":"fixture-db-password"},"stack":"app.py:7"}'),
    ('public_sha256', 'Public SHA256: ' + SHA),
    ('html_form', '<form><input type="hidden" name="csrf_token" value="fixture-csrf-value-7"><input type="password" value="pw7"></form>'),
    ('cookie_reuse', 'Set-Cookie: sid=fixture-session-7; Path=/; HttpOnly'),
    ('encoded_replay', 'q=%3Csvg%20onload%3Dalert%287%29%3E&password=demo-pass'),
    ('token_hello', '{"token":"hello"}'),
    ('cookie_prose', 'Cookie: chocolate chip'),
    ('short_cookie_echo', 'color=blue&sid=blue'),
    ('malformed_json', '{"token":"hello"'),
]
HEADERS = [('Cookie', 'sid=blue'), ('Authorization', 'Bearer fixture-header-secret-123456')]


def prototype_a_body(body: str) -> str:
    """Partial A: no blanket digest masking; skip short known-credential echoes.
    Keeps existing key/prose masks; does NOT solve token/cookie ambiguity.
    """
    values = ['fixture-header-secret-123456', 'Bearer fixture-header-secret-123456']
    for value in sorted(values, key=len, reverse=True):
        body = body.replace(value, '[REDACTED]')
    return apply(body)


def capture_row(body: str) -> dict:
    return {'url': ORIGIN + '/search', 'method': 'GET', 'response_body': body,
            'request_headers': [{'name': k, 'value': v} for k, v in HEADERS],
            'response_headers': [{'name':'Set-Cookie','value':'sid=blue'}],
            'request_body':'q={INJECTION_POINT}'}


def measurements():
    rows = []
    for name, raw in FIXTURES:
        view = request_excerpt(capture_row(raw))
        agent_json = safe_tool_text(json.dumps(view), 'UNAVAILABLE')
        try:
            body_after = json.loads(agent_json)['response_body']
            parse_error = None
        except json.JSONDecodeError as error:
            body_after = '[INVALID JSON ENVELOPE]'
            parse_error = str(error)
        pretty_envelope=safe_tool_text(json.dumps(view, indent=2), 'UNAVAILABLE')
        pretty_body=json.loads(pretty_envelope)['response_body']
        versions = {'native_current': apply_evidence(raw),
                    'capture_replay_current': http_credential_redactor(HEADERS)(raw),
                    'capture_view_current': view['response_body'],
                    'agent_capture_current': pretty_body,
                    'A_partial_prototype': prototype_a_body(raw),
                    'B_target_body_prototype': raw,
                    'C_raw_prototype': raw}
        rows.append({'name':name, 'raw':raw, 'outputs':versions, 'compact_agent_envelope':agent_json, 'compact_envelope_parse_error':parse_error, 'pretty_agent_envelope':pretty_envelope,
                     'metrics':{key:{'exact':value==raw,'chars':len(value),'utf8_bytes':len(value.encode()),
                                     'estimated_text_tokens':text_tokens(value),
                                     'marker_exact_preserved':'{INJECTION_POINT}' in value if '{INJECTION_POINT}' in raw else None,
                                     'marker_encoded_preserved':'%7BINJECTION_POINT%7D' in value if '%7BINJECTION_POINT%7D' in raw else None}
                                for key,value in versions.items()}})
    by_name = {row['name']:row for row in rows}
    pairs = [('sqli_true','sqli_false'),('idor_owner1','idor_owner2'),('idor_only_token1','idor_only_token2')]
    comparisons = {a+' / '+b:{key:by_name[a]['outputs'][key]!=by_name[b]['outputs'][key]
                            for key in by_name[a]['outputs']} for a,b in pairs}
    totals = {key:{'exact_fixtures':sum(row['metrics'][key]['exact'] for row in rows),
                   'estimated_text_tokens':sum(row['metrics'][key]['estimated_text_tokens'] for row in rows),
                   'utf8_bytes':sum(row['metrics'][key]['utf8_bytes'] for row in rows)}
              for key in rows[0]['outputs']}
    return {'fixtures':rows, 'pair_distinguishable':comparisons,'totals':totals, 'compact_invalid_envelopes':[r['name'] for r in rows if r['compact_envelope_parse_error']]}


async def integration(tmp: Path):
    results = {}
    # Real Agent and CaptureGet -> two FakeClient requests (no external LLM).
    for case, body in [('json','{"token":"hello"}'),('html','<input type="password" value="pw7">'),('cookie_prose','Cookie: chocolate chip')]:
        root = tmp / case; root.mkdir()
        client=FakeClient([
            ChatResponse(Message('assistant','',tool_calls=[ToolCall('capture',FunctionCall('browser_capture_get',json.dumps({'id':'fixture'})))]),'tool_calls'),
            ChatResponse(Message('assistant','Read fixture.'),'stop')])
        with patch('src.agent.tool_results.project_root', return_value=root):
            runtime=make_runtime(root,client,origin=ORIGIN)
            receipt=runtime.capture.ingest({'kind':'burp','id':'fixture','url':ORIGIN+'/capture', 'respBody':body})
            client.scripted[0].message.tool_calls[0].function.arguments=json.dumps({'id':receipt['id']})
            events=[]
            await runtime.agent.run('Read captured fixture',FakeSignal(),events.append)
            assert len(client.requests)==2
            message=next(m for m in client.requests[1].messages if m.name=='browser_capture_get')
            out=json.loads(message.content)
            result_event=next(e for e in events if getattr(e,'type',None)=='tool-result')
            await runtime.agent.save()
            saved=next(m for m in runtime.store.load().messages if m.name=='browser_capture_get' and m.role=='tool')
            results[case]={'raw_body':body,'next_llm_body':out['response_body'],'next_llm_alias':out['responseBody'],
                           'event_equals_llm':result_event.result==message.content,'resumed_body':json.loads(saved.content)['response_body'],
                           'compaction':format_history_for_compaction([message]),
                           'encoded_provider_body':OpenAIClient('https://provider.example.test',model='fixture').encode_request(client.requests[1],False)['messages'][
                               client.requests[1].messages.index(message)]['content']}
            runtime.agent.result_retention.pending.clear()
    # Production generic MCP result adapter with an in-memory RPC double only.
    mcp_cases={}
    for name,body in [('json','{"token":"hello"}'),('cookie','Cookie: chocolate chip')]:
        capture=CaptureStore(); receipt=capture.ingest({'kind':'burp','url':ORIGIN+'/capture','respBody':body})
        text=await BrowserCaptureGetTool(capture).run({'id':receipt['id']})
        session=SimpleNamespace(server_name='offline-fixture',call_tool=AsyncMock(return_value={'isError':False,'content':[{'type':'text','text':text}]}))
        adapter=MCPTool(session,'mcp_fixture','browser_capture_get','fixture',{'type':'object','properties':{}})
        raw=await adapter.run({})
        safe=safe_tool_text(raw,'UNAVAILABLE')
        try:
            parsed=json.loads(safe)
            inner=json.loads(parsed[0]['text'])
            mcp_cases[name]={'outer_parse_ok':True,'inner_parse_ok':True,'body':inner['response_body']}
        except (ValueError,KeyError,TypeError) as error:
            mcp_cases[name]={'parse_error':str(error),'adapter_output':raw,'agent_output':safe}
    results['mcp_adapter']=mcp_cases
    # Native HTTP real execution -> mocked send only; gate is bypassed only in this synthetic probe.
    target=Target(ORIGIN); engagement=EngagementState(); engagement.initialize_target(ORIGIN)
    tool=HTTPTool(target,engagement); observations=ObservationStore(); tool.evidence_store=observations
    sent=[]
    async def fake_send(client,request,**kwargs):
        sent.append({'url':str(request.url),'body':request.content.decode(),'cookie':request.headers.get('cookie')})
        return httpx.Response(200,headers={'Content-Type':'application/json','Set-Cookie':'sid=fixture-session-7; Path=/; Secure'},
                              content=b'{"token":"hello","color":"blue"}',request=request)
    with patch('src.tools.http.http_tool.httpx.AsyncClient.send',new=fake_send), patch('src.tools.http.http_tool.gate_private_request',new=AsyncMock(return_value='')):
        output=await tool.run({'phase':'recon','url':ORIGIN+'/login','method':'POST','body':'password=demo-pass'},FakeSignal(),AlwaysAllow())
    observation=next(iter(observations._items.values()))
    results['native_http']={'sent':sent,'tool_result':str(output),'observation_body':observation.body.decode(),
                            'response_hash':observation.response_hash,
                            'raw_hash_matches':observation.response_hash==hashlib.sha256(b'{"token":"hello","color":"blue"}').hexdigest()}
    # Independent cookie jar contract, local only.
    context=HTTPContextStore(); context.sync_target(1,1,'fixture-epoch')
    req=httpx.Request('GET',ORIGIN+'/login')
    resp=httpx.Response(200,headers={'Set-Cookie':'sid=blue; Path=/; Secure'},request=req)
    context.extract(req,resp,'identity1',generation=(1,1,'fixture-epoch'))
    again=httpx.Request('GET',ORIGIN+'/account'); context.add_identity(again,'identity1')
    other=httpx.Request('GET','https://other.example.test/account'); context.add_identity(other,'identity1')
    results['cookie_context']={'same_origin':again.headers.get('cookie'),'other_origin':other.headers.get('cookie'),
                              'other_identity':context.cookie_for(again,'identity2')}
    assert results['cookie_context']=={'same_origin':'sid=blue','other_origin':None,'other_identity':None}
    context.sync_target(2,1,'fixture-epoch')
    results['cookie_context']['after_revision']=context.cookie_for(again,'identity1')
    # ObservationStore truncation/integrity not altered: use current public capture.
    obs=ObservationStore(); obs.attach_storage(tmp/'observations.json')
    action=SimpleNamespace(epoch='fixture-epoch',method='GET',url=ORIGIN,transport_address='fixture',digest='fixture',response_cap=65536)
    oid=obs.capture(action,200,('Public SHA256: '+SHA).encode(),complete=True)
    reloaded=ObservationStore(); reloaded.attach_storage(tmp/'observations.json')
    results['observation']={'retained':obs._items[oid].body.decode(),'resume_exact':reloaded._items[oid].body==obs._items[oid].body,
                            'raw_response_hash':obs._items[oid].response_hash,'retained_hash':obs._items[oid].retained_hash}
    # Evidence normal snapshot and binary exception; no TOCTOU experiments.
    proofs={}
    for name,data in [('public',('Public SHA256: '+SHA).encode()),('text',b'{"token":"hello"}'),('binary',b'\xff{"token":"hello"}')]:
        path=tmp/(name+'.proof'); path.write_bytes(data)
        artifact=EvidenceArtifact.capture_immutable_snapshot('synthetic-candidate',path.name,tmp)
        stored=(tmp/artifact.path).read_bytes()
        proofs[name]={'raw_hex':data.hex(),'stored_hex':stored.hex(),'exact':data==stored,'sha256':artifact.sha256,
                      'hash_matches_stored':artifact.sha256==hashlib.sha256(stored).hexdigest(),'raw_hash_matches':artifact.sha256==hashlib.sha256(data).hexdigest()}
    results['evidence']=proofs
    # Response aliases double body representation; estimators are heuristic.
    big='a'*60000
    for name,body in [('tiny','{"token":"hello"}'),('large',big),('large_token',json.dumps({'token':'a'*60000})),('checksum','Public SHA256: '+SHA)]:
        serialized=json.dumps(request_excerpt(capture_row(body),65536),ensure_ascii=False)
        current=redact_payload(serialized)
        b=json.dumps(request_excerpt(capture_row(body),65536),ensure_ascii=False)
        results.setdefault('context_cost',{})[name]={'raw_body_bytes':len(body.encode()),'current_envelope_bytes':len(current.encode()),
                                                   'B_envelope_bytes':len(b.encode()),'current_text_token_estimate':text_tokens(current),
                                                   'B_text_token_estimate':text_tokens(b)}
    record=logging.LogRecord('kagent',logging.INFO,'fixture',1,'Cookie: chocolate chip',(),None)
    b=request_excerpt(capture_row('{"token":"hello"}'))
    c=deepcopy(capture_row('{"token":"hello"}'))
    results['prototype_boundaries']={'B_request_headers':b['request_headers'],'C_request_headers':c['request_headers'],
                                    'B_response_body':b['response_body'],'C_response_body':c['response_body']}
    results['short_cookie_request_view']=request_view({'url':ORIGIN+'/search?color=blue','request_headers':[{'name':'Cookie','value':'sid=blue'}],
                                                     'request_body':'color=blue'})
    echo='echo fixture-header-secret-123456 and color=blue'
    results['credential_echo']={'ordinary':apply_evidence(echo),'captured':http_credential_redactor(HEADERS)(echo)}
    results['logger_prose']=json.loads(JsonFormatter().format(record))['message']
    results['request_context_malformed']=redact_request_context('q=REFLECT-7','application/json')
    results['snapshot']=snapshot_view({'url':ORIGIN,'local_storage':{'theme':'blue','csrf_token':'fixture'},'document_cookie':'sid=blue'})
    # Memory explicit description is a separate unsanitized metadata field.
    memory=MemoryStore(str(tmp/'memory-project'),str(tmp/'memory-user'))
    fact=memory.add(AddMemoryInput(text='Reusable fixture fact.',description='token=fixture-description-secret-123456',scope='project'))
    results['memory_description']={'stored_description':fact.description if fact else None}
    return results


def main():
    with tempfile.TemporaryDirectory(prefix='kagent-redaction-probes-') as directory:
        result={'kind':'offline synthetic measurements; A/B/C representation-only prototypes',
                'measurements':measurements(),'integration':asyncio.run(integration(Path(directory)))}
    rows={r['name']:r for r in result['measurements']['fixtures']}
    assert rows['token_hello']['outputs']['agent_capture_current']=='{"token":"[REDACTED]"}'
    assert rows['public_sha256']['outputs']['native_current']!=rows['public_sha256']['raw']
    assert rows['public_sha256']['outputs']['agent_capture_current']==rows['public_sha256']['raw']
    assert rows['short_cookie_echo']['outputs']['capture_replay_current']=='color=[REDACTED]&[REDACTED]'
    assert set(r['name'] for r in rows.values() if r['compact_envelope_parse_error'])=={'cookie_prose','cookie_reuse'}
    assert not result['measurements']['pair_distinguishable']['idor_only_token1 / idor_only_token2']['native_current']
    assert result['integration']['json']['next_llm_body']=='{"token":"[REDACTED]"}'
    assert result['integration']['html']['next_llm_body']==result['integration']['html']['raw_body']
    assert result['integration']['native_http']['raw_hash_matches']
    assert result['integration']['evidence']['binary']['exact']
    assert result['integration']['observation']['resume_exact']
    out=Path(__file__).with_name('probe-results.json')
    out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'output':str(out),'totals':result['measurements']['totals'],
                      'pairs':result['measurements']['pair_distinguishable'],
                      'agent':{k:{f:v for f,v in result['integration'][k].items() if f in {'raw_body','next_llm_body','resumed_body'}} for k in ('json','html')},
                      'cookie_context':result['integration']['cookie_context']},ensure_ascii=False,indent=2))

if __name__=='__main__': main()
