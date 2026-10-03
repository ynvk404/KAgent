"""Benign localhost regressions for the final HTTP pipeline review."""
import asyncio
import base64
import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import urlsplit

import httpx
import pytest
from src.browser.store import CaptureStore
from src.browser.redacted_view import snapshot_view
from src.engagement.state import EngagementState
from src.permission.permission import Decision
from src.target.target import Target
from src.tools.http.http_tool import HTTPTool
from src.version import VERSION
from src.workflow.state import Candidate, WorkflowState


class Approve:
    async def ask(self, request, signal=None):
        return Decision.ALLOW_ONCE


@pytest.fixture
def runtime(monkeypatch):
    wire, approved = [], []
    started, release = threading.Event(), threading.Event()
    class Receiver(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args): pass
        def do_GET(self): self.respond()
        def do_POST(self): self.respond()
        def respond(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            wire.append((self.command, self.path, [(k.lower(),v) for k,v in self.headers.items()], body))
            path = urlsplit(self.path).path
            code, headers, content = 200, {}, b'ok'
            if path.startswith('/redirect/'):
                code = int(path.rsplit('/',1)[1])
                headers = {'Location':'/final','Set-Cookie':'sid=fixture; Path=/'}
            elif path.startswith('/self/') and self.command == 'POST': code,headers = int(path.rsplit('/',1)[1]),{'Location':self.path}
            elif path == '/query-only': code,headers = 302,{'Location':'?next=1'} if not urlsplit(self.path).query else {}
            elif path == '/empty': code,headers = 302,{'Location':''}
            elif path == '/loop': code,headers = 302,{'Location':'/loop'}
            elif path == '/chain': code,headers = 302,{'Location':'?n='+str(int(urlsplit(self.path).query.split('=')[-1] or '0')+1)}
            elif path == '/cross': code,headers = 302,{'Location':'http://127.0.0.1:1/final'}
            elif path == '/bad': code,headers = 302,{'Location':'http://[broken'}
            elif path == '/gzip': headers,content = {'Content-Encoding':'gzip'},gzip.compress(b'bounded fixture')
            elif path.startswith('/secret/'):
                bodies = {'nested':b'{"token":{"value":"fixture-value"}}',
                          'number':b'{"token":123456}',
                          'escaped':b'{"to\\u006ben":"fixture-value"}'}
                headers,content={'Content-Type':'application/json'},bodies[path.rsplit('/',1)[1]]
            elif path == '/set': headers={'Set-Cookie':'sid=fixture; Path=/'}
            elif path == '/pending':
                started.set()
                release.wait(10)
                headers={'Set-Cookie':'sid=old-revision; Path=/'}
            self.send_response(code)
            for k,v in headers.items(): self.send_header(k,v)
            self.send_header('Content-Length',str(len(content)))
            self.end_headers()
            self.wfile.write(content)
    server = ThreadingHTTPServer(('127.0.0.1',0),Receiver)
    thread = threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    origin = f'http://127.0.0.1:{server.server_port}'
    target, engagement, capture, workflow = Target(origin), EngagementState(), CaptureStore(), WorkflowState()
    engagement.initialize_target(origin)
    tool = HTTPTool(target,engagement,workflow,capture)
    authorize = tool.permissions.authorize
    async def record(action,*args):
        approved.append(action)
        return await authorize(action,*args)
    monkeypatch.setattr(tool.permissions,'authorize',record)
    def candidate(body,content_type='application/json',location='body',raw=False,occurrence=None):
        headers=[('Host',f'127.0.0.1:{server.server_port}'),('Content-Type',content_type)]
        payload={'method':'POST','url':origin+'/input','requestHeaders':[{'name':k,'value':v} for k,v in headers]}
        if raw:
            head=b'POST /input HTTP/1.1\r\n'+b'\r\n'.join(k.encode()+b': '+v.encode() for k,v in headers)
            head+=b'\r\nContent-Length: '+str(len(body)).encode()
            payload['rawRequestB64']=base64.b64encode(head+b'\r\n\r\n'+body).decode()
        else: payload['requestBody']=body
        ref=capture.ingest(payload)['id']
        item,_=workflow.add_candidate(Candidate(candidate_class='sql-injection',target=origin,method='POST',endpoint='/input',parameter='q',location=location,content_type=content_type,baseline_request_ref=ref))
        return {'phase':'validation','candidate_id':item.id,'mutation_value':'new'}
    async def send(args):
        before,a_before=len(wire),len(approved)
        result=await tool.run(args,None,Approve())
        actuals,actions=wire[before:],approved[a_before:]
        assert len(actuals)==len(actions)
        for actual,action in zip(actuals,actions):
            method,path,headers,body=actual
            expected_path=urlsplit(action.url).path or '/'
            if urlsplit(action.url).query: expected_path+='?'+urlsplit(action.url).query
            assert (method,path,body)==(action.method,expected_path,action.body)
            assert headers==[(k.decode().lower(),v.decode('latin1')) for k,v in action.headers]
        return result
    yield SimpleNamespace(tool=tool,capture=capture,workflow=workflow,target=target,engagement=engagement,wire=wire,approved=approved,candidate=candidate,send=send,origin=origin,started=started,release=release)
    release.set()
    server.shutdown(); server.server_close(); thread.join(2)


@pytest.mark.asyncio
@pytest.mark.parametrize('status',[301,302,303,307,308])
async def test_redirect_wire_exact(runtime,status):
    result=await runtime.send({'phase':'recon','url':f'/redirect/{status}','method':'POST','body':'q=old','headers':{'Content-Type':'application/x-www-form-urlencoded'},'auth_context_ref':'user','max_redirects':1})
    assert len(runtime.wire)==2
    method,_,headers,body=runtime.wire[-1]
    assert method==('POST' if status in (307,308) else 'GET')
    assert body==(b'q=old' if status in (307,308) else b'')
    assert dict(headers)['cookie']=='sid=fixture'
    assert '[hop 1]' in result


@pytest.mark.asyncio
@pytest.mark.parametrize('path,expected_count',[('/query-only',2),('/empty',1),('/loop',1),('/cross',1),('/bad',1),('/chain?n=0',3)])
async def test_redirect_edges_wire_exact(runtime,path,expected_count):
    await runtime.send({'phase':'recon','url':path,'max_redirects':2})
    assert len(runtime.wire)==expected_count


@pytest.mark.asyncio
async def test_native_and_gzip_exact(runtime):
    await runtime.send({'phase':'recon','url':'/native','headers':{'Proxy-Authorization':'Basic fixture','Proxy-Connection':'close','Proxy-Authenticate':'Basic'}})
    assert dict(runtime.wire[-1][2])['user-agent']==f'KAgent/{VERSION}'
    assert not any(key.startswith('proxy-') for key,value in runtime.wire[-1][2])
    result=await runtime.send({'phase':'recon','url':'/gzip'})
    assert 'bounded fixture' in result and 'Content-Encoding: gzip' in result


@pytest.mark.asyncio
async def test_text_baselines_wire_exact(runtime):
    original=b'{ "q":"old", "keep":1e2, "unicode":"\\u00e9" }'
    await runtime.send(runtime.candidate(original.decode()))
    assert runtime.wire[-1][3]==original.replace(b'old',b'new')
    await runtime.send(runtime.candidate('user=Nguyên&q=old&x=%2f','application/x-www-form-urlencoded','form'))
    assert runtime.wire[-1][3]=='user=Nguyên&q=new&x=%2f'.encode()
    body=b'--lab\r\nContent-Disposition: form-data; name=q\r\n\r\nold\r\n--lab\r\nContent-Disposition: form-data; name=file; filename=x\r\n\r\n\x00\xff\r\n--lab--\r\n'
    await runtime.send(runtime.candidate(body,'multipart/form-data; boundary=lab',raw=True))
    assert runtime.wire[-1][3]==body.replace(b'old',b'new')


@pytest.mark.asyncio
@pytest.mark.parametrize('kind',['nested','number','escaped'])
async def test_structured_response_secrets_do_not_reach_tool_output(runtime,kind):
    result=await runtime.send({'phase':'recon','url':'/secret/'+kind})
    leaked='fixture-value' in result or '123456' in result
    assert leaked is False


@pytest.mark.asyncio
async def test_structured_json_replay_requires_raw_recapture(runtime):
    original = b'{"q":"old","n":1e0}'
    with pytest.raises(ValueError, match="original body bytes"):
        await runtime.send(runtime.candidate(json.loads(original)))
    assert runtime.approved == []
    assert runtime.wire == []


@pytest.mark.asyncio
async def test_structured_form_replay_requires_raw_recapture(runtime):
    with pytest.raises(ValueError, match="original body bytes"):
        await runtime.send(runtime.candidate(
            {'type': 'form', 'data': {'q': ['old'], 'csrf': ['keep']}},
            'application/x-www-form-urlencoded', 'form'))
    assert runtime.approved == []
    assert runtime.wire == []


@pytest.mark.asyncio
@pytest.mark.parametrize('location',['header','cookie'])
async def test_unsupported_location_stops_before_body_mutation(runtime,location):
    rejected=False
    try: await runtime.send(runtime.candidate('{"q":"old"}',location=location))
    except ValueError: rejected=True
    assert rejected is True


@pytest.mark.asyncio
async def test_multipart_binary_boundary_prefix_is_not_a_part(runtime):
    body=(b'--lab\r\nContent-Disposition: form-data; name=q\r\n\r\nfirst\r\n'
          b'--lab\r\nContent-Disposition: form-data; name=file; filename=x\r\n\r\nbinary\r\n'
          b'--labZ\r\nContent-Disposition: form-data; name=q\r\n\r\ninside-file\r\n--lab--\r\n')
    rejected=False
    try: await runtime.send(runtime.candidate(body,'multipart/form-data; boundary=lab',raw=True)|{'occurrence':1})
    except ValueError: rejected=True
    assert rejected is True


@pytest.mark.asyncio
@pytest.mark.parametrize('path',['items[0].q[','items..0.q'])
async def test_malformed_json_path_is_rejected(runtime,path):
    rejected=False
    try: await runtime.send(runtime.candidate('{"items":[{"q":"old"}]}')|{'input_path':path})
    except ValueError: rejected=True
    assert rejected is True


@pytest.mark.asyncio
async def test_agent_reset_clears_identity_credentials(runtime):
    from src.agent.agent import Agent,AgentOptions
    from src.tools.common.registry import Registry
    from src.skills.registry import Registry as SkillRegistry
    from tests.helpers.agent_fakes import FakeClient
    registry=Registry(); registry.register(runtime.tool)
    agent=Agent(AgentOptions(client=FakeClient([]),tools=registry,skills=SkillRegistry(),prompter=Approve(),store=None,target=runtime.target,engagement_state=runtime.engagement,workflow=runtime.workflow,streaming_enabled=False))
    await runtime.send({'phase':'recon','url':'/set','auth_context_ref':'user'})
    await agent.reset()
    await runtime.send({'phase':'recon','url':'/after-reset','auth_context_ref':'user'})
    stale_credential_sent='cookie' in dict(runtime.wire[-1][2])
    assert stale_credential_sent is False


@pytest.mark.asyncio
async def test_old_revision_response_cannot_repopulate_reset_context(runtime):
    task=asyncio.create_task(runtime.send({'phase':'recon','url':'/pending','auth_context_ref':'user'}))
    try:
        assert await asyncio.to_thread(runtime.started.wait,5)
        runtime.target.set_base_url(runtime.origin+'/newbase')
        runtime.tool.prepare({'phase':'recon','url':runtime.origin+'/probe','auth_context_ref':'user'})
        runtime.release.set()
        await task
        await runtime.send({'phase':'recon','url':runtime.origin+'/after-revision','auth_context_ref':'user'})
        stale_credential_sent='cookie' in dict(runtime.wire[-1][2])
        assert stale_credential_sent is False
    finally:
        runtime.release.set()
        await asyncio.gather(task,return_exceptions=True)


def test_snapshot_title_is_sanitized():
    view=snapshot_view({'url':'http://target.test','title':'http://target.test/?token=fixture-value'})
    leaked='fixture-value' in json.dumps(view)
    assert leaked is False


@pytest.mark.asyncio
@pytest.mark.parametrize('status',[302,303])
async def test_post_to_get_redirect_to_same_url_is_not_a_loop(runtime,status):
    await runtime.send({'phase':'recon','url':f'/self/{status}','method':'POST','body':'q=old','max_redirects':1})
    followed_get=len(runtime.wire)==2 and runtime.wire[-1][0]=='GET'
    assert followed_get is True


def test_xml_comment_does_not_count_as_named_element():
    from src.tools.http.request_builder import build_captured_request
    row=SimpleNamespace(method='POST',url='http://target.test/api',request_headers=[SimpleNamespace(name='Content-Type',value='application/xml')],request_body='<root><!--<q>old</q>--><q>safe</q></root>',raw_request_b64=None)
    candidate=Candidate(candidate_class='sql-injection',target='http://target.test',method='POST',endpoint='/api',parameter='q',location='raw',content_type='application/xml')
    rejected=False
    try: build_captured_request(row,candidate,'new',old_value='old')
    except ValueError: rejected=True
    assert rejected is True


def test_multiple_connection_fields_all_nominations_removed():
    from src.tools.http.request_builder import origin_headers
    headers=origin_headers([('Connection','X-One'),('Connection','X-Two'),('X-One','fixture'),('X-Two','fixture')])
    extra_forwarded=any(k.lower() in {'x-one','x-two'} for k,v in headers)
    assert extra_forwarded is False


def test_unframed_raw_body_requires_recapture():
    from src.tools.http.request_builder import build_captured_request
    raw=b'POST /api HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/json\r\n\r\n{"q":"old"}'
    row=SimpleNamespace(method='POST',url='http://target.test/api',raw_request_b64=base64.b64encode(raw).decode())
    candidate=Candidate(candidate_class='sql-injection',target='http://target.test',method='POST',endpoint='/api',parameter='q',location='body',content_type='application/json')
    rejected=False
    try: build_captured_request(row,candidate,'new')
    except ValueError: rejected=True
    assert rejected is True


def test_form_unsupported_charset_rejected():
    from src.tools.http.request_builder import build_captured_request
    row=SimpleNamespace(method='POST',url='http://target.test/api',request_headers=[SimpleNamespace(name='Content-Type',value='application/x-www-form-urlencoded; charset=iso-8859-1')],request_body='q=old&keep=%E9',raw_request_b64=None)
    candidate=Candidate(candidate_class='sql-injection',target='http://target.test',method='POST',endpoint='/api',parameter='q',location='form',content_type='application/x-www-form-urlencoded')
    rejected=False
    try: build_captured_request(row,candidate,'é')
    except ValueError: rejected=True
    assert rejected is True


def test_exact_origin_ports_and_ipv6_host_normalization():
    from src.tools.http.context import HTTPContextStore
    from src.tools.http.request_builder import validate_host
    store=HTTPContextStore(); store.sync_target(1,1)
    request=httpx.Request('GET','http://127.0.0.1:1234/input')
    store.extract(request,httpx.Response(200,headers={'Set-Cookie':'sid=fixture; Path=/'},request=request),'user')
    assert store.cookie_for(request,'user') is not None
    assert store.cookie_for(httpx.Request('GET','http://127.0.0.1:1235/input'),'user') is None
    assert store.cookie_for(httpx.Request('GET','https://127.0.0.1:1234/input'),'user') is None
    validate_host(httpx.Headers({'Host':'[::1]:80'}),'http://[::1]/input')
    with pytest.raises(ValueError): validate_host(httpx.Headers({'Host':'[::1]:81'}),'http://[::1]/input')


def test_two_identity_inputs_roundtrip_and_dedup():
    from src.workflow.state import AttackSurfaceInput, WorkflowObjective
    state=WorkflowState(objective=WorkflowObjective(id='fixture-objective', mode='whole_target', target_origin='http://target.test'))
    items=[]
    for identity in ('user','admin','user'):
        item,_=state.add_attack_surface_input(AttackSurfaceInput(objective_id='fixture-objective',target_origin='http://target.test',method='POST',endpoint='/api',parameter='q',location='body',input_type='string',baseline_request_ref='wr:'+identity,auth_context_ref=identity,source_ref='browser:fixture'))
        items.append(item)
    assert len(state.attack_surface_inputs)==2 and items[0] is items[2]
    restored=WorkflowState.from_dict(state.to_dict())
    assert {i.auth_context_ref for i in restored.attack_surface_inputs.values()}=={'user','admin'}
