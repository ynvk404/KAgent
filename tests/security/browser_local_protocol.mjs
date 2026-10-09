// Mock extension ONLY inside a private network/PID namespace. No real Chrome.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { WebSocket } from '/usr/local/lib/kagent-browser-mcp/0.1.3-kagent-local-v3/node_modules/ws/wrapper.mjs';

const root = '/usr/local/lib/kagent-browser-mcp/0.1.3-kagent-local-v3';
const bundle = `${root}/node_modules/@browsermcp/mcp/dist/index.js`;
const origin = 'http://juice.lab:8081';
const env = { PATH: '/usr/bin:/bin', HOME: '/tmp', KAGENT_BROWSER_LOCAL: '1' };
const watchdog = setTimeout(() => { console.error('isolated protocol deadline'); process.exit(2); }, 20000);
const child = spawn('/usr/bin/node', [bundle], { env, stdio: ['pipe', 'pipe', 'pipe'] });
const errors = [];
child.stderr.on('data', data => errors.push(data.toString()));
let nextId = 0;
const pending = new Map();
createInterface({ input: child.stdout }).on('line', line => {
  const message = JSON.parse(line);
  if (message.id !== undefined) {
    const callback = pending.get(message.id);
    pending.delete(message.id);
    callback?.(message);
  }
});
const rpc = (method, params) => new Promise(resolve => {
  const id = ++nextId;
  pending.set(id, resolve);
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
});
const once = (emitter, event) => new Promise(resolve => emitter.once(event, (...args) => resolve(args)));
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function within(promise, milliseconds) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error('operation exceeded bounded deadline')), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}
const status = async () => JSON.parse((await rpc('resources/read', { uri: 'kagent://browser/status' })).result.contents[0].text);
let currentURL = origin;
let disconnect = false;
let delayAction = false;
let delaySnapshot = false;
const operations = [];
function pair() {
  const ws = new WebSocket('ws://127.0.0.1:9009');
  ws.on('message', bytes => {
    const request = JSON.parse(bytes.toString());
    operations.push(request.type);
    if (disconnect && request.type === 'browser_type') { ws.terminate(); return; }
    if (request.type === 'browser_navigate') currentURL = request.payload.url;
    const result = request.type === 'getUrl' ? currentURL
      : request.type === 'getTitle' ? 'KAGENT-MOCK-LAB-MARKER'
      : request.type === 'browser_snapshot' ? '- button "Search" [ref=s1e1]\n- textbox [ref=s1e2]'
      : null;
    if (delayAction && request.type === 'browser_click') {
      // Wrong/stale request ID must not resolve the pending action.
      ws.send(JSON.stringify({ type: 'messageResponse', payload: { requestId: 'wrong-id', result: 'not-accepted' } }));
    }
    const delay = delayAction && request.type === 'browser_click' ? 200
      : delaySnapshot && request.type === 'browser_snapshot' ? 150 : 0;
    setTimeout(() => ws.send(JSON.stringify({ id: request.id, type: 'messageResponse', payload: { requestId: request.id, result } })), delay);
  });
  return ws;
}
const call = async (name, args, generation, snapshotGeneration = 0) =>
  (await rpc('tools/call', { name, arguments: args,
    _meta: { kagentBrowser: { origin, generation, snapshotGeneration, traceId: String(nextId + 1) } } })).result;

try {
  const initialized = await rpc('initialize', { protocolVersion: '2024-11-05', capabilities: {},
    clientInfo: { name: 'isolated-fixture', version: '1' } });
  assert.ok(initialized.result);
  child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  assert.equal((await rpc('tools/list', {})).result.tools.length, 12);
  const listener = readFileSync('/proc/net/tcp', 'utf8').split('\n').filter(row => row.includes(':2331') && row.includes(' 0A '));
  assert.equal(listener.length, 1);
  assert.ok(listener[0].includes('0100007F:2331'));

  const extension = pair();
  await once(extension, 'open');
  const state = await status();
  assert.equal(state.pid, child.pid);
  assert.equal(state.connected, true);
  const second = new WebSocket('ws://127.0.0.1:9009');
  const [closeCode] = await once(second, 'close');
  assert.equal(closeCode, 1008);
  assert.equal(extension.readyState, WebSocket.OPEN);
  assert.equal((await status()).generation, state.generation);

  const first = await call('browser_navigate', { url: origin }, state.generation);
  assert.ok(!first.isError);
  assert.ok(first.content[0].text.includes('KAGENT-MOCK-LAB-MARKER'));
  assert.equal(first._meta.kagentBrowser.snapshotGeneration, 1);
  const click = await call('browser_click', { ref: 's1e1', element: 'search' }, state.generation, 1);
  assert.ok(!click.isError);
  const count = operations.length;
  const stale = await call('browser_type', { ref: 's1e2', element: 'search', text: 'fixture', submit: false }, state.generation, 1);
  assert.ok(stale.isError);
  assert.deepEqual(operations.slice(count), ['getUrl']);
  const typed = await call('browser_type', { ref: 's1e2', element: 'search', text: 'fixture', submit: false }, state.generation, 2);
  assert.ok(!typed.isError);

  delayAction = true;
  const beforeDelayed = operations.length;
  const delayed = await call('browser_click', { ref: 's1e1', element: 'search' }, state.generation, 3);
  assert.ok(!delayed.isError);
  const actionTiming = delayed._meta.kagentBrowserTiming;
  assert.equal(actionTiming.websocket.filter(row => row.type === 'browser_click').length, 1);
  assert.equal(actionTiming.websocket.filter(row => row.type === 'browser_snapshot').length, 1);
  const action = actionTiming.websocket.find(row => row.type === 'browser_click');
  assert.ok(action.endMs - action.sentMs >= 180, JSON.stringify(actionTiming));
  assert.equal(action.outcome, 'response');
  assert.deepEqual(operations.slice(beforeDelayed), ['getUrl', 'browser_click', 'getUrl', 'getTitle', 'browser_snapshot']);
  assert.ok(!JSON.stringify(actionTiming).includes('search'));
  delayAction = false;
  delaySnapshot = true;
  const slowSnapshot = await call('browser_snapshot', {}, state.generation);
  const snapshotTiming = slowSnapshot._meta.kagentBrowserTiming.websocket.find(row => row.type === 'browser_snapshot');
  assert.ok(snapshotTiming.endMs - snapshotTiming.sentMs >= 130);
  delaySnapshot = false;

  currentURL = 'http://outside.lab:8081';
  const beforeOutside = operations.length;
  assert.ok((await call('browser_snapshot', {}, state.generation)).isError);
  assert.deepEqual(operations.slice(beforeOutside), ['getUrl']);
  currentURL = origin;
  disconnect = true;
  const lost = await within(call('browser_type', { ref: 's1e2', element: 'search', text: 'fixture', submit: false }, state.generation, 5), 3000);
  assert.ok(lost.isError && lost.content[0].text.includes('outcome unknown'));
  assert.equal(lost._meta.kagentBrowserTiming.websocket.at(-1).outcome, 'disconnect');
  await pause(30);
  const fresh = pair();
  await once(fresh, 'open');
  const reconnected = await status();
  assert.ok(reconnected.generation > state.generation);
  assert.equal(reconnected.snapshotGeneration, 0);
  const beforeOld = operations.length;
  assert.ok((await call('browser_click', { ref: 's1e1', element: 'search' }, state.generation, 3)).isError);
  assert.equal(operations.length, beforeOld);
  fresh.send(Buffer.alloc(8 * 1024 * 1024 + 1));
  const [payloadCloseCode] = await within(once(fresh, 'close'), 3000);
  // ws may deliver 1009 or an abrupt 1006 when the server's error handler
  // terminates the oversized socket before its close frame flushes.
  assert.ok([1006, 1009].includes(payloadCloseCode));
  assert.equal((await status()).connected, false);

  child.stdin.end();
  await once(child, 'exit');
  assert.equal(child.exitCode, 0, errors.join(''));
  const occupied = createServer();
  occupied.listen(9009, '127.0.0.1');
  await once(occupied, 'listening');
  const conflicting = spawn('/usr/bin/node', [bundle], { env, stdio: 'pipe' });
  const diagnostics = [];
  conflicting.stderr.on('data', data => diagnostics.push(data.toString()));
  await once(conflicting, 'exit');
  assert.notEqual(conflicting.exitCode, 0);
  assert.ok(diagnostics.join('').includes('EADDRINUSE'));
  assert.equal(occupied.listening, true);
  await new Promise(resolve => occupied.close(resolve));
  console.log(JSON.stringify({ tools: 12, loopback: true, ownership: true, noKill: true,
    connectionReplacementBlocked: true, freshRefs: true, currentURLGuard: true,
    disconnectBounded: true, payloadLimit: true, exitReleasesPort: true, timingAttribution: true,
    requestMatching: true, noDuplicateActionSnapshot: true, mockOnly: true }));
} finally {
  clearTimeout(watchdog);
  if (child.exitCode === null) child.kill();
}
