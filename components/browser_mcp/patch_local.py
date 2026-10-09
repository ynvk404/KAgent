"""Small, deterministic patch of the reviewed 0.1.3 bundle; no dependency build."""
from __future__ import annotations

import hashlib

PATCH_ID = 'kagent-local-v2'
UPSTREAM_BUNDLE_SHA256 = 'f391bfe0a8185e7551dfe70f129019b8eb786857fc1e8390edaa6ae3ad27ecfc'


def patch_bundle(bundle: bytes) -> bytes:
    if hashlib.sha256(bundle).hexdigest() != UPSTREAM_BUNDLE_SHA256:
        raise ValueError('patch requires exact reviewed upstream bundle')
    source = bundle.decode()

    def replace(old: str, new: str) -> None:
        nonlocal source
        if source.count(old) != 1:
            raise ValueError('patch hunk does not match exactly once')
        source = source.replace(old, new)

    replace('ws.removeEventListener("close", cleanup);', 'ws.removeEventListener("close", closeHandler);')
    replace('ws.addEventListener("close", cleanup);', '''const closeHandler = () => {
        cleanup();
        reject(new Error("Browser disconnected; outcome unknown if action started"));
      };
      ws.addEventListener("close", closeHandler);''')
    replace('''    const message = JSON.parse(event.data.toString());''', '''    let message;
    try { message = JSON.parse(event.data.toString()); }
    catch { ws.close(1007, "Invalid JSON"); return; }
    if (!message || typeof message !== "object" || !message.payload) return;''')
    replace('''  _ws;
  get ws() {
    if (!this._ws) {''', '''  _ws;
  activeSocket;
  scopeOrigin;
  generation = 0;
  snapshotGeneration = 0;
  refs = new Set();
  get ws() {
    const socket = this.activeSocket || this._ws;
    if (!socket || socket.readyState !== WebSocket.OPEN) {''')
    replace('''    return this._ws;
  }
  set ws(ws) {
    this._ws = ws;
  }''', '''    return socket;
  }
  set ws(ws) {
    this._ws = ws;
    this.generation++;
    this.snapshotGeneration = 0;
    this.refs.clear();
  }''')
    replace('''    await this._ws.close();''', '''    this._ws.terminate();
    this.ws = undefined;''')
    start = source.index('// src/utils/port.ts')
    end = source.index('// src/server.ts', start)
    source = source[:start] + '''// KAgent patch: never kill/adopt a process on a numbered port.
async function createWebSocketServer(port = mcpConfig.defaultWsPort) {
  const wss = new WebSocketServer({ host: "127.0.0.1", port, maxPayload: 8 * 1024 * 1024 });
  await new Promise((resolve, reject) => {
    wss.once("listening", resolve);
    wss.once("error", reject);
  });
  return wss;
}

''' + source[end:]
    replace('''  const wss = await createWebSocketServer();
  wss.on("connection", (websocket) => {
    if (context.hasWs()) {
      context.ws.close();
    }
    context.ws = websocket;
  });''', '''  // Discovery never opens a host listener or pairs with an extension.
  const wss = process.env.KAGENT_BROWSER_DISCOVERY === "1" ? null : await createWebSocketServer();
  wss?.on("connection", (websocket) => {
    if (context.hasWs()) {
      websocket.close(1008, "Browser connection already owned");
      const deadline = setTimeout(() => websocket.terminate(), 250);
      deadline.unref();
      return;
    }
    context.ws = websocket;
    websocket.on("error", () => websocket.terminate());
    websocket.on("close", () => {
      if (context._ws === websocket) context.ws = undefined;
    });
  });
  const status = () => ({
    pid: process.pid, listening: !!wss, connected: context.hasWs(),
    generation: context.generation, snapshotGeneration: context.snapshotGeneration
  });
  const statusURI = "kagent://browser/status";''')
    replace('''    return { resources: resources2.map((resource) => resource.schema) };''', '''    return { resources: [
      ...resources2.map((resource) => resource.schema),
      { uri: statusURI, name: "KAgent Browser connection state", mimeType: "application/json" }
    ] };''')
    replace('''      const result = await tool.handle(context, request.params.arguments);
      return result;''', '''      const meta = request.params._meta?.kagentBrowser;
      if (process.env.KAGENT_BROWSER_LOCAL === "1") {
        if (!meta || typeof meta.origin !== "string" ||
            !["http:", "https:"].includes(new URL(meta.origin).protocol) ||
            new URL(meta.origin).origin !== meta.origin ||
            meta.generation !== context.generation) {
          throw new Error("Blocked: missing/stale controller Browser binding");
        }
        context.activeSocket = context.ws;
        context.scopeOrigin = meta.origin;
        if (request.params.name === "browser_navigate") {
          if (new URL(request.params.arguments.url).origin !== meta.origin)
            throw new Error("Blocked: navigate outside controller origin");
        } else {
          // Current metadata from the selected extension tab, never last-known URL.
          const url = await context.sendSocketMessage("getUrl", undefined);
          if (new URL(url).origin !== meta.origin)
            throw new Error("Blocked: current browser tab outside controller origin");
          const ref = request.params.arguments?.ref;
          if (ref !== undefined && (meta.snapshotGeneration !== context.snapshotGeneration ||
              !context.refs.has(ref)))
            throw new Error("Blocked: stale ref; obtain a new snapshot");
        }
      }
      const result = await tool.handle(context, request.params.arguments);
      return { ...result, _meta: { kagentBrowser: status() } };''')
    replace('''        isError: true
      };
    }
  });
  server.setRequestHandler(ReadResourceRequestSchema''', '''        isError: true,
        _meta: { kagentBrowser: status() }
      };
    } finally {
      context.activeSocket = undefined;
      context.scopeOrigin = undefined;
    }
  });
  server.setRequestHandler(ReadResourceRequestSchema''')
    replace('''    const resource = resources2.find(''', '''    if (request.params.uri === statusURI)
      return { contents: [{ uri: statusURI, mimeType: "application/json", text: JSON.stringify(status()) }] };
    const resource = resources2.find(''')
    replace('''  server.close = async () => {
    await server.close();
    await wss.close();
    await context.close();
  };''', '''  const originalClose = server.close.bind(server);
  let closing;
  server.close = () => closing ||= (async () => {
    await context.close();
    for (const socket of wss?.clients || []) socket.terminate();
    if (wss) await new Promise((resolve) => wss.close(resolve));
    await originalClose();
  })();''')
    replace('''  const snapshot2 = await context.sendSocketMessage("browser_snapshot", {});
  return {''', '''  const snapshot2 = await context.sendSocketMessage("browser_snapshot", {});
  context.snapshotGeneration++;
  context.refs = new Set([...String(snapshot2).matchAll(/\\[ref=([^\\]\\s]+)\\]/g)].map(m => m[1]));
  return {''')
    replace('''  const url = await context.sendSocketMessage("getUrl", void 0);
  const title''', '''  const url = await context.sendSocketMessage("getUrl", void 0);
  if (context.scopeOrigin && new URL(url).origin !== context.scopeOrigin)
    throw new Error("Blocked: page changed origin before snapshot; outcome unknown if action started");
  const title''')
    replace('''    setTimeout(() => process.exit(0), 15e3);''', '''    const deadline = setTimeout(() => process.exit(0), 1000);
    deadline.unref();''')
    return source.encode()
