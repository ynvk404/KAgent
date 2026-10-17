"""Small HTTP/1 lab with an independent wire ledger; no database or eval.

All data is synthetic. Routes model observable behavior, not real exploits.
The server owns and joins every connection task, including held responses.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx


@dataclass
class LocalLab:
    server: asyncio.Server | None = None
    address: tuple[str, int] = ("127.0.0.1", 0)
    wire: list[dict[str, Any]] = field(default_factory=list)
    tasks: set[asyncio.Task] = field(default_factory=set)
    writers: set[asyncio.StreamWriter] = field(default_factory=set)
    entered: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    errors: list[str] = field(default_factory=list)
    failures_left: int = 0
    process_check: Any = field(default=lambda *args: False)

    @property
    def origin(self) -> str:
        return f"http://{self.address[0]}:{self.address[1]}"

    async def start(self) -> None:
        self.server = await asyncio.start_server(self.handle, *self.address, limit=65536)
        self.address = self.server.sockets[0].getsockname()

    async def ready(self) -> None:
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.get(self.origin + "/ready", timeout=2)
            assert response.status_code == 200 and response.text == "ready"

    async def close(self) -> None:
        assert self.server is not None
        self.server.close()
        for task in tuple(self.tasks):
            task.cancel()
        await asyncio.gather(*tuple(self.tasks), return_exceptions=True)
        await self.server.wait_closed()
        assert not self.tasks and not self.writers
        assert not self.errors, self.errors

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        assert task is not None
        self.tasks.add(task)
        self.writers.add(writer)
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
            lines = head.decode("latin1").split("\r\n")
            method, path, _ = lines[0].split(" ", 2)
            headers = dict(line.split(": ", 1) for line in lines[1:] if ": " in line)
            size = int(next((v for k, v in headers.items() if k.lower() == "content-length"), "0"))
            assert 0 <= size <= 65536
            request_body = await reader.readexactly(size)
            url = urlsplit(path)
            params = parse_qs(url.query if method == "GET" else request_body.decode())
            status, body, media, extra = self.render(url.path, params, headers)
            row = {"method": method, "url": self.origin + path, "body": request_body.decode(),
                   "status": status, "response": body, "headers": headers}
            if url.path != "/ready":
                self.wire.append(row)
            if url.path == "/slow":
                self.entered.set()
                await self.release.wait()
            response = (f"HTTP/1.1 {status} Lab\r\nContent-Type: {media}\r\n"
                        f"Content-Length: {len(body)}\r\nServer: m1-fixture\r\nConnection: close\r\n" +
                        "".join(f"{k}: {v}\r\n" for k, v in extra.items()) + "\r\n").encode() + body
            if url.path == "/slow-body":
                head, body = response.split(b"\r\n\r\n", 1)
                writer.write(head + b"\r\n\r\n" + body[:1])
                await writer.drain()
                self.entered.set()
                await self.release.wait()
                writer.write(body[1:])
            else:
                writer.write(response)
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            pass  # Expected when an admitted client is cancelled or times out.
        except Exception as error:
            self.errors.append(repr(error))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            finally:
                self.writers.discard(writer)
                self.tasks.discard(task)

    def render(self, path, params, headers) -> tuple[int, bytes, str, dict[str, str]]:
        media, extra, status = "text/plain", {}, 200
        if path == "/ready":
            body = b"ready"
        elif path == "/":
            media = "text/html"
            body = (b'<html><title>Disposable lab</title><a href="/openapi.json">API</a>'
                    b'<a href="/public">Public</a><form method="GET" action="/filter">'
                    b'<input name="category" value="Gifts"></form></html>')
        elif path == "/openapi.json":
            media = "application/json"
            body = json.dumps({"paths": {"/filter": {"get": {"parameter": "category"}}}}).encode()
        elif path == "/filter":
            value = params.get("category", ["Gifts"])[0]
            # Intentionally literal, deterministic predicates; no SQL engine.
            if value.endswith("'"):
                status, body = 400, b"fixture syntax error"
            elif "1=2" in value:
                body = b"empty"
            else:
                body = b"fixture products"
        elif path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /hidden\n"
        elif path == "/hidden":
            body = b"synthetic hidden route"
        elif path == "/public":
            body = b"public lab page"
        elif path == "/reflect":
            body = ("Reflected: " + params.get("q", [""])[0]).encode()
        elif path == "/redirect":
            status, body, extra = 302, b"redirect", {"Location": "/public"}
        elif path == "/auth":
            status, body = (200, b"synthetic user") if headers.get("X-Lab-User") == "alice" else (401, b"auth required")
        elif path == "/objects/2":
            body = b"synthetic object owned by bob"  # Deliberate access-control mismatch.
        elif path == "/evidence":
            body = b"proof-marker; password=synthetic-secret-canary"
        elif path == "/error":
            status, body = 503, b"controlled service error"
        elif path == "/flaky" and self.failures_left:
            self.failures_left -= 1
            status, body = 503, b"retry once"
        elif path in {"/flaky", "/slow", "/slow-body"}:
            body = b"recovered"
        else:
            status, body = 404, b"not found"
        return status, body, media, extra
