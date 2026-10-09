"""Loopback-only TCP/HTTP forwarding evidence. Never pairs or reads Chrome."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.tools.mcp.browser_deployment import verify_browser_local_deployment
from src.tools.mcp.browser_local import check_ports_free, linux_listeners, WINDOWS_POWERSHELL

MARKER = b'KAGENT-LOOPBACK-FORWARDING-ONLY'


async def main():
    verify_browser_local_deployment()
    await check_ports_free()
    clients: set[asyncio.Task] = set()

    async def respond(reader, writer):
        task = asyncio.current_task()
        assert task is not None
        clients.add(task)
        try:
            async with asyncio.timeout(5):
                await reader.readuntil(b'\r\n\r\n')
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n'
                             + f'Content-Length: {len(MARKER)}\r\n\r\n'.encode() + MARKER)
                await writer.drain()
        except (TimeoutError, OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()
            clients.discard(task)

    server = await asyncio.start_server(respond, '127.0.0.1', 9009, limit=8192)
    results = []
    try:
        for hostname in ('127.0.0.1', 'localhost'):
            command = ("$ErrorActionPreference='Stop'; try { "
                       f"$r=Invoke-WebRequest -UseBasicParsing -TimeoutSec 5 'http://{hostname}:9009/'; "
                       f"if ($r.Content -eq '{MARKER.decode()}') {{ Write-Output 'marker-ok'; exit 0 }}; exit 25 "
                       "} catch { Write-Output 'transport-failed'; exit 26 }")
            child = await asyncio.create_subprocess_exec(
                WINDOWS_POWERSHELL, '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', command,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                env={'PATH': '/usr/bin:/bin', 'WSL_INTEROP': os.environ.get('WSL_INTEROP', '')})
            try:
                out, _ = await asyncio.wait_for(child.communicate(), 12)
                results.append({'windows_host': hostname, 'exit': child.returncode,
                                'marker_received': out.strip() == b'marker-ok'})
            finally:
                if child.returncode is None:
                    child.kill()
                    await child.wait()
    finally:
        server.close()
        await server.wait_closed()
        for task in list(clients):
            task.cancel()
        await asyncio.gather(*clients, return_exceptions=True)
    report = {'listener': '127.0.0.1:9009 in WSL', 'windows_to_wsl': results,
              'port_released': not linux_listeners(), 'websocket_or_chrome_tested': False,
              'system_network_changes': False}
    print(json.dumps(report, indent=2))
    return 0 if all(row['marker_received'] for row in results) and report['port_released'] else 1


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
