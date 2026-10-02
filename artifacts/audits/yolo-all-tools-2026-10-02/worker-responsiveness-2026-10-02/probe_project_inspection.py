"""Read-only project inspection: no model, target requests or tool dispatch."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import time
import sys

from src.engagement.state import EngagementState
from src.permission.execution import default_execution_policy
from src.permission.worker import OfflineWorker


async def main():
    root = Path.cwd()
    policy = default_execution_policy(EngagementState(), root)
    worker = await OfflineWorker.available(root, policy.protected)
    assert worker is not None, 'existing isolated worker must be available'
    gaps = []
    done = asyncio.Event()

    async def heartbeat():
        previous = time.monotonic()
        while not done.is_set():
            await asyncio.sleep(0.05)
            now = time.monotonic()
            gaps.append(now - previous)
            previous = now

    pulse = asyncio.create_task(heartbeat())
    began = time.monotonic()
    error = None
    try:
        # Prepare only. Deliberately do not create the returned subprocess.
        await worker.prepare('/bin/true', [])
    except Exception as exc:
        error = str(exc)
    finally:
        elapsed = time.monotonic() - began
        done.set()
        await pulse
    result = dict(inspection_seconds=round(elapsed, 3), heartbeat_ticks=len(gaps),
                  maximum_heartbeat_gap_seconds=round(max(gaps, default=0), 3),
                  error=error, tool_dispatch=False, model_calls=0, target_requests=0)
    destination = Path(__file__).with_name(sys.argv[1] if len(sys.argv) > 1 else 'project-inspection.json')
    destination.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    asyncio.run(main())
