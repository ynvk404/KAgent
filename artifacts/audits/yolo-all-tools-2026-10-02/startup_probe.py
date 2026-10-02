"""Offline timing of worker capability only; no tool/model/network call."""
import time
started = time.perf_counter()
import asyncio
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from src.permission.worker import OfflineWorker

import_seconds = time.perf_counter() - started


async def run():
    measurements = []
    for _ in range(3):
        tick = time.perf_counter()
        worker = await OfflineWorker.available(ROOT, (ROOT / 'src', ROOT / '.git', ROOT / '.kagent'))
        measurements.append({'available': worker is not None, 'seconds': time.perf_counter() - tick})
    result = {
        'platform': sys.platform, 'project': str(ROOT), 'scope': 'worker startup capability only',
        'imports_seconds': import_seconds, 'samples': measurements,
        'not_measured': 'full CLI/provider initialization, interpreter cold start, actual dispatch project inspection',
    }
    output = ROOT / 'artifacts/audits/yolo-all-tools-2026-10-02/repair-2026-10-02/startup-timing.json'
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


asyncio.run(run())
