"""Line-oriented presentation of persisted parent lifecycle and reset receipts."""
from __future__ import annotations

import time


class Progress:
    def __init__(self, manifest, settings, kind, stream):
        self.stream = stream
        self.order = manifest.execution_order
        self.classes = {op['case_id']: op['vulnerability_class'] for op in manifest.operational}
        self.started = time.monotonic()
        self.finished = 0
        self.current = None
        self.say('KAgent — Scenario 1 Benchmark')
        self.say(f'Mode: {"Smoke / Development" if manifest.mode == "smoke" else kind.title()}')
        self.say(f'Target: {settings.target}\nCases: {len(self.order)}')

    def say(self, line):
        try:
            print(line, file=self.stream, flush=True)
        except OSError:
            pass  # A closed progress pipe does not change execution or exit status.

    def __call__(self, row):
        cid = row['case_id']
        if row['kind'] == 'scheduled':
            return
        if cid != self.current:
            self.current = cid
            cls = 'SQLi' if self.classes[cid] == 'sql-injection' else 'XSS'
            self.say(f'\n[{self.order.index(cid) + 1:02d}/{len(self.order):02d}] {cid} | {cls}')
        if row['kind'] == 'reset-receipt':
            if row['phase'] in {'before', 'after'}:
                self.say(f'  Reset {row["phase"]:<7} {"OK (verified receipt)" if row["status"] == "verified" else "BLOCKED"}')
        elif row['kind'] == 'started':
            self.say('  Agent running  ...')
        elif row['kind'] == 'runtime-finished':
            self.finished += 1
            self.say(f'  Result export  {"persisted (hash recorded)" if row["data"].get("result_sha256") else "unavailable"}')
            seconds = row['data'].get('wall_seconds')
            elapsed = f'{seconds:.1f}s worker wall' if seconds is not None else 'time unavailable'
            self.say(f'  Execution      {row["status"]} | {elapsed}; evaluation pending')
            self.say(f'Progress: {self.finished}/{len(self.order)} executions finished')
        elif row['kind'] == 'evaluated':
            self.say(f'  Evaluator      {row["data"]["partition"]} ({row["data"]["reason"]})')

    def evaluated(self, report):
        self.say('\nPost-run evaluator classification:')
        for record in report['records']:
            label = f' / {record["confusion"]}' if record['confusion'] else ''
            self.say(f'  {record["case_id"]}: {record["partition"]}{label}')
        self.say(f'Total elapsed: {time.monotonic() - self.started:.1f}s (execution + evaluation + publication)')
