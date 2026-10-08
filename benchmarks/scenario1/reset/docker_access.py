"""Bounded Docker reads for admission; no lifecycle operations are exposed."""
from __future__ import annotations

import subprocess


def docker(*args: str) -> str:
    if not (args[:1] == ('inspect',) or args[:2] == ('network', 'inspect')
            or (args[:1] == ('exec',) and len(args) > 2 and args[2] in {'cat', 'sha256sum', 'python3'})):
        raise ValueError('Docker admission operation refused')
    try:
        return subprocess.run(['docker', *args], check=True, capture_output=True,
                              text=True, timeout=20).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        # Inspect output can contain credentials. Neither output nor argv is exported.
        raise ValueError('Docker admission read failed') from None
