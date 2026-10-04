"""Deployed entry point: /usr/bin/python3 -I -B /work/cwe-mcp-deployment/launch.py."""
import asyncio
import sys
from pathlib import Path

sys.dont_write_bytecode = True
root = Path(__file__).resolve().parent
sys.path[:0] = [str(root / 'runtime'), str(root / 'server')]

if __name__ == '__main__':
    try:
        from cwe_mcp.server import main
        status = asyncio.run(main(root))
    except KeyboardInterrupt:
        status = 130
    except Exception:
        sys.stderr.write('INTERNAL_ERROR: catalog startup unavailable.\n')
        status = 1
    raise SystemExit(status)
