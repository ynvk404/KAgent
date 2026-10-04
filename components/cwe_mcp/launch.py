"""Deployed entry point: /usr/bin/python3 -I -B /opt/kagent-cwe-mcp/launch.py."""
import asyncio
import sys
from pathlib import Path

sys.dont_write_bytecode = True
root = Path(__file__).resolve().parent


def memory_archive(archive: Path) -> tuple[str, int]:
    """Read once from the deployment; zip imports then use a sealed memfd.

    No host/tmp path, extraction, persistent cache or shared process is used.
    The worker has already checked dependency/archive consistency before spawn.
    """
    import fcntl
    import os

    with archive.open('rb') as stream:
        data = stream.read(16 * 1024 * 1024 + 1)
    if not data or len(data) > 16 * 1024 * 1024:
        raise ValueError('runtime archive size')
    descriptor = os.memfd_create('cwe-runtime', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        with os.fdopen(os.dup(descriptor), 'wb') as stream:
            stream.write(data)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return f'/proc/self/fd/{descriptor}', descriptor
    except BaseException:
        os.close(descriptor)
        raise

if __name__ == '__main__':
    try:
        archive = root / 'runtime.zip'
        archive_path, archive_fd = memory_archive(archive) if archive.is_file() else ('', None)
        sys.path[:0] = [*([archive_path] if archive_path else []),
                       str(root / 'runtime'), str(root / 'server')]
        from cwe_mcp.server import main
        status = asyncio.run(main(root))
    except KeyboardInterrupt:
        status = 130
    except Exception:
        sys.stderr.write('INTERNAL_ERROR: catalog startup unavailable.\n')
        status = 1
    raise SystemExit(status)
