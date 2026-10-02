"""Linux worker using existing bubblewrap/prlimit, with direct networking denied.

An optional per-invocation UDS mount carries bounded plaintext HTTP to the
controller broker. Unbound wrap() stays offline; no ambient host fallback.
This is not raw-network, CONNECT, aggregate cgroup or cross-platform coverage.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import shutil
import os
import stat
import sys
import tempfile
from typing import Any

from src.permission.execution import ExecutionBlocked

PROBE_TIMEOUT_SECONDS = 5.0


class OfflineWorker:
    def __init__(self, root: Path, protected: tuple[Path, ...], binary: str, limiter: str):
        self.root = root.resolve()
        self.protected = (*protected, self.root / '.kagent')
        self.binary = binary
        self.limiter = limiter
        self.output_root = self.root / "artifacts/worker"
        self.output_root.mkdir(parents=True, exist_ok=True)
        if self.output_root.is_symlink() or not self.output_root.resolve().is_relative_to(self.root):
            raise ExecutionBlocked("blocked: unsafe-worker-output-root")

    @classmethod
    async def available(cls, root: Path, protected: tuple[Path, ...]) -> "OfflineWorker | None":
        binary, limiter = shutil.which("bwrap"), shutil.which("prlimit")
        if sys.platform != "linux" or binary is None or limiter is None:
            return None
        proc = None
        try:
            # Test OS capability on a small controller-created Linux filesystem
            # tree. Never inspect the operator's project during startup; wrap()
            # still validates the actual project before each tool dispatch.
            async with asyncio.timeout(PROBE_TIMEOUT_SECONDS):
                with tempfile.TemporaryDirectory(prefix="kagent-worker-probe-", dir="/tmp") as scratch:
                    probe = cls(Path(scratch), (), binary, limiter)
                    command, argv = probe.wrap("/bin/true", [])
                    proc = await asyncio.create_subprocess_exec(command, *argv, stdout=asyncio.subprocess.DEVNULL,
                                                                stderr=asyncio.subprocess.DEVNULL)
                    await proc.wait()
                    if proc.returncode != 0:
                        return None
            return cls(root, protected, binary, limiter)
        except (OSError, asyncio.TimeoutError, ExecutionBlocked):
            return None
        finally:
            if proc is not None and proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()

    def wrap(self, command: str, argv: list[str], *, broker: Path | None = None, scanner: bool = False) -> tuple[str, list[str]]:
        if self.root.is_symlink() or self.output_root.is_symlink():
            raise ExecutionBlocked("blocked: worker-resource-changed")
        def scan_error(error: OSError) -> None:
            raise ExecutionBlocked("blocked: worker-root-inspection-failed") from error

        for directory, folders, files in os.walk(self.root, followlinks=False, onerror=scan_error):
            folders[:] = [name for name in folders if not any((Path(directory) / name).is_relative_to(p) for p in self.protected)]
            for name in files:
                path = Path(directory) / name
                if any(path.is_relative_to(p) for p in self.protected):
                    continue
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    continue
                except OSError as error:
                    scan_error(error)
                if stat.S_ISSOCK(info.st_mode) or stat.S_ISFIFO(info.st_mode) or stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode):
                    raise ExecutionBlocked("blocked: worker-root-contains-host-ipc/device")
                if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                    raise ExecutionBlocked("blocked: worker-root-contains-ambiguous-hardlink")
        # Go scanners reserve a large virtual arena even for tiny scans. This
        # trusted adapter profile increases AS, not network/filesystem rights.
        # NPROC counts the controller's entire real UID (including IDE/WSL
        # threads), not this PID namespace. 256 made even /bin/sh startup
        # intermittent under ordinary validation. Retain a finite 1024 ceiling;
        # it is explicitly not a per-worker/cgroup process-tree guarantee.
        args = ["--as=" + str(4 * 1024**3 if scanner else 512 * 1024**2), "--cpu=120", "--fsize=16777216", "--nofile=128", "--nproc=1024", "--core=0", "--",
                self.binary, "--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent", "--new-session",
                "--cap-drop", "ALL", "--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/tmp",
                "--setenv", "LANG", "C.UTF-8"]
        for path in ["/usr", "/bin", "/lib", "/lib64"]:
            if Path(path).exists():
                args += ["--ro-bind", path, path]
        if scanner:
            args += ['--setenv', 'GOMAXPROCS', '2', '--setenv', 'GOMEMLIMIT', '134217728']
        args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--ro-bind", str(self.root), "/work",
                 "--bind", str(self.output_root), "/work/artifacts/worker"]
        for protected in self.protected:
            if protected.is_relative_to(self.root) and protected.exists():
                destination = "/work/" + protected.relative_to(self.root).as_posix()
                if protected.is_dir():
                    args += ["--tmpfs", destination, "--remount-ro", destination]
                else:
                    args += ["--ro-bind", "/dev/null", destination]
        if broker is not None:
            args += ["--ro-bind", str(broker), "/run/kagent", "--ro-bind",
                     str(Path(__file__).with_name('worker_relay.py')), "/relay.py"]
            for key in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'ALL_PROXY'):
                args += ['--setenv', key, 'http://127.0.0.1:18080']
            args += ['--setenv', 'NO_PROXY', '', '--setenv', 'no_proxy', '']
            command, argv = '/usr/bin/python3', ['/relay.py', command, *argv]
        args += ["--chdir", "/work", "--", command, *argv]
        return self.limiter, args

    def summary(self) -> str:
        return "Linux isolated worker: lab read-only; artifacts/worker writable; direct network denied; per-invocation scoped plaintext HTTP broker; CONNECT/raw TCP unavailable; per-process 512 MiB AS/120 CPU s; ffuf adapter 4 GiB AS, GOMAXPROCS 2; 16 MiB per-file; real-UID NPROC 1024 (not a cgroup/disk quota)"
