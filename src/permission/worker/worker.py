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
import threading
import time

from src.permission.network.grants import check_cancelled
from src.tools.mcp.cwe_deployment import CWE_MCP_MOUNT_PATH, verify_cwe_runtime_archive

from src.permission.runtime.execution import ExecutionBlocked

PROBE_TIMEOUT_SECONDS = 5.0
INSPECTION_TIMEOUT_SECONDS = 120.0
INSPECTION_POLL_SECONDS = 0.05
EXCLUDED_DIRECTORY_NAMES = frozenset({
    'venv-linux', 'venv', '.venv', '.git', 'node_modules', '__pycache__',
    '.pytest_cache', '.mypy_cache', 'dist', 'build',
})


def _paths_overlap(first: Path, second: Path) -> bool:
    if first.is_relative_to(second) or second.is_relative_to(first):
        return True
    # Canonical spelling does not normalize case on a case-insensitive WSL
    # drive, and bind mounts can give one directory multiple absolute paths.
    # Compare ancestor identities as well as lexical containment.
    try:
        left, right = first.stat(), second.stat()
    except FileNotFoundError:
        return False
    for root, expected in ((first, right), (second, left)):
        for ancestor in (root, *root.parents):
            info = ancestor.stat()
            if (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino):
                return True
    return False


class OfflineWorker:
    def __init__(self, root: Path, protected: tuple[Path, ...], binary: str, limiter: str,
                 *, cwe_mcp_deployment_path: Path | None = None):
        self.root = root.resolve()
        self.protected = (*protected, self.root / '.kagent')
        self.binary = binary
        self.limiter = limiter
        self.cwe_mcp_deployment_path = (Path(cwe_mcp_deployment_path).expanduser()
                                        if cwe_mcp_deployment_path else None)
        self.output_root = self.root / "artifacts/worker"
        self.output_root.mkdir(parents=True, exist_ok=True)
        if self.output_root.is_symlink() or not self.output_root.resolve().is_relative_to(self.root):
            raise ExecutionBlocked("blocked: unsafe-worker-output-root")

    @classmethod
    async def available(cls, root: Path, protected: tuple[Path, ...], *,
                        cwe_mcp_deployment_path: Path | None = None) -> "OfflineWorker | None":
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
            return cls(root, protected, binary, limiter,
                       cwe_mcp_deployment_path=cwe_mcp_deployment_path)
        except (OSError, asyncio.TimeoutError, ExecutionBlocked):
            return None
        finally:
            if proc is not None and proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                await proc.wait()

    async def prepare(self, command: str, argv: list[str], *, broker: Path | None = None,
                      scanner: bool = False, signal=None,
                      cwe_mcp_deployment_path: Path | None = None) -> tuple[str, list[str]]:
        """Inspect off the UI loop; cancellation/revoke never dispatch a child.

        A stopped thread checks its flag between filesystem operations. Python
        cannot interrupt a blocked kernel filesystem call; that thread may live
        until the call returns, but it only inspects and never launches a process.
        Do not cache inspections: another tool/operator can change the tree.
        """
        from src.permission.runtime.execution import current_policy
        policy = current_policy()
        stopped = threading.Event()
        deadline = time.monotonic() + INSPECTION_TIMEOUT_SECONDS

        def check_authority() -> None:
            check_cancelled(signal)
            if policy is not None and (policy.worker is not self or not policy.nested_allowed()):
                raise ExecutionBlocked("blocked: worker-receipt-revoked/changed")
            if time.monotonic() >= deadline:
                raise ExecutionBlocked("blocked: worker-inspection-timeout; no process started")

        check_authority()
        inspection = asyncio.create_task(asyncio.to_thread(
            self.wrap, command, list(argv), broker=broker, scanner=scanner,
            cwe_mcp_deployment_path=cwe_mcp_deployment_path,
            _stopped=stopped, _deadline=deadline))
        try:
            while not inspection.done():
                await asyncio.wait({inspection}, timeout=INSPECTION_POLL_SECONDS)
                check_authority()
            result = inspection.result()
            check_authority()
            self._check_roots()
            return result
        finally:
            stopped.set()
            inspection.cancel()
            await asyncio.gather(inspection, return_exceptions=True)

    def _check_roots(self) -> None:
        if (self.root.is_symlink() or self.root.resolve() != self.root or self.output_root.is_symlink()
                or not self.output_root.resolve().is_relative_to(self.root)):
            raise ExecutionBlocked("blocked: worker-resource-changed")

    def wrap(self, command: str, argv: list[str], *, broker: Path | None = None, scanner: bool = False,
             cwe_mcp_deployment_path: Path | None = None,
             _stopped: threading.Event | None = None, _deadline: float | None = None) -> tuple[str, list[str]]:
        def checkpoint() -> None:
            if _stopped is not None and _stopped.is_set():
                raise ExecutionBlocked("blocked: worker-inspection-cancelled")
            if _deadline is not None and time.monotonic() >= _deadline:
                raise ExecutionBlocked("blocked: worker-inspection-timeout; no process started")

        checkpoint()
        self._check_roots()
        deployment = None
        if cwe_mcp_deployment_path is not None:
            deployment = self._validate_cwe_deployment(cwe_mcp_deployment_path, checkpoint)
        def scan_error(error: OSError) -> None:
            raise ExecutionBlocked("blocked: worker-root-inspection-failed") from error

        excluded: list[Path] = []
        for directory, folders, files in os.walk(self.root, followlinks=False, onerror=scan_error):
            checkpoint()
            kept = []
            for name in folders:
                path = Path(directory) / name
                if any(path.is_relative_to(p) for p in self.protected):
                    continue
                if name in EXCLUDED_DIRECTORY_NAMES:
                    # Skipped trees must also be inaccessible to the process:
                    # otherwise unchecked hardlinks/FIFOs/sockets bypass preflight.
                    if path.is_symlink():
                        raise ExecutionBlocked('blocked: excluded-worker-directory-is-symlink')
                    excluded.append(path)
                    continue
                kept.append(name)
            folders[:] = kept  # Prune before os.walk descends, not after traversal.
            for name in files:
                checkpoint()
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
        checkpoint()
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
        if deployment is not None:
            args += ["--ro-bind", str(deployment), CWE_MCP_MOUNT_PATH]
        for protected in self.protected:
            if protected.is_relative_to(self.root) and protected.exists():
                destination = "/work/" + protected.relative_to(self.root).as_posix()
                if protected.is_dir():
                    args += ["--tmpfs", destination, "--remount-ro", destination]
                else:
                    args += ["--ro-bind", "/dev/null", destination]
        for path in excluded:
            if path.is_symlink() or not path.is_dir():
                raise ExecutionBlocked('blocked: excluded-worker-directory-changed')
            destination = '/work/' + path.relative_to(self.root).as_posix()
            args += ['--tmpfs', destination, '--remount-ro', destination]
        if broker is not None:
            args += ["--ro-bind", str(broker), "/run/kagent", "--ro-bind",
                     str(Path(__file__).with_name('relay.py')), "/relay.py"]
            for key in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'ALL_PROXY'):
                args += ['--setenv', key, 'http://127.0.0.1:18080']
            args += ['--setenv', 'NO_PROXY', '', '--setenv', 'no_proxy', '']
            command, argv = '/usr/bin/python3', ['/relay.py', command, *argv]
        args += ["--chdir", "/work", "--", command, *argv]
        return self.limiter, args

    def _validate_cwe_deployment(self, requested: Path, checkpoint) -> Path:
        configured = self.cwe_mcp_deployment_path
        path = Path(requested).expanduser()
        if configured is None or path != configured or not path.is_absolute():
            raise ExecutionBlocked("blocked: unconfigured-CWE-deployment-mount")
        try:
            info = path.lstat()
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                    or path.resolve(strict=True) != path):
                raise ExecutionBlocked("blocked: unsafe-CWE-deployment-root")
            # A read-only bind is ineffective if the same files are exposed
            # through the worker's writable output mount. Reject ancestors too:
            # mounting the whole project would expose that writable subtree.
            output = self.output_root.resolve(strict=True)
            if _paths_overlap(path, output):
                raise ExecutionBlocked("blocked: CWE-deployment-overlaps-writable-worker-output")
            if any(_paths_overlap(path, protected) for protected in self.protected):
                raise ExecutionBlocked("blocked: CWE-deployment-overlaps-protected-control-plane")

            def scan_error(error: OSError) -> None:
                raise ExecutionBlocked("blocked: CWE-deployment-inspection-failed") from error

            runtime_entries: dict[str, Path | None] = {}
            runtime = path / 'runtime'
            for directory, folders, files in os.walk(path, followlinks=False, onerror=scan_error):
                checkpoint()
                for name in [*folders, *files]:
                    item = Path(directory) / name
                    entry = item.lstat()
                    # The canonical root plus a no-follow walk rejects every
                    # symlink component. Resolving every leaf here causes many
                    # redundant filesystem round trips, especially on mounted
                    # Windows drives.
                    if stat.S_ISLNK(entry.st_mode):
                        raise ExecutionBlocked("blocked: symlink-in-CWE-deployment")
                    if stat.S_ISDIR(entry.st_mode):
                        if item != runtime and item.is_relative_to(runtime):
                            runtime_entries[item.relative_to(runtime).as_posix()] = None
                        continue
                    if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink > 1):
                        raise ExecutionBlocked("blocked: special-file-or-hardlink-in-CWE-deployment")
                    if item.is_relative_to(runtime):
                        runtime_entries[item.relative_to(runtime).as_posix()] = item
            verify_cwe_runtime_archive(path, runtime_entries, checkpoint)
            return path
        except ExecutionBlocked:
            raise
        except (FileNotFoundError, OSError, RuntimeError) as error:
            raise ExecutionBlocked("blocked: unavailable-CWE-deployment") from error

    def summary(self) -> str:
        cwe_mount = f"; configured CWE MCP read-only mount at {CWE_MCP_MOUNT_PATH}" if self.cwe_mcp_deployment_path else ""
        return ("Linux isolated worker: lab read-only; artifacts/worker writable; direct network denied; "
                "per-invocation scoped plaintext HTTP broker; CONNECT/raw TCP unavailable; per-process "
                "512 MiB AS/120 CPU s; ffuf adapter 4 GiB AS, GOMAXPROCS 2; 16 MiB per-file; "
                f"real-UID NPROC 1024 (not a cgroup/disk quota){cwe_mount}")
