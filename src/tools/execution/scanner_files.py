"""Descriptor-bound private scanner files. Never adopt an existing job directory."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import time
from typing import Callable
from src.async_io import check_worker, publication
from src.workflow.evidence_publication import _rename_noreplace

from src.permission.runtime.execution import ExecutionBlocked


def inode(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


class ScannerStorageLimit(OSError):
    """A bounded archive is full; existing saved artifacts remain untouched."""


class PrivateJob:
    def __init__(self, root: Path, parts: tuple[str, ...], *, max_siblings: int | None = None,
                 check: Callable[[], None] | None = None, deadline: float | None = None):
        self.path = root.joinpath(*parts)
        self.check = check
        self.fds: list[int] = []
        self.edges: list[str] = []
        self.owned: dict[str, tuple[int, int]] = {}
        self.control_dirs: list[tuple[int, str]] = []
        self.created = False
        self.job_parent: int | None = None
        self.job_name = parts[-1]
        self.job_inode: tuple[int, int] | None = None
        self.job_fd: int | None = None
        self.archive_lock: int | None = None
        try:
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.fds.append(fd)
            for name in root.parts[1:]:
                fd = self._open(fd, name)
            for name in parts[:-1]:
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                fd = self._open(fd, name)
                self.control_dirs.append((fd, name))
                info = os.fstat(fd)
                # Match the existing private-result store's shared .kagent
                # ancestor contract; scanner-owned subdirectories remain0700.
                if name == '.kagent':
                    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                        raise ExecutionBlocked('blocked: scanner control directory ownership/permissions')
                else:
                    self._private(info, directory=True)
            if max_siblings is not None:
                import fcntl
                # Hold the session-directory lock through publication/rollback.
                # Independent runtimes cannot both reserve the final slot.
                expires = deadline if deadline is not None else time.monotonic() + 3.0
                while True:
                    check_worker()
                    if check is not None:
                        check()
                    if time.monotonic() >= expires:
                        raise TimeoutError('scanner artifact lock deadline exceeded')
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        time.sleep(0.01)  # Only called by an owned filesystem worker.
                self.archive_lock = fd
                if len(os.listdir(fd)) >= max_siblings:
                    raise ScannerStorageLimit('scanner artifact retention limit reached')
            # EXCLUSIVE: preexisting dirs, including abandoned jobs, are foreign.
            os.mkdir(parts[-1], 0o700, dir_fd=fd)
            self.created = True
            self.job_parent = fd
            self.job_inode = inode(os.stat(parts[-1], dir_fd=fd, follow_symlinks=False))
            self.job_fd = self._open(fd, parts[-1])
            if inode(os.fstat(self.job_fd)) != self.job_inode:
                raise ExecutionBlocked('blocked: exclusive scanner job directory replaced')
            self.validate()
        except BaseException:
            self.close(remove=True)
            raise

    def _open(self, fd: int, name: str) -> int:
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        self.fds.append(child)
        self.edges.append(name)
        return child

    @staticmethod
    def _private(info: os.stat_result, *, directory: bool = False) -> None:
        if (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
                or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                or (not directory and info.st_nlink != 1)):
            raise ExecutionBlocked('blocked: scanner private file/directory integrity')

    def validate(self) -> None:
        for parent, child, name in zip(self.fds, self.fds[1:], self.edges):
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(current.st_mode) or inode(current) != inode(os.fstat(child)):
                raise ExecutionBlocked('blocked: scanner directory binding changed')
        for fd, name in self.control_dirs:
            info = os.fstat(fd)
            if name == '.kagent':
                if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                    raise ExecutionBlocked('blocked: scanner control directory ownership/permissions')
            else:
                self._private(info, directory=True)
        self._private(os.fstat(self.fds[-1]), directory=True)

    def write(self, name: str, data: bytes) -> None:
        if name == 'manifest.json':
            self.write('manifest.pending', data)
            self.validate()
            with publication(self.check):
                self.validate()
                current = os.stat('manifest.pending', dir_fd=self.fds[-1], follow_symlinks=False)
                self._private(current)
                if inode(current) != self.owned['manifest.pending']:
                    raise ExecutionBlocked('blocked: scanner manifest temporary inode changed')
                _rename_noreplace(self.fds[-1], 'manifest.pending', name)
            self.owned[name] = self.owned.pop('manifest.pending')
            return
        self.validate()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fds[-1])
        self.owned[name] = inode(os.fstat(fd))
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        self.validate()

    def mkdir(self, name: str) -> None:
        self.validate()
        os.mkdir(name, 0o700, dir_fd=self.fds[-1])
        self.owned[name] = inode(os.stat(name, dir_fd=self.fds[-1], follow_symlinks=False))

    def size(self, name: str) -> int:
        self.validate()
        info = os.stat(name, dir_fd=self.fds[-1], follow_symlinks=False)
        self._private(info)
        if inode(info) != self.owned.get(name):
            raise ExecutionBlocked('blocked: scanner output inode changed')
        return info.st_size

    def read(self, name: str, cap: int) -> bytes:
        if self.size(name) > cap:
            raise ValueError('scanner machine output limit')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fds[-1])
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            self._private(before)
            if inode(before) != self.owned.get(name):
                raise ExecutionBlocked('blocked: scanner output inode changed')
            data = stream.read(cap + 1)
            after = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(data) > cap:
                raise ValueError('scanner output changed or exceeded limit')
        self.validate()
        return data

    def close(self, *, remove: bool) -> None:
        # Cleanup is relative to held directories and only our recorded inodes.
        try:
            if remove and self.created and self.fds:
                fd = self.job_fd
                for name, expected in reversed(tuple(self.owned.items())):
                    assert fd is not None
                    try:
                        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if inode(info) == expected:
                            if stat.S_ISDIR(info.st_mode):
                                # Trusted ffuf creates private history and
                                # calibration files in our exclusive XDG root.
                                # Snapshot/recheck each child inode via held
                                # descriptors; never follow links or adopt a
                                # preexisting job/output directory.
                                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                                try:
                                    self._remove_children(child)
                                finally:
                                    os.close(child)
                                os.rmdir(name, dir_fd=fd)
                            else:
                                os.unlink(name, dir_fd=fd)
                    except FileNotFoundError:
                        pass
                if self.job_parent is not None and self.job_inode is not None:
                    parent, name = self.job_parent, self.job_name
                    current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if inode(current) == self.job_inode:
                        os.rmdir(name, dir_fd=parent)
        finally:
            if self.archive_lock is not None:
                import fcntl
                fcntl.flock(self.archive_lock, fcntl.LOCK_UN)
                self.archive_lock = None
            for fd in reversed(self.fds):
                os.close(fd)
            self.fds.clear()

    @classmethod
    def _remove_children(cls, fd: int, depth: int = 0) -> None:
        if depth > 12:
            raise ExecutionBlocked('blocked: unexpected scanner scratch nesting')
        cls._private(os.fstat(fd), directory=True)
        children = [(name, os.stat(name, dir_fd=fd, follow_symlinks=False)) for name in os.listdir(fd)]
        if len(children) > 1024:
            raise ExecutionBlocked('blocked: unexpected scanner scratch file count')
        for name, expected in children:
            is_dir = stat.S_ISDIR(expected.st_mode)
            cls._private(expected, directory=is_dir)
            if is_dir:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    if inode(os.fstat(child)) != inode(expected):
                        raise ExecutionBlocked('blocked: scanner scratch inode changed')
                    cls._remove_children(child, depth + 1)
                finally:
                    os.close(child)
            if inode(os.stat(name, dir_fd=fd, follow_symlinks=False)) != inode(expected):
                raise ExecutionBlocked('blocked: scanner scratch inode changed')
            if is_dir:
                os.rmdir(name, dir_fd=fd)
            else:
                os.unlink(name, dir_fd=fd)


def read_private(root: Path, relative: str, cap: int) -> bytes:
    """Integrity reread, without granting arbitrary file-tool access."""
    path = Path(relative)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('invalid scanner artifact')
    descriptors = []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(fd)
        for name in (*root.parts[1:], *path.parts[:-1]):
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
        opened = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(opened, 'rb') as stream:
            before = os.fstat(stream.fileno())
            PrivateJob._private(before)
            if before.st_size > cap:
                raise ValueError('scanner artifact limit')
            data = stream.read(cap + 1)
            after = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(data) > cap:
                raise ValueError('scanner artifact changed')
            return data
    finally:
        for fd in reversed(descriptors):
            os.close(fd)
