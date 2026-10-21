"""Publish complete immutable proofs without replacing an incumbent.

Linux renameat2(RENAME_NOREPLACE) avoids both a partial final file and the
transient extra hardlink that would violate the single-link proof contract.
Unsupported filesystems/platforms fail closed, leaving incumbents untouched.
"""
from contextlib import contextmanager
import ctypes
import os
from pathlib import Path
import stat
import uuid
from typing import Callable
from src.async_io import publication

from .source import identity


def _rename_noreplace(directory: int, temporary: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    if rename is None:
        raise OSError('atomic no-clobber proof publication unavailable')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(directory, os.fsencode(temporary), directory, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), destination)


@contextmanager
def _directory(path: Path):
    fds, names = [], []
    try:
        path_only = getattr(os, 'O_PATH', os.O_RDONLY)
        fds.append(os.open('/', path_only | os.O_DIRECTORY | os.O_NOFOLLOW))
        for index, name in enumerate(path.parts[1:], start=1):
            # Only our private destination directory needs a readable fd for
            # fsync; searchable ancestors need no listing permission.
            access = os.O_RDONLY if index == len(path.parts) - 1 else path_only
            fds.append(os.open(name, access | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
            names.append(name)

        def validate():
            for parent, child, name in zip(fds, fds[1:], names):
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or identity(info) != identity(os.fstat(child)):
                    raise ValueError('evidence publication namespace changed')
        validate()
        yield fds[-1], validate
        validate()
    finally:
        for fd in reversed(fds):
            os.close(fd)


def publish(destination: Path, snapshot: bytes, *, check: Callable[[], None] | None = None) -> None:
    with _directory(destination.parent) as (directory, validate):
        temporary = '.' + uuid.uuid4().hex + '.proof-tmp'
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        owned = identity(os.fstat(fd))
        try:
            try:
                handle = os.fdopen(fd, 'wb')
            except BaseException:
                os.close(fd)
                raise
            with handle:
                offset = 0
                while offset < len(snapshot):
                    count = handle.write(snapshot[offset:])
                    if not isinstance(count, int) or not 0 < count <= len(snapshot) - offset:
                        raise OSError('incomplete evidence snapshot write')
                    offset += count
                handle.flush()
                os.fchmod(handle.fileno(), 0o400)
                os.fsync(handle.fileno())
            validate()
            info = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
            if identity(info) != owned or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('evidence publication temporary file changed')
            with publication(check):
                _rename_noreplace(directory, temporary, destination.name)
            os.fsync(directory)
        finally:
            # Only remove this invocation's inode, including close/cancel/fault
            # paths. A published or replaced name never grants unlink rights.
            try:
                info = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if identity(info) == owned:
                    os.unlink(temporary, dir_fd=directory)
