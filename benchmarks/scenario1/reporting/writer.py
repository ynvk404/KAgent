"""Render first, stage privately, then atomically publish without replacing inputs."""
from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import uuid

from .aggregate import public_metrics
from .charts import render_charts
from .loader import load_report
from .tables import render_tables

# These namespaces belong to the benchmark, even before their paths exist.
_RESERVED = {'manifest.json', 'events.jsonl', 'run-classification.json', 'results', 'workspaces'}


def _destination(run: Path, output: Path | None) -> Path:
    raw = output or run / 'report'
    destination = raw.resolve()
    if not destination.is_relative_to(run) or destination == run:
        raise ValueError('report output must be a new directory inside the run')
    # Check both the resolved namespace and the caller's lexical namespace.
    for path in (destination, raw.absolute()):
        if path.is_relative_to(run):
            first = path.relative_to(run).parts[0]
            if first in _RESERVED or first.startswith(('evaluation-', '.kagent-report-')):
                raise ValueError('report output occupies a reserved input namespace')
    if raw.is_symlink() or destination.exists():
        raise ValueError('report output already exists; refusing to overwrite')
    return destination


def _publisher():
    # Linux renameat2(RENAME_NOREPLACE) is atomic even against a concurrent mkdir.
    # Unsupported filesystems can publish the complete stage via exclusive symlink.
    if sys.platform != 'linux':
        raise ValueError('atomic no-overwrite report publication requires Linux')
    rename = getattr(ctypes.CDLL(None, use_errno=True), 'renameat2', None)
    if rename is None:
        raise ValueError('atomic no-overwrite report publication unavailable')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    return rename


def _publish(rename, parent_fd: int, staging_name: str, name: str) -> None:
    if rename(parent_fd, os.fsencode(staging_name), parent_fd, os.fsencode(name), 1):
        code = ctypes.get_errno()
        if code in {errno.EEXIST, errno.ENOTEMPTY}:
            raise ValueError('report output already exists; refusing to overwrite')
        if code in {errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP}:
            # WSL DrvFS/9p rejects RENAME_NOREPLACE. symlinkat also creates the
            # destination atomically and exclusively, even against an empty
            # directory or dangling symlink. Keep its completed private stage;
            # plain rename would risk replacing another owner's directory.
            try:
                os.symlink(staging_name, name, dir_fd=parent_fd, target_is_directory=True)
            except FileExistsError:
                raise ValueError('report output already exists; refusing to overwrite') from None
            return
        raise OSError(code, 'atomic report publication failed')


def _open_parent(run: Path, destination: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current = os.open(run, flags)
    try:
        for name in destination.parent.relative_to(run).parts:
            try:
                os.mkdir(name, mode=0o700, dir_fd=current)
            except FileExistsError:
                pass
            child = os.open(name, flags, dir_fd=current)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _write_file(stage_fd: int, name: str, contents: bytes) -> None:
    parts = Path(name).parts
    if Path(name).is_absolute() or '..' in parts or not parts:
        raise ValueError('invalid rendered report path')
    current = os.dup(stage_fd)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=current)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=current)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(current)
    finally:
        os.close(current)


def _check_parent(parent_fd: int, destination: Path, run: Path) -> None:
    # Resolve the held directory itself, rather than trusting an earlier exists().
    actual = Path(os.readlink(f'/proc/self/fd/{parent_fd}'))
    if actual != destination.parent or not actual.is_relative_to(run):
        raise ValueError('report output parent changed during publication')
    held, visible = os.fstat(parent_fd), destination.parent.stat()
    if (held.st_dev, held.st_ino) != (visible.st_dev, visible.st_ino):
        raise ValueError('report output parent changed during publication')
    _destination(run, destination)


def write_report(run: Path, output: Path | None = None, evaluation: Path | None = None) -> Path:
    run = run.resolve()
    destination = _destination(run, output)
    rename = _publisher()
    model = load_report(run, evaluation)
    files = {**render_tables(model), **render_charts(model)}
    report = {**model.metadata, 'canonical_evaluator_metrics': public_metrics(model),
              'output_files': sorted([*files, 'report.json'])}
    files['report.json'] = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    # No filesystem mutation occurs before validation and rendering complete.
    parent_fd = _open_parent(run, destination)
    staging_name = '.kagent-report-' + uuid.uuid4().hex
    stage_fd = None
    owned = None
    try:
        _check_parent(parent_fd, destination, run)
        os.mkdir(staging_name, mode=0o700, dir_fd=parent_fd)
        stage_fd = os.open(staging_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        owned = os.fstat(stage_fd)
        for name, contents in sorted(files.items()):
            _write_file(stage_fd, name, contents)
        os.fsync(stage_fd)
        _check_parent(parent_fd, destination, run)
        named_stage = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
        if (named_stage.st_dev, named_stage.st_ino) != (owned.st_dev, owned.st_ino):
            raise ValueError('report staging ownership changed during publication')
        _publish(rename, parent_fd, staging_name, destination.name)
        return destination
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        # A unique name alone is insufficient if another process substitutes it.
        # Remove only the directory inode created and owned by this invocation.
        if owned is not None:
            try:
                remaining = os.stat(staging_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass  # publication moved it, or it was removed externally
            else:
                if (stat.S_ISDIR(remaining.st_mode)
                        and (remaining.st_dev, remaining.st_ino) == (owned.st_dev, owned.st_ino)):
                    # Also preserve a published backing directory if interrupted
                    # immediately after symlink creation, before _publish returns.
                    try:
                        linked = os.readlink(destination.name, dir_fd=parent_fd) == staging_name
                    except OSError:
                        linked = False
                    if not linked:
                        shutil.rmtree(staging_name, dir_fd=parent_fd)
        os.close(parent_fd)
