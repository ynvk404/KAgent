"""Explicit offline preparation of an import archive; never called by serving."""
from __future__ import annotations

import argparse
import importlib.util
import hashlib
import json
import marshal
import os
from pathlib import Path
import stat
import struct
import tempfile
import zipfile


def pack_runtime(deployment: Path) -> Path:
    """Bundle pure Python/resources with bytecode for this interpreter.

    Native-extension packages stay in runtime/: extension loading needs real
    files and their original package paths. Source, resources and license/
    distribution metadata are retained. No packages or corpus are acquired.
    """
    if not deployment.is_absolute() or deployment.resolve(strict=True) != deployment:
        raise ValueError('deployment must be a canonical absolute directory')
    runtime = deployment / 'runtime'
    if runtime.is_symlink() or not runtime.is_dir():
        raise ValueError('runtime must be a regular directory')
    files: list[tuple[Path, Path]] = []
    directories: list[Path] = []
    native: set[str] = set()
    def scan_error(error: OSError) -> None:
        raise error

    for directory, folders, names in os.walk(runtime, followlinks=False, onerror=scan_error):
        for name in [*folders, *names]:
            path = Path(directory) / name
            relative = path.relative_to(runtime)
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError('symlink in runtime')
            if stat.S_ISDIR(info.st_mode):
                directories.append(relative)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                files.append((path, relative))
                if '.so' in name or path.suffix.lower() in {'.dll', '.pyd', '.dylib'}:
                    native.add(relative.parts[0])
            else:
                raise ValueError('special file or hardlink in runtime')
    destination = deployment / 'runtime.zip'
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix='.runtime-', suffix='.zip', dir=deployment, delete=False) as stream:
            temporary = Path(stream.name)
            inventory: dict[str, str | None] = {p.as_posix(): None for p in directories}
            with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                for relative in sorted(directories):
                    if relative.parts[0] not in native and '__pycache__' not in relative.parts:
                        archive.writestr(relative.as_posix() + '/', b'')
                for path, relative in sorted(files):
                    data = path.read_bytes()
                    inventory[relative.as_posix()] = hashlib.sha256(data).hexdigest()
                    if (relative.parts[0] in native or '__pycache__' in relative.parts
                            or path.suffix in {'.pyc', '.pyo'}):
                        continue
                    archive.writestr(relative.as_posix(), data)
                    if path.suffix == '.py':
                        filename = '/opt/kagent-cwe-mcp/runtime.zip/' + relative.as_posix()
                        code = compile(data, filename, 'exec', dont_inherit=True)
                        # PEP 552 unchecked hash bytecode, produced only during
                        # explicit trusted maintenance. The controller binds the
                        # archive bytes during review; serving never rebuilds it.
                        bytecode = (importlib.util.MAGIC_NUMBER + struct.pack('<I', 1)
                                    + importlib.util.source_hash(data) + marshal.dumps(code))
                        archive.writestr(relative.with_suffix('.pyc').as_posix(), bytecode)
                manifest = json.dumps({'schema_version': 1, 'entries': inventory},
                                      sort_keys=True, separators=(',', ':')).encode('utf-8')
                if len(manifest) > 512 * 1024:
                    raise ValueError('runtime inventory exceeds reviewed size bound')
                archive.writestr('kagent-runtime-manifest.json', manifest)
            stream.flush()
            os.fsync(stream.fileno())
        # The launcher's sealed memfd obeys the existing 16 MiB worker FSIZE
        # limit too. Never increase that limit for startup optimization.
        if temporary.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('runtime archive exceeds reviewed size bound')
        os.replace(temporary, destination)
        return destination
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('deployment', type=Path)
    print(pack_runtime(parser.parse_args().deployment))
