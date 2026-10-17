"""Operator-selected existing wordlist files; model arguments select only IDs."""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat

BUNDLED_WORDLIST = Path(__file__).with_name('wordlists') / 'web-common.txt'
SYSTEM_WORDLISTS = (
    ('dirb-small', Path('/usr/share/dirb/wordlists/small.txt')),
    ('dirb-common', Path('/usr/share/dirb/wordlists/common.txt')),
)
MAX_WORDLISTS = 16


def parse_wordlist_spec(value: str) -> tuple[str, Path]:
    identifier, separator, filename = value.partition('=')
    if (not separator or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', identifier)
            or identifier == 'web-common' or not filename.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in filename)):
        raise ValueError('Use --scanner-wordlist ID=FILE. IDs must be unique. web-common is reserved.')
    return identifier, Path(os.path.abspath(Path(filename).expanduser()))


def wordlist_files(entries: tuple[tuple[str, Path], ...]) -> tuple[tuple[str, Path], ...]:
    if len(entries) > MAX_WORDLISTS:
        raise ValueError('at most 16 operator wordlist files may be registered')
    # Fixed installed data files only: no recursive host search or downloads.
    result = [(identifier, path) for identifier, path in SYSTEM_WORDLISTS if path.is_file()]
    result.append(('web-common', BUNDLED_WORDLIST))
    seen = {identifier for identifier, _ in result}
    for identifier, filename in entries:
        identifier, filename = parse_wordlist_spec(identifier + '=' + str(filename))
        if identifier in seen:
            raise ValueError('scanner wordlist IDs must be unique')
        seen.add(identifier)
        result.append((identifier, filename))
    return tuple(result)


def wordlist_catalog(entries: tuple[tuple[str, Path], ...]) -> list[dict]:
    rows = []
    for identifier, path in wordlist_files(entries):
        size = None
        try:
            info = path.stat()
            available = (path.resolve(strict=True) == path.absolute() and stat.S_ISREG(info.st_mode)
                         and info.st_nlink == 1 and 0 < info.st_size <= 8 * 1024**2
                         and os.access(path, os.R_OK))
            size = info.st_size
        except OSError:
            available = False
        coverage = ('limited bundled smoke list' if identifier == 'web-common' else
                    'installed DIRB small path list' if identifier == 'dirb-small' else
                    'installed DIRB common web paths' if identifier == 'dirb-common' else
                    'operator-selected file; choose for the observed surface')
        rows.append({'id': identifier, 'path': str(path)[:512], 'path_truncated': len(str(path)) > 512,
                     'bytes': size, 'available': available,
                     'coverage': coverage})
    return rows
