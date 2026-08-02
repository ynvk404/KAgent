from __future__ import annotations

import shutil
import signal
from typing import Callable, NamedTuple

DEFAULT_COLUMNS = 100
DEFAULT_ROWS = 30


class TerminalSize(NamedTuple):
    columns: int
    rows: int


def get_terminal_size() -> TerminalSize:
    size = shutil.get_terminal_size(fallback=(DEFAULT_COLUMNS, DEFAULT_ROWS))
    return TerminalSize(columns=size.columns, rows=size.lines)


def terminal_columns() -> int:
    return get_terminal_size().columns


ResizeListener = Callable[[TerminalSize], None]


class TerminalSizeWatcher:

    def __init__(self) -> None:
        self._listeners: list[ResizeListener] = []
        self._installed = False

    def subscribe(self, listener: ResizeListener) -> Callable[[], None]:
        self._listeners.append(listener)
        self._ensure_installed()

        def unsubscribe() -> None:
            if listener in self._listeners:
                self._listeners.remove(listener)

        return unsubscribe

    def _ensure_installed(self) -> None:
        if self._installed:
            return
        sigwinch = getattr(signal, "SIGWINCH", None)
        if sigwinch is None:
            return
        signal.signal(sigwinch, self._on_resize)
        self._installed = True

    def _on_resize(self, signum, frame) -> None:
        size = get_terminal_size()
        for listener in list(self._listeners):
            listener(size)


terminal_size_watcher = TerminalSizeWatcher()