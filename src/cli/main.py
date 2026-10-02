"""Lightweight console entry point; load the runtime only when needed."""
from __future__ import annotations

import importlib
import sys
from types import ModuleType
from typing import Any

from src.cli.help import print_help
from src.version.version import describe


def _runtime() -> ModuleType:
    runtime = importlib.import_module("src.cli.runtime")
    # Preserve the historical module API, including monkeypatches to runtime
    # globals made by callers importing src.cli.main.
    sys.modules[__name__] = runtime
    return runtime


def __getattr__(name: str) -> Any:
    if name.startswith("__"):
        raise AttributeError(name)
    return getattr(_runtime(), name)


def cli_main() -> int:
    argv = sys.argv[1:]
    if argv and all(arg in {"--help", "-h", "--version", "-v"} for arg in argv):
        if any(arg in {"--version", "-v"} for arg in argv):
            sys.stdout.write(f"{describe()}\n")
        else:
            print_help()
        return 0
    return _runtime().cli_main()


if __name__ == "__main__":
    sys.exit(cli_main())
