"""
Single source of truth for the terminal color level.

When NO_COLOR is set to any non-empty value, ANSI colors are disabled.
Otherwise, the UI assumes full TrueColor support.
"""

from __future__ import annotations

import os
from typing import Literal

ColorLevel = Literal[0, 3]


def no_color_requested() -> bool:
    """Return True if ANSI colors are disabled via NO_COLOR."""
    value = os.getenv("NO_COLOR")
    return value is not None and value != ""


def color_level() -> ColorLevel:
    """Return terminal color level."""
    return 0 if no_color_requested() else 3