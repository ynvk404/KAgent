
from __future__ import annotations

import os
from typing import Literal

ColorLevel = Literal[0, 3]


def no_color_requested() -> bool:
    value = os.getenv("NO_COLOR")
    return value is not None and value != ""


def color_level() -> ColorLevel:
    return 0 if no_color_requested() else 3