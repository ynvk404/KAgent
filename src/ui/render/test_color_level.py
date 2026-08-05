# tests/ui/render/test_color_level.py

from __future__ import annotations

from src.ui.render.color_level import color_level, no_color_requested


def test_forces_truecolor_by_default(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)

    assert no_color_requested() is False
    assert color_level() == 3


def test_drops_to_level_0_when_no_color_is_set(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")

    assert no_color_requested() is True
    assert color_level() == 0


def test_empty_no_color_is_treated_as_not_set(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "")

    assert no_color_requested() is False
    assert color_level() == 3