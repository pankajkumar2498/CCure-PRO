"""Prevent production scanning from silently using an unreviewed browser."""

import ast
from pathlib import Path

import pytest

from core.web.browser_runtime import launch_options


def test_release_channel_is_explicit_and_never_falls_back(monkeypatch):
    monkeypatch.setenv("CCURE_BROWSER_CHANNEL", "chrome")
    assert launch_options() == {"channel": "chrome"}
    monkeypatch.setenv("CCURE_BROWSER_CHANNEL", "chrome-beta")
    with pytest.raises(ValueError, match="unset or chrome"):
        launch_options()


def test_unconfigured_development_preserves_playwright_default(monkeypatch):
    monkeypatch.delenv("CCURE_BROWSER_CHANNEL", raising=False)
    assert launch_options() == {"channel": None}


def test_every_production_browser_launch_uses_the_reviewed_channel():
    root = Path(__file__).resolve().parents[2] / "core" / "web"
    launches = []
    for path in root.rglob("*.py"):
        for call in ast.walk(ast.parse(path.read_text())):
            if not isinstance(call, ast.Call) or not isinstance(
                call.func, ast.Attribute
            ):
                continue
            if call.func.attr not in ("launch", "launch_persistent_context"):
                continue
            receiver = call.func.value
            if not isinstance(receiver, ast.Attribute) or receiver.attr != "chromium":
                continue
            launches.append(path)
            assert any(
                keyword.arg is None
                and isinstance(keyword.value, ast.Call)
                and isinstance(keyword.value.func, ast.Name)
                and keyword.value.func.id == "launch_options"
                for keyword in call.keywords
            ), f"{path}:{call.lineno} bypasses the reviewed browser channel"
    assert len(launches) == 5
