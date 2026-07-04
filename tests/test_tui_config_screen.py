from __future__ import annotations

from pathlib import Path

import pytest
from textual.app import App
from textual.pilot import Pilot
from textual.widgets import Button, Input, Static, Switch, TextArea

from llmbuster.tui.screens import ConfigScreen, ScanConfigResult

_PROFILE_YAML = (
    "kind: profile\n"
    'name: "Test"\n'
    "request:\n"
    "  method: POST\n"
    '  url: "http://127.0.0.1:1/chat"\n'
    "  headers:\n"
    '    Content-Type: "application/json"\n'
    "  body: '{\"messages\": ${messages_json}}'\n"
    "response:\n"
    "  type: text\n"
    "session:\n"
    "  mode: stateless\n"
)


class _FormApp(App[None]):
    pass


def _write_profile(tmp_path: Path) -> Path:
    profile = tmp_path / "target.yaml"
    profile.write_text(_PROFILE_YAML, encoding="utf-8")
    return profile


async def _press(pilot: Pilot, button: Button) -> None:
    button.focus()
    await pilot.pause()
    await pilot.press("enter")
    await pilot.pause()


@pytest.mark.asyncio
async def test_config_screen_loads_form() -> None:
    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(ConfigScreen())
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, ConfigScreen)
        assert screen.query_one("#target-path", Input) is not None
        assert screen.query_one("#model", Input) is not None
        assert screen.query_one("#system-prompt", TextArea) is not None
        assert screen.query_one("#concurrency", Input) is not None
        assert screen.query_one("#repeat", Input) is not None
        assert screen.query_one("#categories", Input) is not None
        assert screen.query_one("#escalate", Switch) is not None
        assert screen.query_one("#submit", Button) is not None
        assert screen.query_one("#test-load", Button) is not None
        assert screen.query_one("#status", Static) is not None
        assert screen.query_one("#concurrency", Input).value == "5"


@pytest.mark.asyncio
async def test_submit_produces_result(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)

    results: list[ScanConfigResult | None] = []

    def on_result(result: ScanConfigResult | None) -> None:
        results.append(result)

    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(ConfigScreen(), callback=on_result)
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, ConfigScreen)
        screen.query_one("#target-path", Input).value = str(profile)
        screen.query_one("#system-prompt", TextArea).text = "You are a test."
        screen.query_one("#concurrency", Input).value = "3"
        screen.query_one("#repeat", Input).value = "2"
        screen.query_one("#categories", Input).value = "LLM01,LLM06"
        screen.query_one("#escalate", Switch).value = True
        await _press(pilot, screen.query_one("#submit", Button))
        await pilot.pause()

    assert len(results) == 1
    result = results[0]
    assert result is not None
    assert result.loaded_target.name == "Test"
    assert result.system_prompt == "You are a test."
    assert result.concurrency == 3
    assert result.repeat == 2
    assert result.categories == ["LLM01", "LLM06"]
    assert result.escalate is True


@pytest.mark.asyncio
async def test_submit_defaults_when_optional_blank(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)

    results: list[ScanConfigResult | None] = []

    def on_result(result: ScanConfigResult | None) -> None:
        results.append(result)

    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(ConfigScreen(), callback=on_result)
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, ConfigScreen)
        screen.query_one("#target-path", Input).value = str(profile)
        await _press(pilot, screen.query_one("#submit", Button))
        await pilot.pause()

    assert len(results) == 1
    result = results[0]
    assert result is not None
    assert result.concurrency == 5
    assert result.repeat is None
    assert result.categories is None
    assert result.system_prompt is None
    assert result.escalate is False


@pytest.mark.asyncio
async def test_validation_error_shown(tmp_path: Path) -> None:
    results: list[ScanConfigResult | None] = []

    def on_result(result: ScanConfigResult | None) -> None:
        results.append(result)

    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(ConfigScreen(), callback=on_result)
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, ConfigScreen)
        screen.query_one("#target-path", Input).value = str(tmp_path / "nonexistent.yaml")
        await _press(pilot, screen.query_one("#submit", Button))
        await pilot.pause()
        assert isinstance(app.screen, ConfigScreen)
        status_text = str(screen.query_one("#status", Static).content)
        assert "failed" in status_text.lower()

    assert results == []


@pytest.mark.asyncio
async def test_concurrency_validation(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)

    results: list[ScanConfigResult | None] = []

    def on_result(result: ScanConfigResult | None) -> None:
        results.append(result)

    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(ConfigScreen(), callback=on_result)
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, ConfigScreen)
        screen.query_one("#target-path", Input).value = str(profile)
        screen.query_one("#concurrency", Input).value = "abc"
        await _press(pilot, screen.query_one("#submit", Button))
        await pilot.pause()
        assert isinstance(app.screen, ConfigScreen)
        status_text = str(screen.query_one("#status", Static).content)
        assert "concurrency" in status_text.lower()

    assert results == []


@pytest.mark.asyncio
async def test_categories_validation(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)

    results: list[ScanConfigResult | None] = []

    def on_result(result: ScanConfigResult | None) -> None:
        results.append(result)

    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(ConfigScreen(), callback=on_result)
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, ConfigScreen)
        screen.query_one("#target-path", Input).value = str(profile)
        screen.query_one("#categories", Input).value = "LLM01,BOGUS"
        await _press(pilot, screen.query_one("#submit", Button))
        await pilot.pause()
        assert isinstance(app.screen, ConfigScreen)
        status_text = str(screen.query_one("#status", Static).content)
        assert "bogus" in status_text.lower()

    assert results == []


@pytest.mark.asyncio
async def test_test_load_button_shows_status(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)

    results: list[ScanConfigResult | None] = []

    def on_result(result: ScanConfigResult | None) -> None:
        results.append(result)

    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(ConfigScreen(), callback=on_result)
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, ConfigScreen)
        screen.query_one("#target-path", Input).value = str(profile)
        await _press(pilot, screen.query_one("#test-load", Button))
        await pilot.pause()
        assert isinstance(app.screen, ConfigScreen)
        status_text = str(screen.query_one("#status", Static).content)
        assert "loaded" in status_text.lower()
        assert "Test" in status_text

    assert results == []


def test_scan_config_result_dataclass_fields() -> None:
    import dataclasses

    names = {f.name for f in dataclasses.fields(ScanConfigResult)}
    assert names == {
        "loaded_target",
        "system_prompt",
        "concurrency",
        "repeat",
        "categories",
        "escalate",
    }


def test_exports_available() -> None:
    from llmbuster.tui.screens import ConfigScreen as ExportedConfig
    from llmbuster.tui.screens import ScanConfigResult as ExportedResult

    assert ExportedConfig is ConfigScreen
    assert ExportedResult is ScanConfigResult
