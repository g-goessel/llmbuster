from __future__ import annotations

from pathlib import Path

import pytest
from textual import on
from textual.app import App, ComposeResult
from textual.pilot import Pilot
from textual.widgets import Button, Input, Label, SelectionList, Static, Switch, TextArea

from llmbuster.tui.screens import ConfigPanel, ScanConfigResult, ScanConfigSubmitted

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
    def __init__(self) -> None:
        super().__init__()
        self.results: list[ScanConfigResult] = []

    def compose(self) -> ComposeResult:
        yield ConfigPanel(id="config-panel")

    @on(ScanConfigSubmitted)
    def _capture(self, event: ScanConfigSubmitted) -> None:
        self.results.append(event.result)


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
async def test_config_panel_loads_form() -> None:
    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(ConfigPanel)
        assert panel.query_one("#target-path", Input) is not None
        assert panel.query_one("#model", Input) is not None
        assert panel.query_one("#system-prompt", TextArea) is not None
        assert panel.query_one("#concurrency", Input) is not None
        assert panel.query_one("#repeat", Input) is not None
        assert panel.query_one("#categories", SelectionList) is not None
        assert panel.query_one("#escalate", Switch) is not None
        assert panel.query_one("#submit", Button) is not None
        assert panel.query_one("#test-load", Button) is not None
        assert panel.query_one("#status", Static) is not None
        assert panel.query_one("#concurrency", Input).value == "5"


@pytest.mark.asyncio
async def test_submit_produces_result(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(ConfigPanel)
        panel.query_one("#target-path", Input).value = str(profile)
        panel.query_one("#system-prompt", TextArea).text = "You are a test."
        panel.query_one("#concurrency", Input).value = "3"
        panel.query_one("#repeat", Input).value = "2"
        categories_list = panel.query_one("#categories", SelectionList)
        categories_list.select("LLM01")
        categories_list.select("LLM06")
        await pilot.pause()
        panel.query_one("#escalate", Switch).value = True
        await _press(pilot, panel.query_one("#submit", Button))
        await pilot.pause()

    assert len(app.results) == 1
    result = app.results[0]
    assert result.loaded_target.name == "Test"
    assert result.system_prompt == "You are a test."
    assert result.concurrency == 3
    assert result.repeat == 2
    assert result.categories == ["LLM01", "LLM06"]
    assert result.escalate is True


@pytest.mark.asyncio
async def test_submit_defaults_when_optional_blank(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(ConfigPanel)
        panel.query_one("#target-path", Input).value = str(profile)
        await _press(pilot, panel.query_one("#submit", Button))
        await pilot.pause()

    assert len(app.results) == 1
    result = app.results[0]
    assert result.concurrency == 5
    assert result.repeat is None
    assert result.categories is None
    assert result.system_prompt is None
    assert result.escalate is False


@pytest.mark.asyncio
async def test_validation_error_shown(tmp_path: Path) -> None:
    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(ConfigPanel)
        panel.query_one("#target-path", Input).value = str(tmp_path / "nonexistent.yaml")
        await _press(pilot, panel.query_one("#submit", Button))
        await pilot.pause()
        status_text = str(panel.query_one("#status", Static).content)
        assert "failed" in status_text.lower()

    assert app.results == []


@pytest.mark.asyncio
async def test_concurrency_validation(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(ConfigPanel)
        panel.query_one("#target-path", Input).value = str(profile)
        panel.query_one("#concurrency", Input).value = "abc"
        await _press(pilot, panel.query_one("#submit", Button))
        await pilot.pause()
        status_text = str(panel.query_one("#status", Static).content)
        assert "concurrency" in status_text.lower()

    assert app.results == []


@pytest.mark.asyncio
async def test_categories_selectionlist_has_all_owasp_categories() -> None:
    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(ConfigPanel)
        categories_list = panel.query_one("#categories", SelectionList)
        assert categories_list.option_count == 10
        values = [opt.value for opt in categories_list.options]
        assert values == [f"LLM{n:02d}" for n in range(1, 11)]


@pytest.mark.asyncio
async def test_categories_empty_means_all(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(ConfigPanel)
        panel.query_one("#target-path", Input).value = str(profile)
        await _press(pilot, panel.query_one("#submit", Button))
        await pilot.pause()

    assert len(app.results) == 1
    assert app.results[0].categories is None


@pytest.mark.asyncio
async def test_categories_selected_passed_through(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(ConfigPanel)
        panel.query_one("#target-path", Input).value = str(profile)
        categories_list = panel.query_one("#categories", SelectionList)
        categories_list.select("LLM01")
        categories_list.select("LLM06")
        await pilot.pause()
        await _press(pilot, panel.query_one("#submit", Button))
        await pilot.pause()

    assert len(app.results) == 1
    assert app.results[0].categories == ["LLM01", "LLM06"]


@pytest.mark.asyncio
async def test_escalate_has_help_text() -> None:
    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(ConfigPanel)
        label = panel.query_one("#escalate-label", Label)
        assert "escalation" in str(label.content).lower()


@pytest.mark.asyncio
async def test_test_load_button_shows_status(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    app = _FormApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(ConfigPanel)
        panel.query_one("#target-path", Input).value = str(profile)
        await _press(pilot, panel.query_one("#test-load", Button))
        await pilot.pause()
        status_text = str(panel.query_one("#status", Static).content)
        assert "loaded" in status_text.lower()
        assert "Test" in status_text

    assert app.results == []


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
    from llmbuster.tui.screens import ConfigPanel as ExportedConfig
    from llmbuster.tui.screens import ScanConfigResult as ExportedResult

    assert ExportedConfig is ConfigPanel
    assert ExportedResult is ScanConfigResult
