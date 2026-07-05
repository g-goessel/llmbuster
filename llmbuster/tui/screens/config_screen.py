from __future__ import annotations

from dataclasses import dataclass

from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.message import Message
from textual.widgets import Button, Input, Label, SelectionList, Static, Switch, TextArea
from textual.widgets.selection_list import Selection

from llmbuster.domain.models import OwaspCategory
from llmbuster.target.factory import LoadedTarget, TargetLoadError, load_target


@dataclass
class ScanConfigResult:
    loaded_target: LoadedTarget
    system_prompt: str | None
    concurrency: int
    repeat: int | None
    categories: list[str] | None
    escalate: bool


class ScanConfigSubmitted(Message):
    """Posted by the config panel when the user starts a scan."""

    def __init__(self, result: ScanConfigResult) -> None:
        super().__init__()
        self.result = result


class ConfigPanel(Vertical):
    CSS = """
    ConfigPanel {
        height: 1fr;
    }
    ConfigPanel > VerticalScroll {
        width: 80;
        max-width: 90%;
        height: 1fr;
        padding: 1 2;
    }
    ConfigPanel #title {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
    }
    ConfigPanel Label {
        margin-top: 1;
    }
    ConfigPanel #system-prompt {
        height: 5;
    }
    ConfigPanel #status {
        margin-top: 1;
        color: $warning;
    }
    ConfigPanel #categories {
        height: auto;
        max-height: 12;
        margin-bottom: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static("Scan Configuration", id="title")
            yield Label("Target profile path:")
            yield Input(placeholder="path/to/target.yaml", id="target-path")
            yield Label("OpenRouter model id (optional, only for openrouter targets):")
            yield Input(placeholder="openai/gpt-4o", id="model")
            yield Label("System prompt:")
            yield TextArea(id="system-prompt")
            yield Label("Concurrency:")
            yield Input(value="5", id="concurrency")
            yield Label("Repeat count (optional, blank = payload defaults):")
            yield Input(value="", id="repeat")
            yield Label("Categories (leave all unchecked = all OWASP categories):")
            yield SelectionList[str](
                *(
                    Selection(prompt=cat.value, value=cat.value, id=cat.value)
                    for cat in OwaspCategory
                ),
                id="categories",
            )
            yield Label(
                "Escalate (enable escalation chains for vulnerable payloads):",
                id="escalate-label",
            )
            yield Switch(id="escalate")
            yield Button("Test load", id="test-load")
            yield Button("Start Scan", id="submit", variant="primary")
            yield Static("", id="status")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            self._submit()
        elif event.button.id == "test-load":
            self._test_load()

    def _set_status(self, message: str) -> None:
        self.query_one("#status", Static).update(message)

    def _test_load(self) -> None:
        path = self.query_one("#target-path", Input).value.strip()
        if not path:
            self._set_status("Target profile path is required.")
            return
        try:
            loaded = load_target(path)
        except TargetLoadError as exc:
            self._set_status(f"Failed to load target: {exc}")
            return
        self._set_status(f"Loaded: {loaded.name} ({loaded.kind.value}).")

    def _submit(self) -> None:
        path = self.query_one("#target-path", Input).value.strip()
        if not path:
            self._set_status("Target profile path is required.")
            return
        try:
            loaded = load_target(path)
        except TargetLoadError as exc:
            self._set_status(f"Failed to load target: {exc}")
            return

        concurrency_text = self.query_one("#concurrency", Input).value.strip()
        if concurrency_text == "":
            concurrency = 5
        else:
            try:
                concurrency = int(concurrency_text)
            except ValueError:
                self._set_status("Concurrency must be an integer.")
                return
            if concurrency < 1:
                self._set_status("Concurrency must be >= 1.")
                return

        repeat_text = self.query_one("#repeat", Input).value.strip()
        repeat: int | None = None
        if repeat_text != "":
            try:
                repeat = int(repeat_text)
            except ValueError:
                self._set_status("Repeat count must be an integer.")
                return
            if repeat < 1:
                self._set_status("Repeat count must be >= 1.")
                return

        selected = self.query_one("#categories", SelectionList).selected
        categories: list[str] | None = sorted(selected) if selected else None

        system_text = self.query_one("#system-prompt", TextArea).text
        system_prompt = system_text.strip() or None

        escalate = self.query_one("#escalate", Switch).value

        self._set_status("Configuration ready — starting scan.")
        self.post_message(
            ScanConfigSubmitted(
                ScanConfigResult(
                    loaded_target=loaded,
                    system_prompt=system_prompt,
                    concurrency=concurrency,
                    repeat=repeat,
                    categories=categories,
                    escalate=escalate,
                )
            )
        )
