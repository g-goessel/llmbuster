from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static


class ConfigScreen(Screen[None]):
    def compose(self) -> ComposeResult:
        yield Static("Configuration (T5.2)", id="msg")
