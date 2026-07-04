from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static


class DashboardScreen(Screen[None]):
    def compose(self) -> ComposeResult:
        yield Static("Live Dashboard (T5.3)", id="msg")
