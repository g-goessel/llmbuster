from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static


class FindingsScreen(Screen[None]):
    def compose(self) -> ComposeResult:
        yield Static("Findings Summary (T5.5)", id="msg")
