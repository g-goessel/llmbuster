from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Static


class HistoryScreen(Screen[None]):
    def compose(self) -> ComposeResult:
        yield Static("Proxy History (T5.4)", id="msg")
