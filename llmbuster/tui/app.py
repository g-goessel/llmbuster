from __future__ import annotations

import asyncio
import contextlib

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.events import Unmount
from textual.widgets import Footer, Header

from llmbuster.orchestrator import ProgressEvent, ScanOrchestrator
from llmbuster.tui.screens import (
    ConfigScreen,
    DashboardScreen,
    FindingsScreen,
    HistoryScreen,
)


class LlmBusterApp(App[None]):
    TITLE = "llmbuster"

    CSS = """
    Screen {
        align: center middle;
    }
    #msg {
        padding: 1 2;
        border: round $panel;
        text-align: center;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("ctrl+c", "quit", "Quit", priority=True),
        Binding("1", "go_config", "Config"),
        Binding("2", "go_dashboard", "Dashboard"),
        Binding("3", "go_history", "History"),
        Binding("4", "go_findings", "Findings"),
        Binding("?", "show_help_panel", "Help"),
    ]

    SCREENS = {
        "config": ConfigScreen,
        "dashboard": DashboardScreen,
        "history": HistoryScreen,
        "findings": FindingsScreen,
    }

    def __init__(self) -> None:
        super().__init__()
        self._orchestrator: ScanOrchestrator | None = None
        self._drainer: asyncio.Task[None] | None = None
        self.progress_events: list[ProgressEvent] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()

    async def on_mount(self) -> None:
        self.push_screen("config")
        self._maybe_start_drainer()

    def attach_orchestrator(self, orchestrator: ScanOrchestrator) -> None:
        self._orchestrator = orchestrator
        self._maybe_start_drainer()

    def _maybe_start_drainer(self) -> None:
        if self._orchestrator is None:
            return
        if not self.is_running:
            return
        if self._drainer is not None and not self._drainer.done():
            return
        self._drainer = asyncio.create_task(self._drain())

    async def _drain(self) -> None:
        orchestrator = self._orchestrator
        if orchestrator is None:
            return
        try:
            while True:
                event = await orchestrator.progress_queue.get()
                if event is None:
                    break
                self.progress_events.append(event)
        except asyncio.CancelledError:
            raise

    @on(Unmount)
    async def on_unmount(self) -> None:
        drainer = self._drainer
        if drainer is not None and not drainer.done():
            drainer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await drainer
        self._drainer = None

    def action_go_config(self) -> None:
        self.switch_screen("config")

    def action_go_dashboard(self) -> None:
        self.switch_screen("dashboard")

    def action_go_history(self) -> None:
        self.switch_screen("history")

    def action_go_findings(self) -> None:
        self.switch_screen("findings")
