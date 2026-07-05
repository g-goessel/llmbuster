from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.events import Unmount
from textual.widgets import Footer, Header

from llmbuster.orchestrator import ProgressEvent, ScanOrchestrator
from llmbuster.store.sqlite_store import SQLiteStore
from llmbuster.tui.screens import (
    MainScreen,
    ScanConfigResult,
    ScanConfigSubmitted,
)


class LlmBusterApp(App[None]):
    TITLE = "llmbuster"

    CSS = """
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

    def __init__(self, db_path: Path = Path("./llmbuster.db")) -> None:
        super().__init__()
        self.db_path = db_path
        self._orchestrator: ScanOrchestrator | None = None
        self._drainer: asyncio.Task[None] | None = None
        self.progress_events: list[ProgressEvent] = []
        self._store: SQLiteStore | None = None
        self.last_config: ScanConfigResult | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()

    async def on_mount(self) -> None:
        self._store = SQLiteStore(self.db_path)
        self.push_screen(MainScreen(self._store))
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
                screen = self.screen
                if isinstance(screen, MainScreen):
                    panel = screen.get_dashboard()
                    if panel is not None:
                        panel.handle_event(event)
        except asyncio.CancelledError:
            raise

    @on(ScanConfigSubmitted)
    def _on_scan_config_submitted(self, event: ScanConfigSubmitted) -> None:
        self.last_config = event.result

    @on(Unmount)
    async def on_unmount(self) -> None:
        drainer = self._drainer
        if drainer is not None and not drainer.done():
            drainer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await drainer
        self._drainer = None
        if self._store is not None:
            self._store.close()
            self._store = None

    def action_go_config(self) -> None:
        self._activate_tab("tab-config")

    def action_go_dashboard(self) -> None:
        self._activate_tab("tab-dashboard")

    def action_go_history(self) -> None:
        self._activate_tab("tab-history")

    def action_go_findings(self) -> None:
        self._activate_tab("tab-findings")

    def _activate_tab(self, tab_id: str) -> None:
        screen = self.screen
        if isinstance(screen, MainScreen):
            screen.activate_tab(tab_id)

