from __future__ import annotations

import contextlib
from typing import ClassVar

from textual import on
from textual.app import ComposeResult
from textual.css.query import NoMatches
from textual.screen import Screen
from textual.widgets import ContentSwitcher, Tab, Tabs

from llmbuster.store.sqlite_store import SQLiteStore
from llmbuster.tui.screens.config_screen import ConfigPanel
from llmbuster.tui.screens.dashboard_screen import DashboardPanel
from llmbuster.tui.screens.findings_screen import FindingsPanel
from llmbuster.tui.screens.history_screen import HistoryPanel


class MainScreen(Screen[None]):
    AUTO_FOCUS: ClassVar[str | None] = None

    CSS = """
    MainScreen {
        layout: vertical;
    }
    #nav-tabs {
        height: 3;
    }
    #content {
        height: 1fr;
    }
    """

    def __init__(self, store: SQLiteStore | None = None) -> None:
        super().__init__()
        self._store = store

    def compose(self) -> ComposeResult:
        yield Tabs(
            Tab("Config", id="tab-config"),
            Tab("Dashboard", id="tab-dashboard"),
            Tab("History", id="tab-history"),
            Tab("Findings", id="tab-findings"),
            id="nav-tabs",
            active="tab-config",
        )
        with ContentSwitcher(id="content", initial="config-panel"):
            yield ConfigPanel(id="config-panel")
            yield DashboardPanel(id="dashboard-panel")
            yield HistoryPanel(self._store, id="history-panel")
            yield FindingsPanel(self._store, id="findings-panel")

    @on(Tabs.TabActivated)
    def _on_tab_activated(self, event: Tabs.TabActivated) -> None:
        tab = event.tab
        if tab.id is None:
            return
        name = tab.id.removeprefix("tab-")
        self.query_one("#content", ContentSwitcher).current = f"{name}-panel"

    def get_dashboard(self) -> DashboardPanel | None:
        try:
            return self.query_one("#dashboard-panel", DashboardPanel)
        except NoMatches:
            return None

    def activate_tab(self, tab_id: str) -> None:
        with contextlib.suppress(NoMatches):
            self.query_one("#nav-tabs", Tabs).active = tab_id
