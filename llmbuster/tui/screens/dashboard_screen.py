from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Label, ProgressBar, Static

from llmbuster.domain.models import OwaspCategory, Verdict
from llmbuster.orchestrator import ProgressEvent

_CATEGORIES: list[str] = [cat.value for cat in OwaspCategory]


class DashboardPanel(Vertical):
    DEFAULT_CSS = """
    DashboardPanel {
        align: center top;
        height: 1fr;
    }
    DashboardPanel #title {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
    }
    DashboardPanel #counters {
        height: 3;
        margin-bottom: 1;
    }
    DashboardPanel #counters Vertical {
        width: 1fr;
        text-align: center;
    }
    DashboardPanel #counters Static {
        text-style: bold;
    }
    DashboardPanel #progress {
        text-align: center;
        margin-bottom: 1;
    }
    DashboardPanel #progress-bar {
        margin-bottom: 1;
    }
    DashboardPanel #category-table {
        width: 1fr;
    }
    """

    def __init__(
        self,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._total_attempted: int = 0
        self._completed: int = 0
        self._findings: int = 0
        self._errors: int = 0
        self._ttft_sum: int = 0
        self._ttft_count: int = 0
        self._tps_sum: float = 0.0
        self._tps_count: int = 0
        self._cat_counts: dict[str, dict[str, int]] = {
            cat: {"total": 0, "vulnerable": 0, "safe": 0, "error": 0}
            for cat in _CATEGORIES
        }

    def compose(self) -> ComposeResult:
        yield Static("Live Dashboard", id="title")
        with Horizontal(id="counters"):
            with Vertical():
                yield Label("Findings")
                yield Static("0", id="findings")
            with Vertical():
                yield Label("TTFT avg (ms)")
                yield Static("0", id="ttft_avg")
            with Vertical():
                yield Label("TPS avg")
                yield Static("0", id="tps_avg")
            with Vertical():
                yield Label("Errors")
                yield Static("0", id="errors")
        yield Static("0 / 0", id="progress")
        yield ProgressBar(
            total=0,
            show_eta=False,
            show_percentage=False,
            id="progress-bar",
        )
        yield DataTable(id="category-table", show_row_labels=False)

    def on_mount(self) -> None:
        table = self.query_one("#category-table", DataTable)
        table.add_column("Category", key="category")
        table.add_column("Total", key="total")
        table.add_column("Vulnerable", key="vulnerable")
        table.add_column("Safe", key="safe")
        table.add_column("Error", key="error")
        for cat in _CATEGORIES:
            table.add_row(cat, 0, 0, 0, 0, key=cat)
        self._refresh_widgets()

    def handle_event(self, event: ProgressEvent) -> None:
        self._apply_event(event)
        if self.is_mounted:
            self._refresh_widgets()

    def _apply_event(self, event: ProgressEvent) -> None:
        cat = event.owasp_category
        if event.phase == "started":
            self._total_attempted += 1
        elif event.phase in ("completed", "error"):
            self._completed += 1
            counts = self._cat_counts.setdefault(
                cat, {"total": 0, "vulnerable": 0, "safe": 0, "error": 0}
            )
            counts["total"] += 1
            if event.verdict is Verdict.VULNERABLE:
                counts["vulnerable"] += 1
                self._findings += 1
            elif event.verdict is Verdict.SAFE:
                counts["safe"] += 1
            elif event.verdict is Verdict.ERROR:
                counts["error"] += 1
                self._errors += 1
        if event.metrics.ttft_ms is not None:
            self._ttft_sum += event.metrics.ttft_ms
            self._ttft_count += 1
        if event.metrics.tps is not None:
            self._tps_sum += event.metrics.tps
            self._tps_count += 1

    def _refresh_widgets(self) -> None:
        self.query_one("#findings", Static).update(str(self._findings))
        ttft = (
            str(int(round(self._ttft_sum / self._ttft_count)))
            if self._ttft_count
            else "0"
        )
        tps = str(self._tps_sum / self._tps_count) if self._tps_count else "0"
        self.query_one("#ttft_avg", Static).update(ttft)
        self.query_one("#tps_avg", Static).update(tps)
        self.query_one("#errors", Static).update(str(self._errors))
        self.query_one("#progress", Static).update(
            f"{self._completed} / {self._total_attempted}"
        )
        bar = self.query_one("#progress-bar", ProgressBar)
        bar.update(total=float(self._total_attempted), progress=float(self._completed))
        table = self.query_one("#category-table", DataTable)
        for cat in _CATEGORIES:
            counts = self._cat_counts[cat]
            table.update_cell(cat, "total", counts["total"])
            table.update_cell(cat, "vulnerable", counts["vulnerable"])
            table.update_cell(cat, "safe", counts["safe"])
            table.update_cell(cat, "error", counts["error"])
