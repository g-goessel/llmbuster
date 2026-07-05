from __future__ import annotations

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Label, Select, Static
from textual.widgets._select import NoSelection

from llmbuster.orchestrator.summary import (
    CategorySummary,
    PayloadSummary,
    RunStats,
    summarize_run,
)
from llmbuster.store.sqlite_store import InteractionRecord, SQLiteStore


def _fmt_rate(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value * 100:.1f}%"


def _fmt_latency(value: float | None) -> str:
    if value is None:
        return "-"
    return str(int(round(value)))


def _fmt_tps(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}"


class FindingsPanel(Vertical):
    DEFAULT_CSS = """
    FindingsPanel {
        align: center top;
        height: 1fr;
    }
    FindingsPanel #title {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
    }
    FindingsPanel #run-select {
        margin-bottom: 1;
        width: 1fr;
    }
    FindingsPanel #exec-summary {
        height: 5;
        margin-bottom: 1;
    }
    FindingsPanel #exec-summary Vertical {
        width: 1fr;
        text-align: center;
    }
    FindingsPanel #exec-summary Static {
        text-style: bold;
    }
    FindingsPanel #category-table {
        height: 12;
        margin-bottom: 1;
    }
    FindingsPanel #payload-table {
        height: 1fr;
    }
    """

    def __init__(
        self,
        store: SQLiteStore | None = None,
        run_id: int = 0,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)
        self._store = store
        self._run_id = run_id

    def compose(self) -> ComposeResult:
        options = self._run_options()
        yield Static(f"Findings Summary — Run {self._run_id}", id="title")
        yield Select(
            options=options,
            value=self._initial_value(options),
            id="run-select",
            allow_blank=True,
        )
        with Horizontal(id="exec-summary"):
            with Vertical():
                yield Label("Interactions")
                yield Static("0", id="total-interactions")
            with Vertical():
                yield Label("Vulnerable")
                yield Static("0", id="total-vulnerable")
            with Vertical():
                yield Label("Vuln Rate")
                yield Static("-", id="overall-vuln-rate")
            with Vertical():
                yield Label("Avg TTFT(ms)")
                yield Static("-", id="avg-ttft")
            with Vertical():
                yield Label("Avg TPS")
                yield Static("-", id="avg-tps")
        yield DataTable(id="category-table", cursor_type="row")
        yield DataTable(id="payload-table", cursor_type="row")

    def on_mount(self) -> None:
        category_table = self.query_one("#category-table", DataTable)
        category_table.add_column("Category", key="category")
        category_table.add_column("Total", key="total")
        category_table.add_column("Vulnerable", key="vulnerable")
        category_table.add_column("Safe", key="safe")
        category_table.add_column("Error", key="error")
        category_table.add_column("Vuln Rate", key="vuln_rate")
        category_table.add_column("Avg TTFT(ms)", key="avg_ttft")
        category_table.add_column("Avg TPS", key="avg_tps")
        category_table.add_column("Avg Duration(ms)", key="avg_duration")

        payload_table = self.query_one("#payload-table", DataTable)
        payload_table.add_column("Payload ID", key="payload_id")
        payload_table.add_column("Category", key="category")
        payload_table.add_column("Total", key="total")
        payload_table.add_column("Vulnerable", key="vulnerable")
        payload_table.add_column("Reproducibility", key="reproducibility")
        payload_table.add_column("Rolled-up Verdict", key="verdict")

        select = self.query_one("#run-select", Select)
        value = select.value
        if isinstance(value, int):
            self._run_id = value
        self._reload()

    def _run_options(self) -> list[tuple[str, int]]:
        if self._store is None:
            return []
        options: list[tuple[str, int]] = []
        for run in self._store.list_runs():
            if run.id is None:
                continue
            label = (
                f"#{run.id} — {run.target_name or run.target_kind} ({run.started_at})"
            )
            options.append((label, run.id))
        return options

    def _initial_value(
        self, options: list[tuple[str, int]]
    ) -> int | NoSelection:
        ids = [value for _, value in options]
        if self._run_id in ids:
            return self._run_id
        if ids:
            return ids[0]
        return Select.NULL

    def refresh_runs(self) -> None:
        select = self.query_one("#run-select", Select)
        options = self._run_options()
        select.set_options(options)
        value = self._initial_value(options)
        select.value = value
        if isinstance(value, int):
            self._run_id = value
        self._reload()

    @on(Select.Changed)
    def _on_run_changed(self, event: Select.Changed) -> None:
        if event.control.id == "run-select" and isinstance(event.value, int):
            self._run_id = event.value
            self._reload()

    def _reload(self) -> None:
        records: list[InteractionRecord] = []
        if self._store is not None and self._run_id > 0:
            records = self._store.interactions_for_run(self._run_id)
        self.query_one("#title", Static).update(
            f"Findings Summary — Run {self._run_id}"
        )
        categories, payloads, stats = summarize_run(records)
        self._render_exec(stats)
        self._render_categories(categories)
        self._render_payloads(payloads)

    def _render_exec(self, stats: RunStats) -> None:
        self.query_one("#total-interactions", Static).update(
            str(stats.total_interactions)
        )
        self.query_one("#total-vulnerable", Static).update(str(stats.total_vulnerable))
        rate = (
            stats.overall_vulnerable_rate
            if stats.total_interactions > 0
            else None
        )
        self.query_one("#overall-vuln-rate", Static).update(_fmt_rate(rate))
        self.query_one("#avg-ttft", Static).update(_fmt_latency(stats.avg_ttft_ms))
        self.query_one("#avg-tps", Static).update(_fmt_tps(stats.avg_tps))

    def _render_categories(self, categories: list[CategorySummary]) -> None:
        table = self.query_one("#category-table", DataTable)
        table.clear()
        for cat in categories:
            table.add_row(
                cat.category,
                cat.total,
                cat.vulnerable,
                cat.safe,
                cat.error,
                _fmt_rate(cat.vulnerable_rate),
                _fmt_latency(cat.avg_ttft_ms),
                _fmt_tps(cat.avg_tps),
                _fmt_latency(cat.avg_duration_ms),
                key=cat.category,
            )

    def _render_payloads(self, payloads: list[PayloadSummary]) -> None:
        table = self.query_one("#payload-table", DataTable)
        table.clear()
        for payload in payloads:
            table.add_row(
                payload.payload_id,
                payload.category,
                payload.total,
                payload.vulnerable,
                _fmt_rate(payload.vulnerable_rate),
                payload.rolled_up_verdict.value,
                key=payload.payload_id,
            )
