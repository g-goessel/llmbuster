from __future__ import annotations

import json
from typing import ClassVar

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Input, Static

from llmbuster.store.sqlite_store import InteractionRecord, SQLiteStore

_MAX_RESPONSE_CHARS = 4000


class HistoryScreen(Screen[None]):
    AUTO_FOCUS: ClassVar[str | None] = ""

    CSS = """
    HistoryScreen {
        align: center top;
    }
    HistoryScreen #title {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
    }
    HistoryScreen #filters {
        height: 3;
        margin-bottom: 1;
    }
    HistoryScreen #filters Input {
        width: 1fr;
        margin-right: 1;
    }
    HistoryScreen #history-table {
        height: 12;
        margin-bottom: 1;
    }
    HistoryScreen #detail {
        height: 1fr;
        border: round $panel;
        padding: 0 1;
    }
    HistoryScreen #detail Static {
        margin-bottom: 1;
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
        self._records: list[InteractionRecord] = []

    def compose(self) -> ComposeResult:
        yield Static(f"Proxy History — Run {self._run_id}", id="title")
        with Horizontal(id="filters"):
            yield Input(
                placeholder="Filter by category (e.g. LLM01)",
                id="category-filter",
            )
            yield Input(
                placeholder="Filter by verdict (e.g. vulnerable)",
                id="verdict-filter",
            )
        yield DataTable(id="history-table", cursor_type="row")
        with VerticalScroll(id="detail"):
            yield Static(
                "Select a row to view details.",
                id="detail-sent-history",
                markup=False,
            )
            yield Static("", id="detail-raw-request", markup=False)
            yield Static("", id="detail-raw-response", markup=False)
            yield Static("", id="detail-detector", markup=False)
            yield Static("", id="detail-metrics", markup=False)

    def on_mount(self) -> None:
        table = self.query_one("#history-table", DataTable)
        table.add_column("id", key="id")
        table.add_column("Category", key="category")
        table.add_column("Payload", key="payload")
        table.add_column("Attempt", key="attempt")
        table.add_column("Mutation", key="mutation")
        table.add_column("Verdict", key="verdict")
        table.add_column("TTFT(ms)", key="ttft")
        table.add_column("TPS", key="tps")
        table.add_column("Detector", key="detector")
        self._reload()

    def _reload(self) -> None:
        if self._store is not None:
            self._records = self._store.interactions_for_run(self._run_id)
        else:
            self._records = []
        self._apply_filters()

    def _apply_filters(self) -> None:
        cat_filter = self.query_one("#category-filter", Input).value.strip().lower()
        verd_filter = self.query_one("#verdict-filter", Input).value.strip().lower()
        table = self.query_one("#history-table", DataTable)
        table.clear()
        for rec in self._records:
            if cat_filter and cat_filter not in rec.owasp_category.lower():
                continue
            if verd_filter and verd_filter not in rec.verdict.lower():
                continue
            table.add_row(
                str(rec.id) if rec.id is not None else "",
                rec.owasp_category,
                rec.payload_id,
                str(rec.attempt_index),
                rec.mutation or "",
                rec.verdict,
                str(rec.ttft_ms) if rec.ttft_ms is not None else "",
                f"{rec.tps:.1f}" if rec.tps is not None else "",
                rec.detector_id or "",
                key=str(rec.id) if rec.id is not None else None,
            )

    @on(Input.Changed)
    def _on_filter_changed(self, event: Input.Changed) -> None:
        if event.input.id in ("category-filter", "verdict-filter"):
            self._apply_filters()

    @on(Input.Submitted)
    def _on_filter_submitted(self, event: Input.Submitted) -> None:
        if event.input.id in ("category-filter", "verdict-filter"):
            self._apply_filters()

    @on(DataTable.RowSelected)
    def _on_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key_value = event.row_key.value
        if row_key_value is None:
            return
        try:
            rec_id = int(row_key_value)
        except (TypeError, ValueError):
            return
        record = next((r for r in self._records if r.id == rec_id), None)
        if record is None:
            return
        self._render_detail(record)

    def _render_detail(self, rec: InteractionRecord) -> None:
        self.query_one("#detail-sent-history", Static).update(
            self._format_sent_history(rec)
        )
        self.query_one("#detail-raw-request", Static).update(
            self._format_raw_request(rec)
        )
        self.query_one("#detail-raw-response", Static).update(
            self._format_raw_response(rec)
        )
        self.query_one("#detail-detector", Static).update(self._format_detector(rec))
        self.query_one("#detail-metrics", Static).update(self._format_metrics(rec))

    def _format_sent_history(self, rec: InteractionRecord) -> str:
        lines = ["=== Sent History ==="]
        messages: list[object] | None = None
        try:
            data: object = json.loads(rec.sent_history_json)
        except (json.JSONDecodeError, TypeError):
            data = None
        if isinstance(data, list):
            messages = data
        elif isinstance(data, dict) and isinstance(data.get("messages"), list):
            messages = data["messages"]
        if messages is None:
            lines.append(rec.sent_history_json)
        else:
            for msg in messages:
                if isinstance(msg, dict):
                    role = str(msg.get("role", "?"))
                    content = str(msg.get("content", ""))
                else:
                    role = "?"
                    content = str(msg)
                lines.append(f"[{role}] {content}")
        return "\n".join(lines)

    def _format_raw_request(self, rec: InteractionRecord) -> str:
        lines = ["=== Raw Request ==="]
        try:
            parsed = json.loads(rec.raw_request_json)
            lines.append(json.dumps(parsed, indent=2, ensure_ascii=False))
        except (json.JSONDecodeError, TypeError):
            lines.append(rec.raw_request_json)
        return "\n".join(lines)

    def _format_raw_response(self, rec: InteractionRecord) -> str:
        lines = ["=== Raw Response ==="]
        text = rec.raw_response_text
        if text is None:
            lines.append("(none)")
        elif len(text) > _MAX_RESPONSE_CHARS:
            lines.append(text[:_MAX_RESPONSE_CHARS] + "\n… (truncated)")
        else:
            lines.append(text)
        return "\n".join(lines)

    def _format_detector(self, rec: InteractionRecord) -> str:
        lines = ["=== Detector ==="]
        if rec.detector_id:
            lines.append(f"detector_id: {rec.detector_id}")
            if rec.detector_detail:
                lines.append(f"detector_detail: {rec.detector_detail}")
        else:
            lines.append("(none)")
        return "\n".join(lines)

    def _format_metrics(self, rec: InteractionRecord) -> str:
        lines = ["=== Metrics ==="]
        lines.append(f"ttft_ms: {rec.ttft_ms}")
        lines.append(f"duration_ms: {rec.duration_ms}")
        lines.append(f"tps: {rec.tps}")
        lines.append(f"prompt_tokens: {rec.prompt_tokens}")
        lines.append(f"completion_tokens: {rec.completion_tokens}")
        lines.append(f"verdict: {rec.verdict}")
        return "\n".join(lines)
