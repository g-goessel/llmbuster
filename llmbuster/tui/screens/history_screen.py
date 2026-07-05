from __future__ import annotations

import json

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import DataTable, Input, Select, Static
from textual.widgets._select import NoSelection

from llmbuster.store.sqlite_store import InteractionRecord, SQLiteStore

_MAX_RESPONSE_CHARS = 4000


class HistoryPanel(Vertical):
    CSS = """
    HistoryPanel {
        layout: vertical;
        height: 1fr;
        width: 1fr;
    }
    HistoryPanel #title {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
    }
    HistoryPanel #run-select {
        width: 1fr;
    }
    HistoryPanel #filters {
        height: 3;
    }
    HistoryPanel #filters Input {
        width: 1fr;
        margin-right: 1;
    }
    HistoryPanel #history-table {
        height: 10;
    }
    HistoryPanel #detail {
        height: 1fr;
        width: 1fr;
    }
    HistoryPanel #detail-summary {
        height: 1;
        margin-bottom: 1;
        text-style: bold;
    }
    HistoryPanel #detail-split {
        height: 1fr;
        width: 1fr;
        min-width: 1;
    }
    HistoryPanel #detail-request {
        width: 1fr;
        height: 1fr;
        min-width: 1;
        border: round $panel;
        padding: 0 1;
    }
    HistoryPanel #detail-response {
        width: 1fr;
        height: 1fr;
        min-width: 1;
        border: round $panel;
        padding: 0 1;
    }
    HistoryPanel #detail-request-content,
    HistoryPanel #detail-response-content {
        width: 1fr;
        height: auto;
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
        options = self._run_options()
        yield Static(f"Proxy History — Run {self._run_id}", id="title")
        yield Select(
            options=options,
            value=self._initial_value(options),
            id="run-select",
            allow_blank=True,
        )
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
        with Vertical(id="detail"):
            yield Static("Select a row to view details.", id="detail-summary")
            with Horizontal(id="detail-split"):
                with VerticalScroll(id="detail-request") as req_scroll:
                    req_scroll.border_title = "Request"
                    yield Static(
                        "Select a row to view details.",
                        id="detail-request-content",
                        markup=False,
                    )
                with VerticalScroll(id="detail-response") as resp_scroll:
                    resp_scroll.border_title = "Response"
                    yield Static(
                        "Select a row to view details.",
                        id="detail-response-content",
                        markup=False,
                    )

    def on_mount(self) -> None:
        table = self.query_one("#history-table", DataTable)
        table.styles.height = 10
        table.add_column("id", key="id")
        table.add_column("Category", key="category")
        table.add_column("Payload", key="payload")
        table.add_column("Attempt", key="attempt")
        table.add_column("Mutation", key="mutation")
        table.add_column("Verdict", key="verdict")
        table.add_column("TTFT(ms)", key="ttft")
        table.add_column("TPS", key="tps")
        table.add_column("Detector", key="detector")
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
        if self._store is not None and self._run_id > 0:
            self._records = self._store.interactions_for_run(self._run_id)
        else:
            self._records = []
        self.query_one("#title", Static).update(
            f"Proxy History — Run {self._run_id}"
        )
        self._apply_filters()

    def _apply_filters(self) -> None:
        cat_filter = self.query_one("#category-filter", Input).value.strip().lower()
        verd_filter = self.query_one("#verdict-filter", Input).value.strip().lower()
        table = self.query_one("#history-table", DataTable)
        table.clear()
        filtered: list[InteractionRecord] = []
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
            filtered.append(rec)
        if filtered:
            table.move_cursor(row=0)
            self._render_detail(filtered[0])

    @on(Input.Changed)
    def _on_filter_changed(self, event: Input.Changed) -> None:
        if event.input.id in ("category-filter", "verdict-filter"):
            self._apply_filters()

    @on(Input.Submitted)
    def _on_filter_submitted(self, event: Input.Submitted) -> None:
        if event.input.id in ("category-filter", "verdict-filter"):
            self._apply_filters()

    @on(DataTable.RowHighlighted)
    def _on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._show_row_by_key(event.row_key.value)

    @on(DataTable.RowSelected)
    def _on_row_selected(self, event: DataTable.RowSelected) -> None:
        self._show_row_by_key(event.row_key.value)

    def _show_row_by_key(self, row_key_value: str | None) -> None:
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
        self.query_one("#detail-summary", Static).update(self._format_summary(rec))
        self.query_one("#detail-request-content", Static).update(
            self._format_request_pane(rec)
        )
        self.query_one("#detail-response-content", Static).update(
            self._format_response_pane(rec)
        )

    def _format_summary(self, rec: InteractionRecord) -> str:
        verdict = rec.verdict if rec.verdict else "-"
        detector = rec.detector_id if rec.detector_id else "-"
        ttft = f"{rec.ttft_ms}ms" if rec.ttft_ms is not None else "-"
        duration = f"{rec.duration_ms}ms" if rec.duration_ms is not None else "-"
        tps = f"{rec.tps:.1f}" if rec.tps is not None else "-"
        return (
            f"verdict={verdict}  detector={detector}  "
            f"ttft={ttft}  duration={duration}  tps={tps}"
        )

    def _format_request_pane(self, rec: InteractionRecord) -> str:
        sections = [
            self._format_sent_history(rec),
            self._format_raw_request(rec),
        ]
        return "\n\n".join(sections)

    def _format_response_pane(self, rec: InteractionRecord) -> str:
        sections = [
            self._format_extracted_reply(rec),
            self._format_detector(rec),
            self._format_metrics(rec),
            self._format_raw_response(rec),
        ]
        return "\n\n".join(sections)

    def _format_extracted_reply(self, rec: InteractionRecord) -> str:
        lines = ["=== Extracted Reply ==="]
        text = rec.response_text
        if text is None:
            lines.append("(none)")
        elif len(text) > _MAX_RESPONSE_CHARS:
            lines.append(text[:_MAX_RESPONSE_CHARS] + "\n… (truncated)")
        else:
            lines.append(text)
        return "\n".join(lines)

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
