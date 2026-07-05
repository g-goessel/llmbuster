from __future__ import annotations

from pathlib import Path

import pytest
from textual.app import App, ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, Input, Select, Static

from llmbuster.domain.models import OwaspCategory, Verdict
from llmbuster.store.sqlite_store import InteractionRecord, RunRecord, SQLiteStore
from llmbuster.tui.screens import HistoryPanel


class _HarnessApp(App[None]):
    def __init__(self, panel: Widget) -> None:
        super().__init__()
        self._panel = panel

    def compose(self) -> ComposeResult:
        yield self._panel


def _make_run(target_name: str = "Bot") -> RunRecord:
    return RunRecord(
        started_at="2026-07-04T12:00:00+00:00",
        target_kind="profile",
        target_name=target_name,
        model="gpt-x",
        system_prompt="you are bot",
        config_json='{"repeat":3}',
    )


def _make_interaction(
    run_id: int,
    *,
    payload_id: str,
    owasp: OwaspCategory,
    attempt: int,
    verdict: Verdict,
    mutation: str | None = None,
) -> InteractionRecord:
    return InteractionRecord(
        run_id=run_id,
        payload_id=payload_id,
        owasp_category=owasp.value,
        attempt_index=attempt,
        mutation=mutation,
        escalation_from=None,
        sent_history_json='{"messages":[{"role":"system","content":"you are bot"},'
        '{"role":"user","content":"hi"}]}',
        raw_request_json='{"body":"hi","model":"gpt-x"}',
        raw_response_text="raw-response-body",
        response_text="PWNED",
        ttft_ms=12,
        duration_ms=300,
        tps=42.5,
        prompt_tokens=5,
        completion_tokens=9,
        verdict=verdict.value,
        detector_id="canary",
        detector_detail="token PWNED found",
        created_at="2026-07-04T12:00:01+00:00",
    )


def _seed_run(store: SQLiteStore, n: int = 5) -> int:
    run_id = store.create_run(_make_run())
    specs: list[tuple[str, OwaspCategory, int, Verdict, str | None]] = [
        ("p1", OwaspCategory.LLM01, 0, Verdict.VULNERABLE, None),
        ("p2", OwaspCategory.LLM01, 0, Verdict.SAFE, None),
        ("p3", OwaspCategory.LLM02, 0, Verdict.ERROR, None),
        ("p4", OwaspCategory.LLM02, 1, Verdict.VULNERABLE, "base64"),
        ("p5", OwaspCategory.LLM01, 0, Verdict.INCONCLUSIVE, None),
    ]
    for i in range(n):
        payload_id, owasp, attempt, verdict, mutation = specs[i % len(specs)]
        store.insert_interaction(
            _make_interaction(
                run_id,
                payload_id=payload_id,
                owasp=owasp,
                attempt=attempt,
                verdict=verdict,
                mutation=mutation,
            )
        )
    return run_id


@pytest.fixture
def seeded_store(tmp_path: Path) -> tuple[SQLiteStore, int]:
    db = tmp_path / "history.db"
    store = SQLiteStore(db)
    run_id = _seed_run(store, n=5)
    return store, run_id


@pytest.mark.asyncio
async def test_table_renders_all_interactions(
    seeded_store: tuple[SQLiteStore, int],
) -> None:
    store, run_id = seeded_store
    app = _HarnessApp(HistoryPanel(store, run_id))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(HistoryPanel)
        table = panel.query_one("#history-table", DataTable)
        assert table.row_count == 5
        columns = [str(c.label) for c in table.ordered_columns]
        assert columns == [
            "id",
            "Category",
            "Payload",
            "Attempt",
            "Mutation",
            "Verdict",
            "TTFT(ms)",
            "TPS",
            "Detector",
        ]
    store.close()


@pytest.mark.asyncio
async def test_category_filter(
    seeded_store: tuple[SQLiteStore, int],
) -> None:
    store, run_id = seeded_store
    app = _HarnessApp(HistoryPanel(store, run_id))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(HistoryPanel)
        cat_input = panel.query_one("#category-filter", Input)
        cat_input.focus()
        await pilot.pause()
        for char in "LLM01":
            await pilot.press(char)
            await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        table = panel.query_one("#history-table", DataTable)
        assert table.row_count == 3
        for i in range(table.row_count):
            assert table.get_row_at(i)[1] == "LLM01"
    store.close()


@pytest.mark.asyncio
async def test_verdict_filter(
    seeded_store: tuple[SQLiteStore, int],
) -> None:
    store, run_id = seeded_store
    app = _HarnessApp(HistoryPanel(store, run_id))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(HistoryPanel)
        verd_input = panel.query_one("#verdict-filter", Input)
        verd_input.value = "vulnerable"
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        table = panel.query_one("#history-table", DataTable)
        assert table.row_count == 2
        for i in range(table.row_count):
            assert table.get_row_at(i)[5] == "vulnerable"
    store.close()


@pytest.mark.asyncio
async def test_row_select_shows_detail(
    seeded_store: tuple[SQLiteStore, int],
) -> None:
    store, run_id = seeded_store
    app = _HarnessApp(HistoryPanel(store, run_id))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(HistoryPanel)
        table = panel.query_one("#history-table", DataTable)
        table.focus()
        await pilot.pause()
        assert "Sent History" in _request_text(panel)
        assert "Raw Response" in _response_text(panel)
        assert "vulnerable" in _summary_text(panel)
        await pilot.press("enter")
        await pilot.pause()
        request_text = _request_text(panel)
        response_text = _response_text(panel)
        summary_text = _summary_text(panel)
        assert "Sent History" in request_text
        assert "Raw Request" in request_text
        assert '"body": "hi"' in request_text
        assert "Raw Response" in response_text
        assert "raw-response-body" in response_text
        assert "Detector" in response_text
        assert "canary" in response_text
        assert "token PWNED found" in response_text
        assert "Metrics" in response_text
        assert "ttft_ms: 12" in response_text
        assert "vulnerable" in summary_text
        assert "canary" in summary_text
    store.close()


@pytest.mark.asyncio
async def test_first_row_auto_highlighted_on_load(
    seeded_store: tuple[SQLiteStore, int],
) -> None:
    store, run_id = seeded_store
    app = _HarnessApp(HistoryPanel(store, run_id))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await pilot.pause()
        panel = app.query_one(HistoryPanel)
        assert "Sent History" in _request_text(panel)
        assert "Raw Request" in _request_text(panel)
        assert "Raw Response" in _response_text(panel)
        assert "raw-response-body" in _response_text(panel)
        assert "vulnerable" in _summary_text(panel)
        table = panel.query_one("#history-table", DataTable)
        assert table.cursor_coordinate.row == 0
    store.close()


@pytest.mark.asyncio
async def test_arrow_keys_update_detail(
    seeded_store: tuple[SQLiteStore, int],
) -> None:
    store, run_id = seeded_store
    app = _HarnessApp(HistoryPanel(store, run_id))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(HistoryPanel)
        table = panel.query_one("#history-table", DataTable)
        table.focus()
        await pilot.pause()
        assert "vulnerable" in _summary_text(panel)
        await pilot.press("down")
        await pilot.pause()
        assert table.cursor_coordinate.row == 1
        assert "safe" in _summary_text(panel)
        assert "verdict: safe" in _response_text(panel)
        await pilot.press("up")
        await pilot.pause()
        assert table.cursor_coordinate.row == 0
        assert "vulnerable" in _summary_text(panel)
    store.close()


@pytest.mark.asyncio
async def test_response_pane_visible(
    seeded_store: tuple[SQLiteStore, int],
) -> None:
    store, run_id = seeded_store
    app = _HarnessApp(HistoryPanel(store, run_id))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(HistoryPanel)
        table = panel.query_one("#history-table", DataTable)
        table.focus()
        await pilot.pause()
        response_pane = panel.query_one("#detail-response", Widget)
        assert response_pane.outer_size.width > 0
        assert response_pane.outer_size.height > 0
        response_text = _response_text(panel)
        assert "Raw Response" in response_text
        assert "raw-response-body" in response_text
    store.close()


@pytest.mark.asyncio
async def test_empty_run_shows_empty_table(tmp_path: Path) -> None:
    db = tmp_path / "empty.db"
    store = SQLiteStore(db)
    app = _HarnessApp(HistoryPanel(store, 9999))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(HistoryPanel)
        table = panel.query_one("#history-table", DataTable)
        assert table.row_count == 0
    store.close()


@pytest.mark.asyncio
async def test_run_picker_lists_runs(
    seeded_store: tuple[SQLiteStore, int],
) -> None:
    store, run_id = seeded_store
    app = _HarnessApp(HistoryPanel(store, run_id))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(HistoryPanel)
        select = panel.query_one("#run-select", Select)
        assert select.value == run_id
        assert isinstance(select.value, int)
    store.close()


@pytest.mark.asyncio
async def test_run_picker_switches_run(tmp_path: Path) -> None:
    db = tmp_path / "multi.db"
    store = SQLiteStore(db)
    older_id = store.create_run(_make_run("Older"))
    for pid in ("p1", "p2", "p3"):
        store.insert_interaction(
            _make_interaction(
                older_id,
                payload_id=pid,
                owasp=OwaspCategory.LLM01,
                attempt=0,
                verdict=Verdict.VULNERABLE,
            )
        )
    newer_id = store.create_run(_make_run("Newer"))
    store.insert_interaction(
        _make_interaction(
            newer_id,
            payload_id="only-new",
            owasp=OwaspCategory.LLM02,
            attempt=0,
            verdict=Verdict.SAFE,
        )
    )

    app = _HarnessApp(HistoryPanel(store))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(HistoryPanel)
        select = panel.query_one("#run-select", Select)
        assert select.value == newer_id
        table = panel.query_one("#history-table", DataTable)
        assert table.row_count == 1

        select.value = older_id
        await pilot.pause()
        await pilot.pause()
        assert select.value == older_id
        assert table.row_count == 3
    store.close()


@pytest.mark.asyncio
async def test_run_picker_empty_when_no_runs(tmp_path: Path) -> None:
    db = tmp_path / "noruns.db"
    store = SQLiteStore(db)
    app = _HarnessApp(HistoryPanel(store))
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(HistoryPanel)
        select = panel.query_one("#run-select", Select)
        assert select.value == Select.NULL
        table = panel.query_one("#history-table", DataTable)
        assert table.row_count == 0
    store.close()


def _request_text(panel: HistoryPanel) -> str:
    return str(panel.query_one("#detail-request-content", Static).content)


def _response_text(panel: HistoryPanel) -> str:
    return str(panel.query_one("#detail-response-content", Static).content)


def _summary_text(panel: HistoryPanel) -> str:
    return str(panel.query_one("#detail-summary", Static).content)
