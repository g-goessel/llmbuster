from __future__ import annotations

from pathlib import Path

import pytest
from textual.app import App
from textual.widgets import DataTable, Input, Static

from llmbuster.domain.models import OwaspCategory, Verdict
from llmbuster.store.sqlite_store import InteractionRecord, RunRecord, SQLiteStore
from llmbuster.tui.screens import HistoryScreen


class _HarnessApp(App[None]):
    pass


def _make_run() -> RunRecord:
    return RunRecord(
        started_at="2026-07-04T12:00:00+00:00",
        target_kind="profile",
        target_name="Bot",
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
    app = _HarnessApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(HistoryScreen(store, run_id))
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, HistoryScreen)
        table = screen.query_one("#history-table", DataTable)
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
    app = _HarnessApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(HistoryScreen(store, run_id))
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, HistoryScreen)
        cat_input = screen.query_one("#category-filter", Input)
        cat_input.focus()
        await pilot.pause()
        for char in "LLM01":
            await pilot.press(char)
            await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        table = screen.query_one("#history-table", DataTable)
        assert table.row_count == 3
        for i in range(table.row_count):
            assert table.get_row_at(i)[1] == "LLM01"
    store.close()


@pytest.mark.asyncio
async def test_verdict_filter(
    seeded_store: tuple[SQLiteStore, int],
) -> None:
    store, run_id = seeded_store
    app = _HarnessApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(HistoryScreen(store, run_id))
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, HistoryScreen)
        verd_input = screen.query_one("#verdict-filter", Input)
        verd_input.value = "vulnerable"
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        table = screen.query_one("#history-table", DataTable)
        assert table.row_count == 2
        for i in range(table.row_count):
            assert table.get_row_at(i)[5] == "vulnerable"
    store.close()


@pytest.mark.asyncio
async def test_row_select_shows_detail(
    seeded_store: tuple[SQLiteStore, int],
) -> None:
    store, run_id = seeded_store
    app = _HarnessApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(HistoryScreen(store, run_id))
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, HistoryScreen)
        table = screen.query_one("#history-table", DataTable)
        table.focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        detail_text = _detail_text(screen)
        assert "system" in detail_text or "user" in detail_text
        assert "Raw Request" in detail_text
        assert '"body": "hi"' in detail_text or "hi" in detail_text
        assert "Raw Response" in detail_text
        assert "raw-response-body" in detail_text
        assert "Detector" in detail_text
        assert "canary" in detail_text
        assert "token PWNED found" in detail_text
        assert "Metrics" in detail_text
        assert "ttft_ms: 12" in detail_text
    store.close()


@pytest.mark.asyncio
async def test_empty_run_shows_empty_table(tmp_path: Path) -> None:
    db = tmp_path / "empty.db"
    store = SQLiteStore(db)
    app = _HarnessApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen(HistoryScreen(store, 9999))
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, HistoryScreen)
        table = screen.query_one("#history-table", DataTable)
        assert table.row_count == 0
    store.close()


def _detail_text(screen: HistoryScreen) -> str:
    detail = screen.query_one("#detail")
    statics = detail.query(Static)
    return "\n".join(str(s.content) for s in statics)
