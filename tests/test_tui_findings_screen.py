from __future__ import annotations

from pathlib import Path

import pytest
from textual.app import App
from textual.widgets import DataTable, Static
from textual.widgets._data_table import RowDoesNotExist

from llmbuster.domain.models import OwaspCategory, Verdict
from llmbuster.store.sqlite_store import InteractionRecord, RunRecord, SQLiteStore
from llmbuster.tui.screens import FindingsScreen


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
    ttft_ms: int | None = None,
    tps: float | None = None,
    duration_ms: int | None = None,
) -> InteractionRecord:
    return InteractionRecord(
        run_id=run_id,
        payload_id=payload_id,
        owasp_category=owasp.value,
        attempt_index=attempt,
        mutation=None,
        escalation_from=None,
        sent_history_json='{"messages":[{"role":"user","content":"hi"}]}',
        raw_request_json='{"body":"hi"}',
        raw_response_text="raw-response",
        response_text="reply",
        ttft_ms=ttft_ms,
        duration_ms=duration_ms,
        tps=tps,
        prompt_tokens=5,
        completion_tokens=9,
        verdict=verdict.value,
        detector_id="canary",
        detector_detail="token found",
        created_at="2026-07-04T12:00:01+00:00",
    )


def _seed_run(store: SQLiteStore) -> int:
    run_id = store.create_run(_make_run())
    store.insert_interaction(
        _make_interaction(
            run_id,
            payload_id="p1",
            owasp=OwaspCategory.LLM01,
            attempt=0,
            verdict=Verdict.VULNERABLE,
            ttft_ms=100,
            tps=10.0,
            duration_ms=200,
        )
    )
    store.insert_interaction(
        _make_interaction(
            run_id,
            payload_id="p1",
            owasp=OwaspCategory.LLM01,
            attempt=1,
            verdict=Verdict.SAFE,
            ttft_ms=200,
            tps=20.0,
            duration_ms=400,
        )
    )
    store.insert_interaction(
        _make_interaction(
            run_id,
            payload_id="p2",
            owasp=OwaspCategory.LLM06,
            attempt=0,
            verdict=Verdict.VULNERABLE,
            ttft_ms=150,
            tps=15.0,
            duration_ms=300,
        )
    )
    store.insert_interaction(
        _make_interaction(
            run_id,
            payload_id="p2",
            owasp=OwaspCategory.LLM06,
            attempt=1,
            verdict=Verdict.SAFE,
            ttft_ms=None,
            tps=None,
            duration_ms=None,
        )
    )
    store.insert_interaction(
        _make_interaction(
            run_id,
            payload_id="p2",
            owasp=OwaspCategory.LLM06,
            attempt=2,
            verdict=Verdict.ERROR,
            ttft_ms=300,
            tps=30.0,
            duration_ms=600,
        )
    )
    store.insert_interaction(
        _make_interaction(
            run_id,
            payload_id="p3",
            owasp=OwaspCategory.LLM03,
            attempt=0,
            verdict=Verdict.SAFE,
            ttft_ms=50,
            tps=5.0,
            duration_ms=100,
        )
    )
    store.insert_interaction(
        _make_interaction(
            run_id,
            payload_id="p3",
            owasp=OwaspCategory.LLM03,
            attempt=1,
            verdict=Verdict.SAFE,
            ttft_ms=70,
            tps=7.0,
            duration_ms=140,
        )
    )
    return run_id


@pytest.fixture
def seeded_store(tmp_path: Path) -> tuple[SQLiteStore, int]:
    db = tmp_path / "findings.db"
    store = SQLiteStore(db)
    run_id = _seed_run(store)
    return store, run_id


@pytest.mark.asyncio
async def test_findings_screen_renders(
    seeded_store: tuple[SQLiteStore, int],
) -> None:
    store, run_id = seeded_store
    app = _HarnessApp()
    async with app.run_test(size=(140, 44)) as pilot:
        app.push_screen(FindingsScreen(store, run_id))
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, FindingsScreen)
        assert str(screen.query_one("#total-interactions", Static).content) == "7"
        assert str(screen.query_one("#total-vulnerable", Static).content) == "2"
        assert str(screen.query_one("#overall-vuln-rate", Static).content) == "28.6%"
        category_table = screen.query_one("#category-table", DataTable)
        payload_table = screen.query_one("#payload-table", DataTable)
        assert category_table.row_count == 3
        assert payload_table.row_count == 2
    store.close()


@pytest.mark.asyncio
async def test_category_table_values(
    seeded_store: tuple[SQLiteStore, int],
) -> None:
    store, run_id = seeded_store
    app = _HarnessApp()
    async with app.run_test(size=(140, 44)) as pilot:
        app.push_screen(FindingsScreen(store, run_id))
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, FindingsScreen)
        table = screen.query_one("#category-table", DataTable)
        assert [str(c.label) for c in table.ordered_columns] == [
            "Category",
            "Total",
            "Vulnerable",
            "Safe",
            "Error",
            "Vuln Rate",
            "Avg TTFT(ms)",
            "Avg TPS",
            "Avg Duration(ms)",
        ]
        assert table.get_row("LLM01") == [
            "LLM01",
            2,
            1,
            1,
            0,
            "50.0%",
            "150",
            "15.00",
            "300",
        ]
        assert table.get_row("LLM06") == [
            "LLM06",
            3,
            1,
            1,
            1,
            "33.3%",
            "225",
            "22.50",
            "450",
        ]
        assert table.get_row("LLM03") == [
            "LLM03",
            2,
            0,
            2,
            0,
            "0.0%",
            "60",
            "6.00",
            "120",
        ]
    store.close()


@pytest.mark.asyncio
async def test_payload_table_only_vulnerable(
    seeded_store: tuple[SQLiteStore, int],
) -> None:
    store, run_id = seeded_store
    app = _HarnessApp()
    async with app.run_test(size=(140, 44)) as pilot:
        app.push_screen(FindingsScreen(store, run_id))
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, FindingsScreen)
        table = screen.query_one("#payload-table", DataTable)
        assert [str(c.label) for c in table.ordered_columns] == [
            "Payload ID",
            "Category",
            "Total",
            "Vulnerable",
            "Reproducibility",
            "Rolled-up Verdict",
        ]
        assert table.row_count == 2
        assert table.get_row("p1") == [
            "p1",
            "LLM01",
            2,
            1,
            "50.0%",
            "vulnerable",
        ]
        assert table.get_row("p2") == [
            "p2",
            "LLM06",
            3,
            1,
            "33.3%",
            "vulnerable",
        ]
        with pytest.raises(RowDoesNotExist):
            table.get_row("p3")
    store.close()


@pytest.mark.asyncio
async def test_empty_run_no_crash(tmp_path: Path) -> None:
    db = tmp_path / "empty.db"
    store = SQLiteStore(db)
    run_id = store.create_run(_make_run())
    app = _HarnessApp()
    async with app.run_test(size=(140, 44)) as pilot:
        app.push_screen(FindingsScreen(store, run_id))
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, FindingsScreen)
        assert str(screen.query_one("#total-interactions", Static).content) == "0"
        assert str(screen.query_one("#total-vulnerable", Static).content) == "0"
        assert str(screen.query_one("#overall-vuln-rate", Static).content) == "-"
        assert str(screen.query_one("#avg-ttft", Static).content) == "-"
        assert str(screen.query_one("#avg-tps", Static).content) == "-"
        category_table = screen.query_one("#category-table", DataTable)
        payload_table = screen.query_one("#payload-table", DataTable)
        assert category_table.row_count == 0
        assert payload_table.row_count == 0
    store.close()
