from __future__ import annotations

from pathlib import Path

import pytest
from textual.app import App, ComposeResult
from textual.widgets import DataTable, ProgressBar, Static

from llmbuster.domain.models import Metrics, OwaspCategory, Payload, Verdict
from llmbuster.orchestrator import ProgressEvent, ScanConfig, ScanOrchestrator
from llmbuster.tui import LlmBusterApp
from llmbuster.tui.screens.dashboard_screen import DashboardPanel


def _event(
    pid: str = "p1",
    verdict: Verdict = Verdict.SAFE,
    cat: str = OwaspCategory.LLM01.value,
    phase: str = "completed",
    attempt_index: int = 0,
    ttft_ms: int | None = None,
    tps: float | None = None,
) -> ProgressEvent:
    return ProgressEvent(
        payload_id=pid,
        attempt_index=attempt_index,
        mutation=None,
        owasp_category=cat,
        verdict=verdict,
        metrics=Metrics(ttft_ms=ttft_ms, tps=tps),
        phase=phase,
    )


class _StubTarget:
    async def send(self, history: object) -> object:
        from llmbuster.domain.models import ChatHistory, TargetResponse

        assert isinstance(history, ChatHistory)
        return TargetResponse(
            reply="ok",
            raw_request_json=history.to_messages_json(),
            raw_response_text="ok",
            metrics=Metrics(),
        )


def _orchestrator() -> ScanOrchestrator:
    payloads = [Payload(id="p1", prompt="hi", detectors=[])]
    return ScanOrchestrator(
        _StubTarget(),
        ScanConfig(run_id=1, concurrency=1),
        payloads,
        {"p1": OwaspCategory.LLM01},
    )


class _DashApp(App[None]):
    def compose(self) -> ComposeResult:
        yield DashboardPanel(id="dashboard-panel")


@pytest.mark.asyncio
async def test_dashboard_initial_state() -> None:
    app = _DashApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(DashboardPanel)
        assert str(panel.query_one("#findings", Static).content) == "0"
        assert str(panel.query_one("#ttft_avg", Static).content) == "0"
        assert str(panel.query_one("#tps_avg", Static).content) == "0"
        assert str(panel.query_one("#errors", Static).content) == "0"
        assert str(panel.query_one("#progress", Static).content) == "0 / 0"
        assert panel.query_one("#progress-bar", ProgressBar) is not None
        table = panel.query_one("#category-table", DataTable)
        assert table.row_count == 10
        assert table.get_row(OwaspCategory.LLM01.value) == [
            OwaspCategory.LLM01.value,
            0,
            0,
            0,
            0,
        ]
        assert table.get_row(OwaspCategory.LLM10.value) == [
            OwaspCategory.LLM10.value,
            0,
            0,
            0,
            0,
        ]


@pytest.mark.asyncio
async def test_handle_event_updates_counters() -> None:
    app = _DashApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(DashboardPanel)
        panel.handle_event(
            _event(
                verdict=Verdict.VULNERABLE,
                ttft_ms=200,
                tps=10.0,
            )
        )
        assert str(panel.query_one("#findings", Static).content) == "1"
        assert str(panel.query_one("#ttft_avg", Static).content) == "200"
        assert str(panel.query_one("#tps_avg", Static).content) == "10.0"
        assert str(panel.query_one("#errors", Static).content) == "0"


@pytest.mark.asyncio
async def test_per_category_table() -> None:
    app = _DashApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(DashboardPanel)
        panel.handle_event(
            _event(pid="p1", verdict=Verdict.VULNERABLE, cat=OwaspCategory.LLM01.value)
        )
        panel.handle_event(
            _event(pid="p1", verdict=Verdict.SAFE, cat=OwaspCategory.LLM01.value)
        )
        panel.handle_event(
            _event(pid="p2", verdict=Verdict.ERROR, cat=OwaspCategory.LLM02.value)
        )
        table = panel.query_one("#category-table", DataTable)
        assert table.get_row(OwaspCategory.LLM01.value) == [
            OwaspCategory.LLM01.value,
            2,
            1,
            1,
            0,
        ]
        assert table.get_row(OwaspCategory.LLM02.value) == [
            OwaspCategory.LLM02.value,
            1,
            0,
            0,
            1,
        ]
        assert str(panel.query_one("#findings", Static).content) == "1"
        assert str(panel.query_one("#errors", Static).content) == "1"


@pytest.mark.asyncio
async def test_progress_bar_advances() -> None:
    app = _DashApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(DashboardPanel)
        panel.handle_event(_event(pid="a", phase="started"))
        panel.handle_event(_event(pid="b", phase="started"))
        panel.handle_event(
            _event(pid="a", verdict=Verdict.SAFE, phase="completed")
        )
        assert str(panel.query_one("#progress", Static).content) == "1 / 2"
        panel.handle_event(
            _event(pid="b", verdict=Verdict.SAFE, phase="completed")
        )
        assert str(panel.query_one("#progress", Static).content) == "2 / 2"


@pytest.mark.asyncio
async def test_averages_excluded_when_none() -> None:
    app = _DashApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one(DashboardPanel)
        panel.handle_event(_event(ttft_ms=200, tps=10.0))
        assert str(panel.query_one("#ttft_avg", Static).content) == "200"
        assert str(panel.query_one("#tps_avg", Static).content) == "10.0"
        panel.handle_event(_event(ttft_ms=None, tps=None))
        assert str(panel.query_one("#ttft_avg", Static).content) == "200"
        assert str(panel.query_one("#tps_avg", Static).content) == "10.0"


@pytest.mark.asyncio
async def test_via_app_drain_forwards_to_dashboard(tmp_path: Path) -> None:
    app = LlmBusterApp(db_path=tmp_path / "dash.db")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one("#dashboard-panel", DashboardPanel)
        orchestrator = _orchestrator()
        app.attach_orchestrator(orchestrator)
        await orchestrator.progress_queue.put(
            _event(
                pid="p1",
                verdict=Verdict.VULNERABLE,
                ttft_ms=100,
                tps=5.0,
            )
        )
        await orchestrator.progress_queue.put(
            _event(
                pid="p2",
                verdict=Verdict.ERROR,
                cat=OwaspCategory.LLM02.value,
            )
        )
        await orchestrator.progress_queue.put(None)
        await pilot.pause()
        assert app._drainer is not None
        await app._drainer
        assert len(app.progress_events) == 2
        assert str(panel.query_one("#findings", Static).content) == "1"
        assert str(panel.query_one("#errors", Static).content) == "1"
        assert str(panel.query_one("#ttft_avg", Static).content) == "100"
        assert str(panel.query_one("#tps_avg", Static).content) == "5.0"
        table = panel.query_one("#category-table", DataTable)
        assert table.get_row(OwaspCategory.LLM01.value) == [
            OwaspCategory.LLM01.value,
            1,
            1,
            0,
            0,
        ]
        assert table.get_row(OwaspCategory.LLM02.value) == [
            OwaspCategory.LLM02.value,
            1,
            0,
            0,
            1,
        ]


@pytest.mark.asyncio
async def test_drain_collects_when_screen_not_main(tmp_path: Path) -> None:
    app = LlmBusterApp(db_path=tmp_path / "dash.db")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        from textual.screen import Screen

        other = Screen()
        app.push_screen(other)
        await pilot.pause()
        assert app.screen is other
        orchestrator = _orchestrator()
        app.attach_orchestrator(orchestrator)
        await orchestrator.progress_queue.put(
            _event(pid="p1", verdict=Verdict.VULNERABLE, ttft_ms=100, tps=5.0)
        )
        await orchestrator.progress_queue.put(None)
        await pilot.pause()
        assert app._drainer is not None
        await app._drainer
        assert len(app.progress_events) == 1
