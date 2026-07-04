from __future__ import annotations

import pytest
from textual.widgets import DataTable, ProgressBar, Static

from llmbuster.domain.models import Metrics, OwaspCategory, Payload, Verdict
from llmbuster.orchestrator import ProgressEvent, ScanConfig, ScanOrchestrator
from llmbuster.tui import LlmBusterApp
from llmbuster.tui.screens import DashboardScreen


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


@pytest.mark.asyncio
async def test_dashboard_initial_state() -> None:
    app = LlmBusterApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen("dashboard")
        await pilot.pause()
        screen = app.get_screen("dashboard")
        assert isinstance(screen, DashboardScreen)
        assert str(screen.query_one("#findings", Static).content) == "0"
        assert str(screen.query_one("#ttft_avg", Static).content) == "0"
        assert str(screen.query_one("#tps_avg", Static).content) == "0"
        assert str(screen.query_one("#errors", Static).content) == "0"
        assert str(screen.query_one("#progress", Static).content) == "0 / 0"
        assert screen.query_one("#progress-bar", ProgressBar) is not None
        table = screen.query_one("#category-table", DataTable)
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
    app = LlmBusterApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen("dashboard")
        await pilot.pause()
        screen = app.get_screen("dashboard")
        assert isinstance(screen, DashboardScreen)
        screen.handle_event(
            _event(
                verdict=Verdict.VULNERABLE,
                ttft_ms=200,
                tps=10.0,
            )
        )
        assert str(screen.query_one("#findings", Static).content) == "1"
        assert str(screen.query_one("#ttft_avg", Static).content) == "200"
        assert str(screen.query_one("#tps_avg", Static).content) == "10.0"
        assert str(screen.query_one("#errors", Static).content) == "0"


@pytest.mark.asyncio
async def test_per_category_table() -> None:
    app = LlmBusterApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen("dashboard")
        await pilot.pause()
        screen = app.get_screen("dashboard")
        assert isinstance(screen, DashboardScreen)
        screen.handle_event(
            _event(pid="p1", verdict=Verdict.VULNERABLE, cat=OwaspCategory.LLM01.value)
        )
        screen.handle_event(
            _event(pid="p1", verdict=Verdict.SAFE, cat=OwaspCategory.LLM01.value)
        )
        screen.handle_event(
            _event(pid="p2", verdict=Verdict.ERROR, cat=OwaspCategory.LLM02.value)
        )
        table = screen.query_one("#category-table", DataTable)
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
        assert str(screen.query_one("#findings", Static).content) == "1"
        assert str(screen.query_one("#errors", Static).content) == "1"


@pytest.mark.asyncio
async def test_progress_bar_advances() -> None:
    app = LlmBusterApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen("dashboard")
        await pilot.pause()
        screen = app.get_screen("dashboard")
        assert isinstance(screen, DashboardScreen)
        screen.handle_event(_event(pid="a", phase="started"))
        screen.handle_event(_event(pid="b", phase="started"))
        screen.handle_event(
            _event(pid="a", verdict=Verdict.SAFE, phase="completed")
        )
        assert str(screen.query_one("#progress", Static).content) == "1 / 2"
        screen.handle_event(
            _event(pid="b", verdict=Verdict.SAFE, phase="completed")
        )
        assert str(screen.query_one("#progress", Static).content) == "2 / 2"


@pytest.mark.asyncio
async def test_averages_excluded_when_none() -> None:
    app = LlmBusterApp()
    async with app.run_test(size=(120, 40)) as pilot:
        app.push_screen("dashboard")
        await pilot.pause()
        screen = app.get_screen("dashboard")
        assert isinstance(screen, DashboardScreen)
        screen.handle_event(_event(ttft_ms=200, tps=10.0))
        assert str(screen.query_one("#ttft_avg", Static).content) == "200"
        assert str(screen.query_one("#tps_avg", Static).content) == "10.0"
        screen.handle_event(_event(ttft_ms=None, tps=None))
        assert str(screen.query_one("#ttft_avg", Static).content) == "200"
        assert str(screen.query_one("#tps_avg", Static).content) == "10.0"


@pytest.mark.asyncio
async def test_via_app_drain_forwards_to_dashboard() -> None:
    app = LlmBusterApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.push_screen("dashboard")
        await pilot.pause()
        screen = app.get_screen("dashboard")
        assert isinstance(screen, DashboardScreen)
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
        assert str(screen.query_one("#findings", Static).content) == "1"
        assert str(screen.query_one("#errors", Static).content) == "1"
        assert str(screen.query_one("#ttft_avg", Static).content) == "100"
        assert str(screen.query_one("#tps_avg", Static).content) == "5.0"
        table = screen.query_one("#category-table", DataTable)
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
async def test_drain_does_not_crash_when_dashboard_not_mounted() -> None:
    app = LlmBusterApp()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
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
