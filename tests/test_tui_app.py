from __future__ import annotations

import pytest

from llmbuster.domain.models import (
    ChatHistory,
    Metrics,
    OwaspCategory,
    Payload,
    TargetResponse,
    Verdict,
)
from llmbuster.orchestrator import ProgressEvent, ScanConfig, ScanOrchestrator
from llmbuster.tui import LlmBusterApp
from llmbuster.tui.screens import (
    ConfigScreen,
    DashboardScreen,
    FindingsScreen,
    HistoryScreen,
)


def _payload(pid: str = "p1", prompt: str = "hi") -> Payload:
    return Payload(id=pid, prompt=prompt, detectors=[])


def _categories(payloads: list[Payload]) -> dict[str, OwaspCategory]:
    return {p.id: OwaspCategory.LLM01 for p in payloads}


class StubTarget:
    async def send(self, history: ChatHistory) -> TargetResponse:
        return TargetResponse(
            reply="ok",
            raw_request_json=history.to_messages_json(),
            raw_response_text="ok",
            metrics=Metrics(),
        )


def _progress_event(pid: str = "p1", verdict: Verdict = Verdict.SAFE) -> ProgressEvent:
    return ProgressEvent(
        payload_id=pid,
        attempt_index=0,
        mutation=None,
        owasp_category=OwaspCategory.LLM01.value,
        verdict=verdict,
        metrics=Metrics(),
        phase="completed",
    )


def _orchestrator() -> ScanOrchestrator:
    payloads = [_payload("p1", "hi")]
    return ScanOrchestrator(
        StubTarget(),
        ScanConfig(run_id=1, concurrency=1),
        payloads,
        _categories(payloads),
    )


@pytest.mark.asyncio
async def test_app_boots_and_quits() -> None:
    app = LlmBusterApp()
    async with app.run_test() as pilot:
        assert isinstance(app.screen, ConfigScreen)
        await pilot.pause()
    assert app.is_running is False


@pytest.mark.asyncio
async def test_navigation_between_screens() -> None:
    app = LlmBusterApp()
    async with app.run_test() as pilot:
        assert isinstance(app.screen, ConfigScreen)

        await pilot.press("2")
        assert isinstance(app.screen, DashboardScreen)

        await pilot.press("3")
        assert isinstance(app.screen, HistoryScreen)

        await pilot.press("4")
        assert isinstance(app.screen, FindingsScreen)

        await pilot.press("1")
        assert isinstance(app.screen, ConfigScreen)


@pytest.mark.asyncio
async def test_quit_binding() -> None:
    app = LlmBusterApp()
    async with app.run_test() as pilot:
        await pilot.press("q")
        await pilot.pause()
    assert app._return_code == 0


@pytest.mark.asyncio
async def test_ctrl_c_quits() -> None:
    app = LlmBusterApp()
    async with app.run_test() as pilot:
        await pilot.press("ctrl+c")
        await pilot.pause()
    assert app._return_code == 0


@pytest.mark.asyncio
async def test_help_panel_binding() -> None:
    from textual.widgets import HelpPanel

    app = LlmBusterApp()
    async with app.run_test() as pilot:
        await pilot.press("?")
        await pilot.pause()
        assert app.screen.query_one(HelpPanel) is not None


@pytest.mark.asyncio
async def test_attach_orchestrator_collects_events() -> None:
    app = LlmBusterApp()
    async with app.run_test() as pilot:
        orchestrator = _orchestrator()
        app.attach_orchestrator(orchestrator)
        await orchestrator.progress_queue.put(_progress_event("p1", Verdict.SAFE))
        await orchestrator.progress_queue.put(_progress_event("p1", Verdict.VULNERABLE))
        await orchestrator.progress_queue.put(None)
        await pilot.pause()
        assert app._drainer is not None
        await app._drainer
        assert len(app.progress_events) == 2
        assert app.progress_events[0].payload_id == "p1"
        assert app.progress_events[1].verdict is Verdict.VULNERABLE


@pytest.mark.asyncio
async def test_clean_teardown_cancels_drainer() -> None:
    app = LlmBusterApp()
    async with app.run_test() as pilot:
        app.attach_orchestrator(_orchestrator())
        await pilot.pause()
        assert app._drainer is not None
        assert not app._drainer.done()
    assert app._drainer is None


@pytest.mark.asyncio
async def test_attach_before_mount_starts_drainer() -> None:
    app = LlmBusterApp()
    orchestrator = _orchestrator()
    app.attach_orchestrator(orchestrator)
    assert app._drainer is None
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app._drainer is not None
        assert not app._drainer.done()
        await orchestrator.progress_queue.put(None)
        await pilot.pause()
        assert app._drainer.done()
