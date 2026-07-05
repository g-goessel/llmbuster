from __future__ import annotations

from pathlib import Path

import pytest
from textual.pilot import Pilot
from textual.widgets import ContentSwitcher, HelpPanel, Select, Tab, Tabs

from llmbuster.domain.models import (
    ChatHistory,
    Metrics,
    OwaspCategory,
    Payload,
    TargetResponse,
    Verdict,
)
from llmbuster.orchestrator import ProgressEvent, ScanConfig, ScanOrchestrator
from llmbuster.target.factory import LoadedTarget, TargetKind
from llmbuster.tui import LlmBusterApp
from llmbuster.tui.screens import (
    ConfigPanel,
    FindingsPanel,
    HistoryPanel,
    ScanConfigResult,
    ScanConfigSubmitted,
)
from llmbuster.tui.screens.dashboard_screen import DashboardPanel


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


def _app(tmp_path: Path) -> LlmBusterApp:
    return LlmBusterApp(db_path=tmp_path / "tui.db")


@pytest.mark.asyncio
async def test_app_boots_and_quits(tmp_path: Path) -> None:
    app = _app(tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.query_one("#nav-tabs", Tabs).active == "tab-config"
    assert app.is_running is False


@pytest.mark.asyncio
async def test_tabs_display_all_sections(tmp_path: Path) -> None:
    app = _app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        tabs = app.query_one("#nav-tabs", Tabs)
        labels = [str(tab.label) for tab in tabs.query(Tab)]
        assert labels == ["Config", "Dashboard", "History", "Findings"]
        tab_ids = [tab.id for tab in tabs.query(Tab)]
        assert tab_ids == ["tab-config", "tab-dashboard", "tab-history", "tab-findings"]


@pytest.mark.asyncio
async def test_navigation_between_tabs(tmp_path: Path) -> None:
    app = _app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        tabs = app.query_one("#nav-tabs", Tabs)
        switcher = app.query_one("#content", ContentSwitcher)
        assert tabs.active == "tab-config"
        assert switcher.current == "config-panel"

        await pilot.press("2")
        await pilot.pause()
        assert tabs.active == "tab-dashboard"
        assert switcher.current == "dashboard-panel"
        assert isinstance(switcher.visible_content, DashboardPanel)

        await pilot.press("3")
        await pilot.pause()
        assert tabs.active == "tab-history"
        assert switcher.current == "history-panel"
        assert isinstance(switcher.visible_content, HistoryPanel)

        await pilot.press("4")
        await pilot.pause()
        assert tabs.active == "tab-findings"
        assert switcher.current == "findings-panel"
        assert isinstance(switcher.visible_content, FindingsPanel)

        await pilot.press("1")
        await pilot.pause()
        assert tabs.active == "tab-config"
        assert switcher.current == "config-panel"
        assert isinstance(switcher.visible_content, ConfigPanel)


@pytest.mark.asyncio
async def test_all_panels_mounted(tmp_path: Path) -> None:
    app = _app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert app.query_one("#config-panel", ConfigPanel) is not None
        assert app.query_one("#dashboard-panel", DashboardPanel) is not None
        assert app.query_one("#history-panel", HistoryPanel) is not None
        assert app.query_one("#findings-panel", FindingsPanel) is not None


@pytest.mark.asyncio
async def test_quit_binding(tmp_path: Path) -> None:
    app = _app(tmp_path)
    async with app.run_test() as pilot:
        await pilot.press("q")
        await pilot.pause()
    assert app._return_code == 0


@pytest.mark.asyncio
async def test_ctrl_c_quits(tmp_path: Path) -> None:
    app = _app(tmp_path)
    async with app.run_test() as pilot:
        await pilot.press("ctrl+c")
        await pilot.pause()
    assert app._return_code == 0


@pytest.mark.asyncio
async def test_help_panel_binding(tmp_path: Path) -> None:
    app = _app(tmp_path)
    async with app.run_test() as pilot:
        await pilot.press("?")
        await pilot.pause()
        assert app.screen.query_one(HelpPanel) is not None


@pytest.mark.asyncio
async def test_attach_orchestrator_collects_events(tmp_path: Path) -> None:
    app = _app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
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
async def test_clean_teardown_cancels_drainer(tmp_path: Path) -> None:
    app = _app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.attach_orchestrator(_orchestrator())
        await pilot.pause()
        assert app._drainer is not None
        assert not app._drainer.done()
    assert app._drainer is None


@pytest.mark.asyncio
async def test_attach_before_mount_starts_drainer(tmp_path: Path) -> None:
    app = _app(tmp_path)
    orchestrator = _orchestrator()
    app.attach_orchestrator(orchestrator)
    assert app._drainer is None
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert app._drainer is not None
        assert not app._drainer.done()
        await orchestrator.progress_queue.put(None)
        await pilot.pause()
        assert app._drainer.done()


@pytest.mark.asyncio
async def test_drain_forwards_to_dashboard_panel(tmp_path: Path) -> None:
    from textual.widgets import Static

    app = _app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        panel = app.query_one("#dashboard-panel", DashboardPanel)
        orchestrator = _orchestrator()
        app.attach_orchestrator(orchestrator)
        await orchestrator.progress_queue.put(_progress_event("p1", Verdict.VULNERABLE))
        await orchestrator.progress_queue.put(None)
        await pilot.pause()
        assert app._drainer is not None
        await app._drainer
        assert str(panel.query_one("#findings", Static).content) == "1"


def _scan_config_result() -> ScanConfigResult:
    return ScanConfigResult(
        loaded_target=LoadedTarget(
            target=StubTarget(),
            kind=TargetKind.PROFILE,
            name="stub",
        ),
        system_prompt=None,
        concurrency=5,
        repeat=1,
        categories=None,
        escalate=False,
    )


async def _submit_and_wait(pilot: Pilot, app: LlmBusterApp) -> None:
    app.post_message(ScanConfigSubmitted(_scan_config_result()))
    for _ in range(10):
        await pilot.pause()
        if app._scan_task is not None:
            break


@pytest.mark.asyncio
async def test_scan_launch_from_config(tmp_path: Path) -> None:
    app = _app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _submit_and_wait(pilot, app)

        runs = app._store.list_runs()
        assert len(runs) == 1
        assert runs[0].target_name == "stub"
        assert runs[0].target_kind == "profile"

        tabs = app.query_one("#nav-tabs", Tabs)
        assert tabs.active == "tab-dashboard"
        switcher = app.query_one("#content", ContentSwitcher)
        assert switcher.current == "dashboard-panel"

        assert app._scan_task is not None
        assert app._writer_task is not None
        await app._scan_task
        await app._writer_task
        await pilot.pause()


@pytest.mark.asyncio
async def test_scan_completes_and_refreshes(tmp_path: Path) -> None:
    app = _app(tmp_path)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await _submit_and_wait(pilot, app)

        if app._scan_task is not None:
            await app._scan_task
        if app._writer_task is not None:
            await app._writer_task
        if app._await_task is not None:
            await app._await_task
        await pilot.pause()

        runs = app._store.list_runs()
        assert len(runs) == 1
        run_id = runs[0].id
        assert run_id is not None
        interactions = app._store.interactions_for_run(run_id)
        assert len(interactions) > 0

        history = app.query_one("#history-panel", HistoryPanel)
        history_select = history.query_one("#run-select", Select)
        assert isinstance(history_select.value, int)
        assert history_select.value == run_id

        findings = app.query_one("#findings-panel", FindingsPanel)
        findings_select = findings.query_one("#run-select", Select)
        assert isinstance(findings_select.value, int)
        assert findings_select.value == run_id
