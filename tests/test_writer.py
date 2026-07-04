from __future__ import annotations

import asyncio
from pathlib import Path

from llmbuster.domain.models import Interaction, Metrics, OwaspCategory, Verdict
from llmbuster.store import RunRecord, SQLiteStore, WriterTask


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
    payload_id: str = "llm01-direct-override",
    attempt: int = 0,
    verdict: Verdict = Verdict.VULNERABLE,
) -> Interaction:
    return Interaction(
        run_id=run_id,
        payload_id=payload_id,
        owasp_category=OwaspCategory.LLM01,
        attempt_index=attempt,
        mutation=None,
        escalation_from=None,
        sent_history_json='{"messages":[{"role":"user","content":"hi"}]}',
        raw_request_json='{"body":"hi"}',
        raw_response_text="raw",
        response_text="PWNED",
        metrics=Metrics(ttft_ms=12, duration_ms=300, tps=42.5, completion_tokens=9),
        verdict=verdict,
        detector_id="canary",
        detector_detail="token PWNED found",
    )


async def test_basic_drain(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = SQLiteStore(db)
    run_id = store.create_run(_make_run())
    queue: asyncio.Queue[Interaction | None] = asyncio.Queue()
    writer = WriterTask(store, queue)
    for i in range(3):
        await queue.put(_make_interaction(run_id, attempt=i))
    await queue.put(None)
    await writer.run()
    rows = store.interactions_for_run(run_id)
    store.close()
    assert len(rows) == 3
    assert writer.inserted_count == 3
    assert [r.attempt_index for r in rows] == [0, 1, 2]


async def test_shutdown_sentinel_flushes_remaining(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = SQLiteStore(db)
    run_id = store.create_run(_make_run())
    queue: asyncio.Queue[Interaction | None] = asyncio.Queue()
    writer = WriterTask(store, queue)
    for i in range(5):
        await queue.put(_make_interaction(run_id, payload_id=f"p{i}", attempt=i))
    await queue.put(None)
    await writer.run()
    rows = store.interactions_for_run(run_id)
    store.close()
    assert len(rows) == 5
    assert writer.inserted_count == 5


async def test_concurrent_producers(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = SQLiteStore(db)
    run_id = store.create_run(_make_run())
    queue: asyncio.Queue[Interaction | None] = asyncio.Queue()
    writer = WriterTask(store, queue)

    async def producer(start: int, count: int) -> None:
        for i in range(count):
            await queue.put(_make_interaction(run_id, payload_id=f"p{start + i}"))

    writer_task = asyncio.create_task(writer.run())
    await asyncio.gather(*(producer(i * 10, 10) for i in range(5)))
    await queue.put(None)
    await writer_task
    rows = store.interactions_for_run(run_id)
    store.close()
    assert len(rows) == 50
    assert writer.inserted_count == 50


async def test_insert_error_does_not_crash_writer(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = SQLiteStore(db)
    run_id = store.create_run(_make_run())
    queue: asyncio.Queue[Interaction | None] = asyncio.Queue()
    writer = WriterTask(store, queue)
    await queue.put(_make_interaction(run_id, payload_id="good-1"))
    await queue.put(_make_interaction(9999, payload_id="bad"))
    await queue.put(_make_interaction(run_id, payload_id="good-2"))
    await queue.put(None)
    await writer.run()
    rows = store.interactions_for_run(run_id)
    store.close()
    assert len(rows) == 2
    assert writer.inserted_count == 2
    assert {r.payload_id for r in rows} == {"good-1", "good-2"}


async def test_empty_queue_sentinel(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = SQLiteStore(db)
    queue: asyncio.Queue[Interaction | None] = asyncio.Queue()
    writer = WriterTask(store, queue)
    await queue.put(None)
    await writer.run()
    store.close()
    assert writer.inserted_count == 0
    assert writer.is_running is False


async def test_stop_method(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = SQLiteStore(db)
    run_id = store.create_run(_make_run())
    queue: asyncio.Queue[Interaction | None] = asyncio.Queue()
    writer = WriterTask(store, queue)
    writer_task = asyncio.create_task(writer.run())
    for i in range(3):
        await queue.put(_make_interaction(run_id, attempt=i))
    await writer.stop()
    await writer_task
    rows = store.interactions_for_run(run_id)
    store.close()
    assert len(rows) == 3
    assert writer.inserted_count == 3
