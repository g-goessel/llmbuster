from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from llmbuster.cli import app
from llmbuster.domain.models import (
    ChatHistory,
    Message,
    Metrics,
    OwaspCategory,
    Role,
    TargetResponse,
    Verdict,
)
from llmbuster.repeater import replay_interaction
from llmbuster.store import InteractionRecord, RunRecord, SQLiteStore

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"
ECHO_ADAPTER = str(FIXTURES / "echo_adapter.py")


class StubTarget:
    def __init__(self, reply: str = "I cannot help with that.") -> None:
        self._reply = reply
        self.last_request_json: str | None = None

    async def send(self, history: ChatHistory) -> TargetResponse:
        request_json = history.to_messages_json()
        self.last_request_json = request_json
        return TargetResponse(
            reply=self._reply,
            raw_request_json=request_json,
            raw_response_text=self._reply,
            metrics=Metrics(duration_ms=42),
        )


def _make_run() -> RunRecord:
    return RunRecord(
        started_at="2026-07-04T12:00:00+00:00",
        target_kind="profile",
        target_name="Bot",
        config_json='{"repeat":1}',
    )


def _make_interaction(
    run_id: int,
    *,
    sent_history_json: str,
    payload_id: str = "llm01-direct-override",
    owasp: OwaspCategory = OwaspCategory.LLM01,
    verdict: Verdict = Verdict.VULNERABLE,
) -> InteractionRecord:
    return InteractionRecord(
        run_id=run_id,
        payload_id=payload_id,
        owasp_category=owasp.value,
        attempt_index=0,
        sent_history_json=sent_history_json,
        raw_request_json='{"body":"hi"}',
        raw_response_text="raw-response",
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


def _seed_interaction(
    db_path: Path,
    history: ChatHistory | None = None,
) -> tuple[SQLiteStore, int, int]:
    store = SQLiteStore(db_path)
    run_id = store.create_run(_make_run())
    if history is None:
        history = ChatHistory(
            messages=[Message(role=Role.USER, content="original prompt")]
        )
    record = _make_interaction(run_id, sent_history_json=history.to_messages_json())
    iid = store.insert_interaction(record)
    return store, run_id, iid


async def test_replay_interaction_unchanged(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store, run_id, iid = _seed_interaction(db)
    target = StubTarget(reply="I cannot help with that.")
    try:
        new_record = await replay_interaction(
            store, iid, target, edited_history=None
        )
    finally:
        store.close()

    assert new_record.id is not None
    assert new_record.id != iid
    assert new_record.replayed_from == iid
    assert new_record.run_id == run_id
    assert new_record.payload_id == "llm01-direct-override"
    assert new_record.verdict == Verdict.SAFE.value

    store = SQLiteStore(db)
    try:
        rows = store.interactions_for_run(run_id)
        fetched = store.interaction_by_id(new_record.id)
    finally:
        store.close()
    assert len(rows) == 2
    assert fetched is not None
    assert fetched.replayed_from == iid
    assert fetched.id == new_record.id


async def test_replay_interaction_edited(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    original_history = ChatHistory(
        messages=[
            Message(role=Role.SYSTEM, content="sys"),
            Message(role=Role.USER, content="original prompt"),
        ]
    )
    store, run_id, iid = _seed_interaction(db, history=original_history)
    target = StubTarget(reply="echo back")

    edited = original_history.clone()
    for msg in reversed(edited.messages):
        if msg.role is Role.USER:
            msg.content = "edited prompt"
            break

    try:
        new_record = await replay_interaction(
            store, iid, target, edited_history=edited
        )
    finally:
        store.close()

    assert new_record.id is not None
    assert new_record.replayed_from == iid
    parsed = json.loads(new_record.sent_history_json)
    last_user = next(
        m["content"] for m in reversed(parsed) if m["role"] == "user"
    )
    assert last_user == "edited prompt"
    assert "original prompt" not in new_record.sent_history_json
    assert target.last_request_json == new_record.sent_history_json


async def test_replay_nonexistent_raises(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = SQLiteStore(db)
    target = StubTarget()
    try:
        with pytest.raises(ValueError, match="99999"):
            await replay_interaction(store, 99999, target)
    finally:
        store.close()


def test_replayed_from_column_exists(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = SQLiteStore(db)
    try:
        cur = store._conn.cursor()
        cur.execute("PRAGMA table_info(interactions)")
        names = {r["name"] for r in cur.fetchall()}
        cur.close()
    finally:
        store.close()
    assert "replayed_from" in names


def test_replayed_from_migration_adds_column(tmp_path: Path) -> None:
    import sqlite3

    db = tmp_path / "t.db"
    conn = sqlite3.connect(str(db))
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE runs ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, "
        "target_kind TEXT NOT NULL, target_name TEXT, model TEXT, "
        "system_prompt TEXT, config_json TEXT NOT NULL)"
    )
    cur.execute(
        "CREATE TABLE interactions ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL, "
        "payload_id TEXT NOT NULL, owasp_category TEXT NOT NULL, "
        "attempt_index INTEGER NOT NULL, mutation TEXT, "
        "escalation_from INTEGER, sent_history_json TEXT NOT NULL, "
        "raw_request_json TEXT NOT NULL, raw_response_text TEXT, "
        "response_text TEXT, ttft_ms INTEGER, duration_ms INTEGER, "
        "tps REAL, prompt_tokens INTEGER, completion_tokens INTEGER, "
        "verdict TEXT NOT NULL, detector_id TEXT, detector_detail TEXT, "
        "created_at TEXT NOT NULL)"
    )
    cur.execute(
        "INSERT INTO runs (started_at, target_kind, config_json) "
        "VALUES ('2026-01-01T00:00:00+00:00', 'profile', '{}')"
    )
    run_id = cur.lastrowid
    cur.execute(
        "INSERT INTO interactions (run_id, payload_id, owasp_category, "
        "attempt_index, sent_history_json, raw_request_json, verdict, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id,
            "p1",
            "LLM01",
            0,
            '[{"role":"user","content":"hi"}]',
            "{}",
            "safe",
            "2026-01-01T00:00:01+00:00",
        ),
    )
    conn.commit()
    cur.close()
    conn.close()

    old_conn = sqlite3.connect(str(db))
    old_cur = old_conn.cursor()
    old_cur.execute("PRAGMA table_info(interactions)")
    assert "replayed_from" not in {r[1] for r in old_cur.fetchall()}
    old_cur.close()
    old_conn.close()

    store = SQLiteStore(db)
    try:
        new_cur = store._conn.cursor()
        new_cur.execute("PRAGMA table_info(interactions)")
        cols = {r["name"] for r in new_cur.fetchall()}
        new_cur.close()
        fetched = store.interaction_by_id(1)
    finally:
        store.close()

    assert "replayed_from" in cols
    assert fetched is not None
    assert fetched.replayed_from is None
    assert fetched.payload_id == "p1"


def test_cli_replay(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store, run_id, iid = _seed_interaction(db)
    store.close()

    profile = tmp_path / "cmd.yaml"
    profile.write_text(
        "kind: command\n"
        'name: "echo"\n'
        f'command: ["python3", "{ECHO_ADAPTER}"]\n',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["replay", str(iid), str(profile), "--db", str(db)],
    )
    assert result.exit_code == 0, result.output
    assert "New interaction id:" in result.output
    assert f"Replayed from: {iid}" in result.output
    assert "Verdict: safe" in result.output


def test_cli_replay_with_edit(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    original_history = ChatHistory(
        messages=[Message(role=Role.USER, content="original prompt")]
    )
    store, run_id, iid = _seed_interaction(db, history=original_history)
    store.close()

    profile = tmp_path / "cmd.yaml"
    profile.write_text(
        "kind: command\n"
        'name: "echo"\n'
        f'command: ["python3", "{ECHO_ADAPTER}"]\n',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "replay",
            str(iid),
            str(profile),
            "--db",
            str(db),
            "--edit",
            "edited prompt",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "New interaction id:" in result.output
    assert "echo: edited prompt" in result.output


def test_cli_replay_missing_interaction(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    SQLiteStore(db).close()

    profile = tmp_path / "cmd.yaml"
    profile.write_text(
        "kind: command\n"
        'name: "echo"\n'
        f'command: ["python3", "{ECHO_ADAPTER}"]\n',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["replay", "99999", str(profile), "--db", str(db)],
    )
    assert result.exit_code == 1
    assert "not found" in result.output
