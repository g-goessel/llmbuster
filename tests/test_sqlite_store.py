from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from llmbuster.domain import Interaction, Metrics, OwaspCategory, Verdict
from llmbuster.store import (
    InteractionRecord,
    RunRecord,
    SQLiteStore,
    interaction_to_record,
    record_to_interaction,
)


def _make_run(
    target_kind: str = "profile",
    target_name: str | None = "Bot",
    model: str | None = "gpt-x",
    system_prompt: str | None = "you are bot",
) -> RunRecord:
    return RunRecord(
        started_at="2026-07-04T12:00:00+00:00",
        target_kind=target_kind,
        target_name=target_name,
        model=model,
        system_prompt=system_prompt,
        config_json='{"repeat":3}',
    )


def _make_interaction(
    run_id: int,
    payload_id: str = "llm01-direct-override",
    owasp: OwaspCategory = OwaspCategory.LLM01,
    attempt: int = 0,
    verdict: Verdict = Verdict.VULNERABLE,
    mutation: str | None = None,
    escalation_from: int | None = None,
) -> InteractionRecord:
    return InteractionRecord(
        run_id=run_id,
        payload_id=payload_id,
        owasp_category=owasp.value,
        attempt_index=attempt,
        mutation=mutation,
        escalation_from=escalation_from,
        sent_history_json='{"messages":[{"role":"user","content":"hi"}]}',
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


def _open(db_path: Path) -> SQLiteStore:
    return SQLiteStore(db_path)


def test_schema_creates_tables(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    cur = store._conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r["name"] for r in cur.fetchall()}
    cur.close()
    store.close()
    assert {"runs", "interactions"}.issubset(tables)


def test_wal_mode_enabled(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    cur = store._conn.cursor()
    cur.execute("PRAGMA journal_mode")
    mode = cur.fetchone()[0]
    cur.close()
    store.close()
    assert mode == "wal"


def test_foreign_keys_pragma_on(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    cur = store._conn.cursor()
    cur.execute("PRAGMA foreign_keys")
    val = cur.fetchone()[0]
    cur.close()
    store.close()
    assert val == 1


def test_create_run_returns_id(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    run_id = store.create_run(_make_run())
    store.close()
    assert run_id >= 1


def test_insert_interaction_returns_id(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    run_id = store.create_run(_make_run())
    iid = store.insert_interaction(_make_interaction(run_id))
    store.close()
    assert iid >= 1


def test_interactions_for_run_in_insertion_order(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    run_id = store.create_run(_make_run())
    for i in range(3):
        store.insert_interaction(_make_interaction(run_id, attempt=i))
    rows = store.interactions_for_run(run_id)
    store.close()
    assert [r.attempt_index for r in rows] == [0, 1, 2]
    assert [r.id for r in rows] == sorted(r.id for r in rows)


def test_findings_for_run_filters_and_orders(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    run_id = store.create_run(_make_run())
    store.insert_interaction(
        _make_interaction(
            run_id,
            payload_id="p-b",
            owasp=OwaspCategory.LLM02,
            attempt=0,
            verdict=Verdict.VULNERABLE,
        )
    )
    store.insert_interaction(
        _make_interaction(
            run_id,
            payload_id="p-a",
            owasp=OwaspCategory.LLM01,
            attempt=0,
            verdict=Verdict.VULNERABLE,
        )
    )
    store.insert_interaction(
        _make_interaction(run_id, payload_id="p-c", attempt=0, verdict=Verdict.SAFE)
    )
    store.insert_interaction(
        _make_interaction(run_id, payload_id="p-d", attempt=0, verdict=Verdict.ERROR)
    )
    findings = store.findings_for_run(run_id)
    store.close()
    assert len(findings) == 2
    assert all(f.verdict == Verdict.VULNERABLE.value for f in findings)
    assert [(f.owasp_category, f.payload_id) for f in findings] == [
        ("LLM01", "p-a"),
        ("LLM02", "p-b"),
    ]


def test_interaction_by_id_reconstructs_all_fields(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    run_id = store.create_run(_make_run())
    record = _make_interaction(run_id)
    iid = store.insert_interaction(record)
    fetched = store.interaction_by_id(iid)
    store.close()
    assert fetched is not None
    record.id = iid
    assert fetched == record
    assert fetched.sent_history_json == record.sent_history_json
    assert fetched.ttft_ms == 12
    assert fetched.duration_ms == 300
    assert fetched.tps == 42.5
    assert fetched.prompt_tokens == 5
    assert fetched.completion_tokens == 9
    assert fetched.verdict == "vulnerable"
    assert fetched.detector_id == "canary"
    assert fetched.detector_detail == "token PWNED found"


def test_interaction_by_id_not_found(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    assert store.interaction_by_id(9999) is None
    store.close()


def test_get_run_round_trip(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    run = _make_run()
    run_id = store.create_run(run)
    fetched = store.get_run(run_id)
    store.close()
    assert fetched is not None
    run.id = run_id
    assert fetched == run


def test_list_runs_returns_newest_first(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    id_a = store.create_run(_make_run(target_name="A"))
    id_b = store.create_run(_make_run(target_name="B"))
    id_c = store.create_run(_make_run(target_name="C"))
    runs = store.list_runs()
    store.close()
    assert [r.id for r in runs] == [id_c, id_b, id_a]
    assert all(r.id is not None for r in runs)
    assert runs[0].target_name == "C"


def test_domain_round_trip(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    run_id = store.create_run(_make_run())
    interaction = Interaction(
        run_id=run_id,
        payload_id="llm01-direct-override",
        owasp_category=OwaspCategory.LLM01,
        attempt_index=0,
        mutation="base64",
        escalation_from=None,
        sent_history_json='{"messages":[{"role":"user","content":"hi"}]}',
        raw_request_json='{"body":"hi"}',
        raw_response_text="raw",
        response_text="PWNED",
        metrics=Metrics(ttft_ms=12, duration_ms=300, tps=42.5, completion_tokens=9),
        verdict=Verdict.VULNERABLE,
        detector_id="canary",
        detector_detail="token PWNED found",
    )
    record = interaction_to_record(interaction, run_id)
    iid = store.insert_interaction(record)
    fetched = store.interaction_by_id(iid)
    store.close()
    assert fetched is not None
    rebuilt = record_to_interaction(fetched)
    assert rebuilt == interaction
    assert rebuilt.owasp_category is OwaspCategory.LLM01
    assert rebuilt.verdict is Verdict.VULNERABLE
    assert rebuilt.metrics == interaction.metrics


def test_multiple_runs_no_cross_leakage(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    r1 = store.create_run(_make_run(target_name="A"))
    r2 = store.create_run(_make_run(target_name="B"))
    store.insert_interaction(_make_interaction(r1, payload_id="a1"))
    store.insert_interaction(_make_interaction(r1, payload_id="a2"))
    store.insert_interaction(_make_interaction(r2, payload_id="b1"))
    rows1 = store.interactions_for_run(r1)
    rows2 = store.interactions_for_run(r2)
    store.close()
    assert {r.payload_id for r in rows1} == {"a1", "a2"}
    assert {r.payload_id for r in rows2} == {"b1"}
    assert all(r.run_id == r1 for r in rows1)
    assert all(r.run_id == r2 for r in rows2)


def test_escalation_from_self_reference(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    run_id = store.create_run(_make_run())
    parent = _make_interaction(run_id, payload_id="parent")
    parent_id = store.insert_interaction(parent)
    child = _make_interaction(
        run_id, payload_id="child", escalation_from=parent_id
    )
    child_id = store.insert_interaction(child)
    fetched = store.interaction_by_id(child_id)
    store.close()
    assert fetched is not None
    assert fetched.escalation_from == parent_id


def test_indexes_exist(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    store = _open(db)
    cur = store._conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='index'")
    names = {r["name"] for r in cur.fetchall()}
    cur.close()
    store.close()
    assert {
        "idx_inter_run",
        "idx_inter_category",
        "idx_inter_payload",
    }.issubset(names)


def test_context_manager_closes(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    with _open(db) as store:
        run_id = store.create_run(_make_run())
        assert run_id >= 1
    with pytest.raises(sqlite3.ProgrammingError):
        store.create_run(_make_run())
