from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime
from types import TracebackType
from typing import Any

from pydantic import BaseModel, Field

from llmbuster.domain.models import Interaction, Metrics, OwaspCategory, Verdict

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    target_kind   TEXT NOT NULL,
    target_name   TEXT,
    model         TEXT,
    system_prompt TEXT,
    config_json   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS interactions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES runs(id),
    payload_id      TEXT NOT NULL,
    owasp_category  TEXT NOT NULL,
    attempt_index   INTEGER NOT NULL,
    mutation        TEXT,
    escalation_from INTEGER REFERENCES interactions(id),
    replayed_from   INTEGER REFERENCES interactions(id),

    sent_history_json TEXT NOT NULL,
    raw_request_json  TEXT NOT NULL,
    raw_response_text TEXT,
    response_text     TEXT,

    ttft_ms           INTEGER,
    duration_ms       INTEGER,
    tps               REAL,
    prompt_tokens     INTEGER,
    completion_tokens INTEGER,

    verdict         TEXT NOT NULL,
    detector_id     TEXT,
    detector_detail TEXT,

    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_inter_run      ON interactions(run_id);
CREATE INDEX IF NOT EXISTS idx_inter_category ON interactions(run_id, owasp_category);
CREATE INDEX IF NOT EXISTS idx_inter_payload  ON interactions(run_id, payload_id);
"""

_INTERACTION_COLUMNS = (
    "run_id, payload_id, owasp_category, attempt_index, mutation, escalation_from, "
    "replayed_from, "
    "sent_history_json, raw_request_json, raw_response_text, response_text, "
    "ttft_ms, duration_ms, tps, prompt_tokens, completion_tokens, "
    "verdict, detector_id, detector_detail, created_at"
)
_INTERACTION_PLACEHOLDERS = ", ".join(["?"] * 20)


class RunRecord(BaseModel):
    id: int | None = None
    started_at: str
    target_kind: str
    target_name: str | None = None
    model: str | None = None
    system_prompt: str | None = None
    config_json: str


class InteractionRecord(BaseModel):
    id: int | None = None
    run_id: int
    payload_id: str
    owasp_category: str
    attempt_index: int
    mutation: str | None = None
    escalation_from: int | None = None
    replayed_from: int | None = None
    sent_history_json: str
    raw_request_json: str
    raw_response_text: str | None = None
    response_text: str | None = None
    ttft_ms: int | None = None
    duration_ms: int | None = None
    tps: float | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    verdict: str
    detector_id: str | None = None
    detector_detail: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


def interaction_to_record(interaction: Interaction, run_id: int) -> InteractionRecord:
    return InteractionRecord(
        run_id=run_id,
        payload_id=interaction.payload_id,
        owasp_category=interaction.owasp_category.value,
        attempt_index=interaction.attempt_index,
        mutation=interaction.mutation,
        escalation_from=interaction.escalation_from,
        replayed_from=interaction.replayed_from,
        sent_history_json=interaction.sent_history_json,
        raw_request_json=interaction.raw_request_json,
        raw_response_text=interaction.raw_response_text,
        response_text=interaction.response_text,
        ttft_ms=interaction.metrics.ttft_ms,
        duration_ms=interaction.metrics.duration_ms,
        tps=interaction.metrics.tps,
        prompt_tokens=interaction.metrics.prompt_tokens,
        completion_tokens=interaction.metrics.completion_tokens,
        verdict=interaction.verdict.value,
        detector_id=interaction.detector_id,
        detector_detail=interaction.detector_detail,
    )


def record_to_interaction(record: InteractionRecord) -> Interaction:
    return Interaction(
        run_id=record.run_id,
        payload_id=record.payload_id,
        owasp_category=OwaspCategory(record.owasp_category),
        attempt_index=record.attempt_index,
        mutation=record.mutation,
        escalation_from=record.escalation_from,
        replayed_from=record.replayed_from,
        sent_history_json=record.sent_history_json,
        raw_request_json=record.raw_request_json,
        raw_response_text=record.raw_response_text,
        response_text=record.response_text,
        metrics=Metrics(
            ttft_ms=record.ttft_ms,
            duration_ms=record.duration_ms,
            tps=record.tps,
            prompt_tokens=record.prompt_tokens,
            completion_tokens=record.completion_tokens,
        ),
        verdict=Verdict(record.verdict),
        detector_id=record.detector_id,
        detector_detail=record.detector_detail,
    )


class SQLiteStore:
    def __init__(self, db_path: str | os.PathLike[str]) -> None:
        self._conn: sqlite3.Connection = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._apply_pragmas()
        self._create_schema()

    def _apply_pragmas(self) -> None:
        cur = self._conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute("PRAGMA foreign_keys=ON;")
        cur.close()

    def _create_schema(self) -> None:
        cur = self._conn.cursor()
        cur.executescript(_SCHEMA_SQL)
        self._migrate_interactions_replayed_from(cur)
        cur.close()

    def _migrate_interactions_replayed_from(self, cur: sqlite3.Cursor) -> None:
        cur.execute("PRAGMA table_info(interactions)")
        cols = {r["name"] for r in cur.fetchall()}
        if "replayed_from" not in cols:
            cur.execute(
                "ALTER TABLE interactions "
                "ADD COLUMN replayed_from INTEGER REFERENCES interactions(id)"
            )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> SQLiteStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def create_run(self, run: RunRecord) -> int:
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO runs (started_at, target_kind, target_name, model, "
            "system_prompt, config_json) VALUES (?, ?, ?, ?, ?, ?)",
            (
                run.started_at,
                run.target_kind,
                run.target_name,
                run.model,
                run.system_prompt,
                run.config_json,
            ),
        )
        self._conn.commit()
        last_id = cur.lastrowid
        cur.close()
        assert last_id is not None
        return last_id

    def insert_interaction(self, interaction: InteractionRecord) -> int:
        cur = self._conn.cursor()
        sql = (
            f"INSERT INTO interactions ({_INTERACTION_COLUMNS}) "
            f"VALUES ({_INTERACTION_PLACEHOLDERS})"
        )
        cur.execute(
            sql,
            (
                interaction.run_id,
                interaction.payload_id,
                interaction.owasp_category,
                interaction.attempt_index,
                interaction.mutation,
                interaction.escalation_from,
                interaction.replayed_from,
                interaction.sent_history_json,
                interaction.raw_request_json,
                interaction.raw_response_text,
                interaction.response_text,
                interaction.ttft_ms,
                interaction.duration_ms,
                interaction.tps,
                interaction.prompt_tokens,
                interaction.completion_tokens,
                interaction.verdict,
                interaction.detector_id,
                interaction.detector_detail,
                interaction.created_at,
            ),
        )
        self._conn.commit()
        last_id = cur.lastrowid
        cur.close()
        assert last_id is not None
        return last_id

    def interactions_for_run(self, run_id: int) -> list[InteractionRecord]:
        cur = self._conn.cursor()
        cur.execute(
            "SELECT * FROM interactions WHERE run_id = ? ORDER BY id",
            (run_id,),
        )
        rows: list[sqlite3.Row] = cur.fetchall()
        cur.close()
        return [self._row_to_interaction(r) for r in rows]

    def findings_for_run(self, run_id: int) -> list[InteractionRecord]:
        cur = self._conn.cursor()
        cur.execute(
            "SELECT * FROM interactions WHERE run_id = ? AND verdict = ? "
            "ORDER BY owasp_category, payload_id, attempt_index",
            (run_id, Verdict.VULNERABLE.value),
        )
        rows: list[sqlite3.Row] = cur.fetchall()
        cur.close()
        return [self._row_to_interaction(r) for r in rows]

    def interaction_by_id(self, interaction_id: int) -> InteractionRecord | None:
        cur = self._conn.cursor()
        cur.execute(
            "SELECT * FROM interactions WHERE id = ?",
            (interaction_id,),
        )
        row: Any = cur.fetchone()
        cur.close()
        if row is None:
            return None
        return self._row_to_interaction(row)

    def get_run(self, run_id: int) -> RunRecord | None:
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM runs WHERE id = ?", (run_id,))
        row: Any = cur.fetchone()
        cur.close()
        if row is None:
            return None
        return self._row_to_run(row)

    def list_runs(self) -> list[RunRecord]:
        cur = self._conn.cursor()
        cur.execute("SELECT * FROM runs ORDER BY id DESC")
        rows: list[sqlite3.Row] = cur.fetchall()
        cur.close()
        return [self._row_to_run(r) for r in rows]

    def _row_to_interaction(self, row: sqlite3.Row) -> InteractionRecord:
        return InteractionRecord(
            id=row["id"],
            run_id=row["run_id"],
            payload_id=row["payload_id"],
            owasp_category=row["owasp_category"],
            attempt_index=row["attempt_index"],
            mutation=row["mutation"],
            escalation_from=row["escalation_from"],
            replayed_from=row["replayed_from"],
            sent_history_json=row["sent_history_json"],
            raw_request_json=row["raw_request_json"],
            raw_response_text=row["raw_response_text"],
            response_text=row["response_text"],
            ttft_ms=row["ttft_ms"],
            duration_ms=row["duration_ms"],
            tps=row["tps"],
            prompt_tokens=row["prompt_tokens"],
            completion_tokens=row["completion_tokens"],
            verdict=row["verdict"],
            detector_id=row["detector_id"],
            detector_detail=row["detector_detail"],
            created_at=row["created_at"],
        )

    def _row_to_run(self, row: sqlite3.Row) -> RunRecord:
        return RunRecord(
            id=row["id"],
            started_at=row["started_at"],
            target_kind=row["target_kind"],
            target_name=row["target_name"],
            model=row["model"],
            system_prompt=row["system_prompt"],
            config_json=row["config_json"],
        )
