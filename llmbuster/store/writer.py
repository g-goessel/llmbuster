from __future__ import annotations

import asyncio
import sys

from llmbuster.domain.models import Interaction
from llmbuster.store.sqlite_store import SQLiteStore, interaction_to_record


class WriterTask:
    def __init__(
        self,
        store: SQLiteStore,
        queue: asyncio.Queue[Interaction | None],
    ) -> None:
        self._store = store
        self._queue = queue
        self._inserted_count = 0
        self._running = False

    @property
    def inserted_count(self) -> int:
        return self._inserted_count

    @property
    def is_running(self) -> bool:
        return self._running

    async def run(self) -> None:
        self._running = True
        try:
            while True:
                item = await self._queue.get()
                if item is None:
                    self._flush_remaining()
                    break
                self._persist(item)
        finally:
            self._running = False

    def _flush_remaining(self) -> None:
        while True:
            try:
                item = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            if item is not None:
                self._persist(item)

    def _persist(self, item: Interaction) -> None:
        try:
            self._store.insert_interaction(interaction_to_record(item, item.run_id))
        except Exception as exc:
            print(f"writer: failed to persist interaction: {exc}", file=sys.stderr)
            return
        self._inserted_count += 1

    async def stop(self) -> None:
        await self._queue.put(None)
