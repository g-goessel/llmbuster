from __future__ import annotations

import asyncio
from dataclasses import dataclass

from pydantic import BaseModel

from llmbuster.detector.registry import default_registry
from llmbuster.domain.models import (
    ChatHistory,
    Interaction,
    Message,
    Metrics,
    OwaspCategory,
    Payload,
    Role,
    TargetResponse,
    Verdict,
)
from llmbuster.domain.protocols import Target
from llmbuster.orchestrator.aggregation import compute_reproducibility
from llmbuster.payload.mutation import mutate


class ScanConfig(BaseModel):
    run_id: int
    concurrency: int = 5
    repeat: int | None = None
    mutations: list[str] | None = None
    system_prompt: str | None = None
    categories: list[str] | None = None
    escalate: bool = False


class ProgressEvent(BaseModel):
    payload_id: str
    attempt_index: int
    mutation: str | None
    owasp_category: str
    verdict: Verdict
    metrics: Metrics
    phase: str
    detail: str | None = None


@dataclass
class WorkItem:
    payload: Payload
    attempt_index: int
    mutation: str | None
    owasp_category: OwaspCategory
    escalation_from: int | None = None


class ScanOrchestrator:
    def __init__(
        self,
        target: Target,
        config: ScanConfig,
        payloads: list[Payload],
        owasp_categories: dict[str, OwaspCategory],
    ) -> None:
        self._target = target
        self._config = config
        self._payloads = payloads
        self._owasp_categories = owasp_categories
        self._interaction_queue: asyncio.Queue[Interaction | None] = asyncio.Queue()
        self._progress_queue: asyncio.Queue[ProgressEvent | None] = asyncio.Queue()
        self._semaphore = asyncio.Semaphore(config.concurrency)
        self._max_concurrent = 0
        self._active = 0
        self._collected_interactions: list[Interaction] = []

    @property
    def interaction_queue(self) -> asyncio.Queue[Interaction | None]:
        return self._interaction_queue

    @property
    def progress_queue(self) -> asyncio.Queue[ProgressEvent | None]:
        return self._progress_queue

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    def build_work_items(self) -> list[WorkItem]:
        items: list[WorkItem] = []
        categories = self._config.categories
        for payload in self._payloads:
            cat = self._owasp_categories.get(payload.id)
            if cat is None:
                continue
            if categories is not None and cat.value not in categories:
                continue
            repeat = (
                self._config.repeat if self._config.repeat is not None else payload.repeat
            )
            mutations = (
                self._config.mutations
                if self._config.mutations is not None
                else payload.mutations
            )
            for i in range(repeat):
                items.append(
                    WorkItem(
                        payload=payload,
                        attempt_index=i,
                        mutation=None,
                        owasp_category=cat,
                    )
                )
                for m in mutations:
                    items.append(
                        WorkItem(
                            payload=payload,
                            attempt_index=i,
                            mutation=m,
                            owasp_category=cat,
                        )
                    )
        return items

    async def run(self) -> None:
        items = self.build_work_items()
        tasks = [asyncio.create_task(self._worker(item)) for item in items]
        await asyncio.gather(*tasks, return_exceptions=True)
        if self._config.escalate:
            await self._run_escalations()
        await self._interaction_queue.put(None)
        await self._progress_queue.put(None)

    def _find_payload(self, payload_id: str) -> Payload | None:
        for payload in self._payloads:
            if payload.id == payload_id:
                return payload
        return None

    async def _run_escalations(self) -> None:
        initial = list(self._collected_interactions)
        by_payload: dict[str, list[Interaction]] = {}
        for interaction in initial:
            by_payload.setdefault(interaction.payload_id, []).append(interaction)
        items: list[WorkItem] = []
        for payload_id, interactions in by_payload.items():
            score = compute_reproducibility(
                payload_id, [i.verdict for i in interactions]
            )
            if score.rolled_up_verdict is not Verdict.VULNERABLE:
                continue
            origin = self._find_payload(payload_id)
            if origin is None or origin.escalation_to is None:
                continue
            target_payload = self._find_payload(origin.escalation_to)
            if target_payload is None:
                continue
            cat = self._owasp_categories.get(target_payload.id)
            if cat is None:
                continue
            await self._progress_queue.put(
                ProgressEvent(
                    payload_id=target_payload.id,
                    attempt_index=0,
                    mutation=None,
                    owasp_category=cat.value,
                    verdict=Verdict.VULNERABLE,
                    metrics=Metrics(),
                    phase="escalation",
                    detail=f"escalating from {payload_id} to {target_payload.id}",
                )
            )
            items.append(
                WorkItem(
                    payload=target_payload,
                    attempt_index=0,
                    mutation=None,
                    owasp_category=cat,
                    escalation_from=None,
                )
            )
        if not items:
            return
        tasks = [asyncio.create_task(self._worker(item)) for item in items]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _worker(self, item: WorkItem) -> None:
        async with self._semaphore:
            self._active += 1
            self._max_concurrent = max(self._max_concurrent, self._active)
            try:
                await self._progress_queue.put(
                    ProgressEvent(
                        payload_id=item.payload.id,
                        attempt_index=item.attempt_index,
                        mutation=item.mutation,
                        owasp_category=item.owasp_category.value,
                        verdict=Verdict.SAFE,
                        metrics=Metrics(),
                        phase="started",
                    )
                )
                prompt = item.payload.prompt
                if item.mutation is not None:
                    prompt = mutate(prompt, item.mutation)
                history = ChatHistory()
                if self._config.system_prompt:
                    history.append(
                        Message(role=Role.SYSTEM, content=self._config.system_prompt)
                    )
                history.append(Message(role=Role.USER, content=prompt))
                try:
                    response = await self._target.send(history)
                except Exception as exc:
                    response = TargetResponse(
                        reply=None,
                        raw_request_json="",
                        raw_response_text=None,
                        metrics=Metrics(),
                        error=f"target error: {exc!s}",
                    )
                verdict, detector_id, detector_detail = self._evaluate(item.payload, response)
                interaction = Interaction(
                    run_id=self._config.run_id,
                    payload_id=item.payload.id,
                    owasp_category=item.owasp_category,
                    attempt_index=item.attempt_index,
                    mutation=item.mutation,
                    escalation_from=item.escalation_from,
                    sent_history_json=history.to_messages_json(),
                    raw_request_json=response.raw_request_json,
                    raw_response_text=response.raw_response_text,
                    response_text=response.reply,
                    metrics=response.metrics,
                    verdict=verdict,
                    detector_id=detector_id,
                    detector_detail=detector_detail,
                )
                await self._interaction_queue.put(interaction)
                self._collected_interactions.append(interaction)
                phase = "error" if verdict is Verdict.ERROR else "completed"
                await self._progress_queue.put(
                    ProgressEvent(
                        payload_id=item.payload.id,
                        attempt_index=item.attempt_index,
                        mutation=item.mutation,
                        owasp_category=item.owasp_category.value,
                        verdict=verdict,
                        metrics=response.metrics,
                        phase=phase,
                        detail=response.error or detector_detail,
                    )
                )
            finally:
                self._active -= 1

    def _evaluate(
        self, payload: Payload, response: TargetResponse
    ) -> tuple[Verdict, str | None, str | None]:
        if response.error is not None:
            return Verdict.ERROR, None, response.error
        detectors = default_registry.build_from_payload(payload)
        if not detectors:
            return Verdict.SAFE, None, None
        results = [d.evaluate(payload, response.reply) for d in detectors]
        for idx, (v, detail) in enumerate(results):
            if v is Verdict.VULNERABLE:
                return Verdict.VULNERABLE, type(detectors[idx]).__name__, detail
        for v, detail in results:
            if v is Verdict.ERROR:
                return Verdict.ERROR, None, detail
        for v, detail in results:
            if v is Verdict.INCONCLUSIVE:
                return Verdict.INCONCLUSIVE, None, detail
        return Verdict.SAFE, None, results[0][1] if results else None
