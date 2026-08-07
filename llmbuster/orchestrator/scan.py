from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, Field

from llmbuster.detector.judge import LlmJudgeDetector
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
    judge_model: str | None = None
    judge_mode: Literal["hits", "all", "sample"] = "hits"
    judge_sample_rate: float = Field(default=0.25, ge=0.0, le=1.0)


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
    prior_history: ChatHistory | None = None


class ScanOrchestrator:
    def __init__(
        self,
        target: Target,
        config: ScanConfig,
        payloads: list[Payload],
        owasp_categories: dict[str, OwaspCategory],
        judge_target: Target | None = None,
    ) -> None:
        self._target = target
        self._config = config
        self._payloads = payloads
        self._owasp_categories = owasp_categories
        self._judge_target = judge_target
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
                    prior_history=self._history_for_escalation(interactions),
                )
            )
        if not items:
            return
        tasks = [asyncio.create_task(self._worker(item)) for item in items]
        await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    def _history_for_escalation(interactions: list[Interaction]) -> ChatHistory | None:
        source = next((item for item in interactions if item.verdict is Verdict.VULNERABLE), None)
        if source is None:
            return None
        try:
            messages = json.loads(source.sent_history_json)
            history = ChatHistory.model_validate({"messages": messages})
        except (json.JSONDecodeError, ValueError):
            return None
        if source.response_text is not None:
            history.append_assistant(source.response_text)
        return history

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
                history = (
                    item.prior_history.clone()
                    if item.prior_history is not None
                    else ChatHistory()
                )
                if item.prior_history is None and self._config.system_prompt:
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
                verdict, detector_id, detector_detail = await self._evaluate(
                    item.payload, response, history.to_messages_json()
                )
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

    async def _evaluate(
        self, payload: Payload, response: TargetResponse, sent_history_json: str
    ) -> tuple[Verdict, str | None, str | None]:
        if response.error is not None:
            return Verdict.ERROR, None, response.error
        if response.reply is None:
            return Verdict.ERROR, None, "no reply extracted from response"
        detectors = default_registry.build_from_payload(payload)
        if not detectors:
            return Verdict.INCONCLUSIVE, None, "payload has no detectors"
        results = [d.evaluate(payload, response.reply) for d in detectors]
        heuristic_verdict = Verdict.SAFE
        heuristic_detail = results[0][1]
        heuristic_id: str | None = None
        for idx, (v, detail) in enumerate(results):
            if v is Verdict.VULNERABLE:
                heuristic_verdict = Verdict.VULNERABLE
                heuristic_detail = detail
                heuristic_id = type(detectors[idx]).__name__
                break
        if self._should_judge(payload, sent_history_json, heuristic_verdict):
            assert self._judge_target is not None
            judge = LlmJudgeDetector(self._judge_target)
            jv, jdetail = await judge.evaluate(
                payload, response.reply, sent_history_json, heuristic_detail
            )
            return jv, "LlmJudgeDetector", jdetail
        if heuristic_verdict is Verdict.VULNERABLE:
            return heuristic_verdict, heuristic_id, heuristic_detail
        for v, detail in results:
            if v is Verdict.ERROR:
                return Verdict.ERROR, None, detail
        for v, detail in results:
            if v is Verdict.INCONCLUSIVE:
                return Verdict.INCONCLUSIVE, None, detail
        return Verdict.SAFE, None, results[0][1] if results else None

    def _should_judge(
        self, payload: Payload, sent_history_json: str, heuristic_verdict: Verdict
    ) -> bool:
        if self._judge_target is None:
            return False
        if heuristic_verdict is Verdict.VULNERABLE or self._config.judge_mode == "all":
            return True
        if self._config.judge_mode != "sample":
            return False
        key = f"{self._config.run_id}:{payload.id}:{sent_history_json}".encode()
        fraction = int.from_bytes(hashlib.sha256(key).digest()[:8]) / 2**64
        return fraction < self._config.judge_sample_rate
