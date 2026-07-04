from __future__ import annotations

from typing import Protocol, runtime_checkable

from llmbuster.domain.models import ChatHistory, Payload, TargetResponse, Verdict


@runtime_checkable
class Target(Protocol):
    async def send(self, history: ChatHistory) -> TargetResponse: ...


@runtime_checkable
class Detector(Protocol):
    def evaluate(self, payload: Payload, reply: str | None) -> tuple[Verdict, str]: ...
