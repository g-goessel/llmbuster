from __future__ import annotations

import json
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, Field


class Role(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class Message(BaseModel):
    role: Role
    content: str


class ChatHistory(BaseModel):
    messages: list[Message] = []

    def append(self, msg: Message) -> None:
        self.messages.append(msg)

    def append_user(self, content: str) -> None:
        self.messages.append(Message(role=Role.USER, content=content))

    def append_assistant(self, content: str) -> None:
        self.messages.append(Message(role=Role.ASSISTANT, content=content))

    def clone(self) -> ChatHistory:
        return self.model_copy(deep=True)

    def to_messages_json(self) -> str:
        payload = [{"role": m.role.value, "content": m.content} for m in self.messages]
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


class OwaspCategory(StrEnum):
    LLM01 = "LLM01"
    LLM02 = "LLM02"
    LLM03 = "LLM03"
    LLM04 = "LLM04"
    LLM05 = "LLM05"
    LLM06 = "LLM06"
    LLM07 = "LLM07"
    LLM08 = "LLM08"
    LLM09 = "LLM09"
    LLM10 = "LLM10"


class Verdict(StrEnum):
    VULNERABLE = "vulnerable"
    SAFE = "safe"
    ERROR = "error"
    INCONCLUSIVE = "inconclusive"


class Metrics(BaseModel):
    ttft_ms: int | None = None
    duration_ms: int | None = None
    tps: float | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class TargetResponse(BaseModel):
    reply: str | None
    raw_request_json: str
    raw_response_text: str | None
    metrics: Metrics
    captures: dict[str, str] = {}
    error: str | None = None


class Interaction(BaseModel):
    run_id: int
    payload_id: str
    owasp_category: OwaspCategory
    attempt_index: int
    mutation: str | None = None
    escalation_from: int | None = None
    sent_history_json: str
    raw_request_json: str
    raw_response_text: str | None
    response_text: str | None
    metrics: Metrics
    verdict: Verdict
    detector_id: str | None = None
    detector_detail: str | None = None


class CanaryDetectorConfig(BaseModel):
    type: Literal["canary"]
    token: str


class RegexDetectorConfig(BaseModel):
    type: Literal["regex"]
    pattern: str
    flags: str | None = None


DetectorConfig = Annotated[
    CanaryDetectorConfig | RegexDetectorConfig,
    Field(discriminator="type"),
]


class Payload(BaseModel):
    id: str
    prompt: str
    repeat: int = 1
    detectors: list[DetectorConfig] = []
    mutations: list[str] = []
    escalation_to: str | None = None


class PayloadPack(BaseModel):
    category: OwaspCategory
    payloads: list[Payload]
