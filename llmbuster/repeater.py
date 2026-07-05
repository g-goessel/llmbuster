from __future__ import annotations

import json

from llmbuster.domain.models import (
    ChatHistory,
    Message,
    Role,
    TargetResponse,
    Verdict,
)
from llmbuster.domain.protocols import Target
from llmbuster.store.sqlite_store import InteractionRecord, SQLiteStore


def _parse_history(sent_history_json: str) -> ChatHistory:
    data = json.loads(sent_history_json)
    if not isinstance(data, list):
        raise ValueError("sent_history_json must be a JSON array of messages")
    messages: list[Message] = []
    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("each message must be a JSON object")
        role_raw = entry.get("role")
        content = entry.get("content")
        if not isinstance(role_raw, str) or not isinstance(content, str):
            raise ValueError("message requires string 'role' and 'content'")
        messages.append(Message(role=Role(role_raw), content=content))
    return ChatHistory(messages=messages)


async def replay_interaction(
    store: SQLiteStore,
    interaction_id: int,
    target: Target,
    edited_history: ChatHistory | None = None,
) -> InteractionRecord:
    original = store.interaction_by_id(interaction_id)
    if original is None:
        raise ValueError(f"interaction {interaction_id} not found")
    history = (
        edited_history
        if edited_history is not None
        else _parse_history(original.sent_history_json)
    )
    response: TargetResponse = await target.send(history)
    record = InteractionRecord(
        run_id=original.run_id,
        payload_id=original.payload_id,
        owasp_category=original.owasp_category,
        attempt_index=original.attempt_index,
        mutation=original.mutation,
        escalation_from=original.escalation_from,
        replayed_from=interaction_id,
        sent_history_json=history.to_messages_json(),
        raw_request_json=response.raw_request_json,
        raw_response_text=response.raw_response_text,
        response_text=response.reply,
        ttft_ms=response.metrics.ttft_ms,
        duration_ms=response.metrics.duration_ms,
        tps=response.metrics.tps,
        prompt_tokens=response.metrics.prompt_tokens,
        completion_tokens=response.metrics.completion_tokens,
        verdict=Verdict.SAFE.value,
        detector_id=None,
        detector_detail=None,
    )
    new_id = store.insert_interaction(record)
    record.id = new_id
    return record
