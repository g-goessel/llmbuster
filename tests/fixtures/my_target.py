from __future__ import annotations

from llmbuster.domain.models import (
    ChatHistory,
    Metrics,
    Role,
    TargetResponse,
)


class MyTarget:
    async def send(self, history: ChatHistory) -> TargetResponse:
        last_user = next(
            (m.content for m in reversed(history.messages) if m.role is Role.USER),
            "",
        )
        reply = f"plugin-echo: {last_user}"
        return TargetResponse(
            reply=reply,
            raw_request_json=history.to_messages_json(),
            raw_response_text=reply,
            metrics=Metrics(),
            captures={},
            error=None,
        )
