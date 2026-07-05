from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MockResponse:
    status: int = 200
    json_body: dict[str, Any] | None = None
    text_body: str | None = None
    raw_body: str | None = None
    sse_tokens: list[str] = field(default_factory=list)
    sse_delay: float = 0.0
    headers: dict[str, str] = field(default_factory=dict)


Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


class MockLLMServer:
    def __init__(self) -> None:
        self.routes: dict[str, MockResponse] = {}
        self.received_requests: list[dict[str, Any]] = []

    def configure(self, path: str, response: MockResponse) -> None:
        self.routes[path] = response

    def clear(self) -> None:
        self.routes.clear()
        self.received_requests.clear()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        path = scope["path"]
        method = scope.get("method", "POST")
        body = await self._read_body(receive)
        self.received_requests.append(
            {"method": method, "path": path, "body": body, "headers": scope.get("headers", [])}
        )
        response = self.routes.get(path)
        if response is None:
            await self._send(send, 404, b'{"error":"not found"}', "application/json")
            return
        if response.sse_tokens:
            await self._send_sse(send, response)
        elif response.json_body is not None:
            payload = json.dumps(response.json_body).encode()
            await self._send(
                send, response.status, payload, "application/json", response.headers
            )
        elif response.text_body is not None:
            await self._send(
                send, response.status, response.text_body.encode(), "text/plain", response.headers
            )
        elif response.raw_body is not None:
            await self._send(
                send,
                response.status,
                response.raw_body.encode(),
                "application/json",
                response.headers,
            )
        else:
            await self._send(send, response.status, b"", "text/plain", response.headers)

    @staticmethod
    async def _read_body(receive: Receive) -> bytes:
        body = b""
        more = True
        while more:
            msg = await receive()
            if msg["type"] == "http.request":
                body += msg.get("body", b"")
                more = msg.get("more_body", False)
            else:
                break
        return body

    @staticmethod
    async def _send(
        send: Send,
        status: int,
        body: bytes,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        headers: list[tuple[bytes, bytes]] = [(b"content-type", content_type.encode())]
        for key, value in (extra_headers or {}).items():
            headers.append((key.lower().encode(), value.encode()))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    @staticmethod
    async def _send_sse(send: Send, response: MockResponse) -> None:
        headers: list[tuple[bytes, bytes]] = [(b"content-type", b"text/event-stream")]
        for key, value in response.headers.items():
            headers.append((key.lower().encode(), value.encode()))
        await send(
            {"type": "http.response.start", "status": response.status, "headers": headers}
        )
        for token in response.sse_tokens:
            chunk = f"data: {token}\n\n".encode()
            await send({"type": "http.response.body", "body": chunk, "more_body": True})
            if response.sse_delay:
                await asyncio.sleep(response.sse_delay)
        await send({"type": "http.response.body", "body": b"", "more_body": False})
