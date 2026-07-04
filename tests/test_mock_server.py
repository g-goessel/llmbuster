from __future__ import annotations

import time

import httpx
import pytest

from tests.mock_server import MockLLMServer, MockResponse


async def test_json_response_via_asgi_transport(mock_server: MockLLMServer) -> None:
    mock_server.configure(
        "/chat",
        MockResponse(json_body={"data": {"reply": "PWNED", "session_id": "abc"}}),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_server), base_url="http://mock"
    ) as client:
        response = await client.post("/chat", json={"user_message": "hi"})
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    body = response.json()
    assert body["data"]["reply"] == "PWNED"
    assert body["data"]["session_id"] == "abc"
    assert mock_server.received_requests[-1]["path"] == "/chat"


async def test_text_response_via_asgi_transport(mock_server: MockLLMServer) -> None:
    mock_server.configure("/chat/text", MockResponse(text_body="raw reply"))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_server), base_url="http://mock"
    ) as client:
        response = await client.post("/chat/text", content=b"ping")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/plain"
    assert response.text == "raw reply"


async def test_sse_tokens_arrive_in_order(
    mock_server: MockLLMServer, sse_response: MockResponse
) -> None:
    mock_server.configure("/chat/stream", sse_response)
    received: list[str] = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_server), base_url="http://mock"
    ) as client, client.stream("POST", "/chat/stream", json={"user_message": "hi"}) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "text/event-stream"
        async for line in resp.aiter_lines():
            if line.startswith("data: "):
                received.append(line[len("data: ") :])
    assert received == ["Hello", " ", "world"]


async def test_sse_respects_token_delays(
    mock_server: MockLLMServer, sse_response: MockResponse
) -> None:
    sse_response.sse_delay = 0.05
    sse_response.sse_tokens = ["a", "b", "c"]
    mock_server.configure("/chat/stream", sse_response)
    timestamps: list[float] = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_server), base_url="http://mock"
    ) as client:
        start = time.perf_counter()
        async with client.stream("POST", "/chat/stream") as resp:
            async for line in resp.aiter_lines():
                if line.startswith("data: "):
                    timestamps.append(time.perf_counter() - start)
    assert len(timestamps) == 3
    elapsed = timestamps[-1]
    expected_min = 0.05 * 2 * 0.9
    assert elapsed >= expected_min
    assert elapsed < 5.0


async def test_sse_single_token(mock_server: MockLLMServer) -> None:
    mock_server.configure(
        "/chat/stream", MockResponse(sse_tokens=["solo"], sse_delay=0.0)
    )
    received: list[str] = []
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_server), base_url="http://mock"
    ) as client, client.stream("POST", "/chat/stream") as resp:
        async for line in resp.aiter_lines():
            if line.startswith("data: "):
                received.append(line[len("data: ") :])
    assert received == ["solo"]


async def test_unconfigured_path_returns_404(mock_server: MockLLMServer) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_server), base_url="http://mock"
    ) as client:
        response = await client.post("/unknown", json={})
    assert response.status_code == 404


async def test_received_request_body_captured(mock_server: MockLLMServer) -> None:
    mock_server.configure("/chat", MockResponse(json_body={"data": {"reply": "ok"}}))
    payload = {"user_message": "hello", "session_id": "s1"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=mock_server), base_url="http://mock"
    ) as client:
        await client.post("/chat", json=payload)
    last = mock_server.received_requests[-1]
    assert last["path"] == "/chat"
    assert last["method"] == "POST"
    import json

    assert json.loads(last["body"]) == payload


async def test_httpx_mock_fixture_works(httpx_mock: pytest.httpx.HTTPXMock) -> None:
    httpx_mock.add_response(
        url="http://example.test/models",
        json={"data": [{"id": "model-a"}, {"id": "model-b"}]},
    )
    async with httpx.AsyncClient() as client:
        response = await client.get("http://example.test/models")
    assert response.status_code == 200
    body = response.json()
    assert body["data"] == [{"id": "model-a"}, {"id": "model-b"}]
