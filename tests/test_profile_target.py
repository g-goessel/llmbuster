from __future__ import annotations

import json

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from llmbuster.domain import ChatHistory, Message, Role, Target
from llmbuster.target.profile import ProfileConfig, ProfileTarget, SessionMode
from tests.mock_server import MockLLMServer, MockResponse

JSON_BODY = (
    '{"user_message":"${last_user_message}",'
    '"messages":${messages_json},"session_id":"${session_id}"}'
)


def _json_profile(
    url: str = "http://mock/chat",
    mode: SessionMode = SessionMode.STATELESS,
    body: str = JSON_BODY,
) -> dict[str, object]:
    return {
        "kind": "profile",
        "name": "test",
        "request": {
            "method": "POST",
            "url": url,
            "headers": {
                "Content-Type": "application/json",
                "Authorization": "Bearer ${env:TARGET_TOKEN}",
            },
            "body": body,
        },
        "response": {
            "type": "json",
            "reply_path": "$.data.reply",
            "capture": {"session_id": "$.data.session_id"},
        },
        "session": {"mode": mode.value},
    }


def _text_profile(url: str = "http://mock/chat/text") -> dict[str, object]:
    return {
        "kind": "profile",
        "name": "text-target",
        "request": {
            "method": "POST",
            "url": url,
            "headers": {},
            "body": "${last_user_message}",
        },
        "response": {"type": "text"},
        "session": {"mode": "stateless"},
    }


def _sse_profile(url: str = "http://mock/chat/stream") -> dict[str, object]:
    return {
        "kind": "profile",
        "name": "sse-target",
        "request": {
            "method": "POST",
            "url": url,
            "headers": {"Accept": "text/event-stream"},
            "body": '{"user_message":"${last_user_message}"}',
        },
        "response": {"type": "sse"},
        "session": {"mode": "stateless"},
    }


def _client(server: MockLLMServer) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server), base_url="http://mock"
    )


def _client_from_app(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://mock"
    )


def _history(*pairs: tuple[Role, str]) -> ChatHistory:
    return ChatHistory(
        messages=[Message(role=role, content=content) for role, content in pairs]
    )


def test_profile_target_implements_target_protocol() -> None:
    target = ProfileTarget(ProfileConfig.model_validate(_json_profile()))
    assert isinstance(target, Target)


async def test_json_response_extracts_reply_and_captures(
    mock_server: MockLLMServer,
) -> None:
    mock_server.configure(
        "/chat",
        MockResponse(json_body={"data": {"reply": "PWNED", "session_id": "sess-9"}}),
    )
    target = ProfileTarget(
        ProfileConfig.model_validate(_json_profile()), client=_client(mock_server)
    )
    response = await target.send(_history((Role.SYSTEM, "sys"), (Role.USER, "hi")))
    assert response.reply == "PWNED"
    assert response.error is None
    assert response.captures == {"session_id": "sess-9"}
    request = json.loads(response.raw_request_json)
    assert request["method"] == "POST"
    assert request["headers"]["Authorization"] == "Bearer test-token"
    assert json.loads(request["body"])["user_message"] == "hi"
    assert request["body"].count('"session_id":""') == 1
    assert response.metrics.duration_ms is not None
    assert response.metrics.ttft_ms is None
    assert response.metrics.tps is None
    assert response.raw_response_text is not None


async def test_json_server_managed_carries_session_id_across_calls(
    mock_server: MockLLMServer,
) -> None:
    mock_server.configure(
        "/chat",
        MockResponse(json_body={"data": {"reply": "ok", "session_id": "sess-1"}}),
    )
    target = ProfileTarget(
        ProfileConfig.model_validate(_json_profile(mode=SessionMode.SERVER_MANAGED)),
        client=_client(mock_server),
    )
    first = await target.send(_history((Role.USER, "first")))
    assert first.captures == {"session_id": "sess-1"}
    second = await target.send(_history((Role.USER, "second")))
    request = json.loads(second.raw_request_json)
    assert json.loads(request["body"])["session_id"] == "sess-1"
    assert target.captures == {"session_id": "sess-1"}


async def test_json_stateless_does_not_carry_session_id(
    mock_server: MockLLMServer,
) -> None:
    mock_server.configure(
        "/chat",
        MockResponse(json_body={"data": {"reply": "ok", "session_id": "s-x"}}),
    )
    target = ProfileTarget(
        ProfileConfig.model_validate(_json_profile(mode=SessionMode.STATELESS)),
        client=_client(mock_server),
    )
    await target.send(_history((Role.USER, "first")))
    second = await target.send(_history((Role.USER, "second")))
    request = json.loads(second.raw_request_json)
    assert json.loads(request["body"])["session_id"] == ""
    assert target.captures == {}


async def test_json_client_history_sends_full_messages_json(
    mock_server: MockLLMServer,
) -> None:
    mock_server.configure(
        "/chat",
        MockResponse(json_body={"data": {"reply": "ok", "session_id": "s"}}),
    )
    target = ProfileTarget(
        ProfileConfig.model_validate(_json_profile(mode=SessionMode.CLIENT_HISTORY)),
        client=_client(mock_server),
    )
    history = _history(
        (Role.SYSTEM, "sys"),
        (Role.USER, "u1"),
        (Role.ASSISTANT, "a1"),
        (Role.USER, "u2"),
    )
    response = await target.send(history)
    request = json.loads(response.raw_request_json)
    body = json.loads(request["body"])
    assert len(body["messages"]) == 4
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    assert body["messages"][-1] == {"role": "user", "content": "u2"}


async def test_text_response_uses_raw_body(mock_server: MockLLMServer) -> None:
    mock_server.configure("/chat/text", MockResponse(text_body="raw reply text"))
    target = ProfileTarget(
        ProfileConfig.model_validate(_text_profile()), client=_client(mock_server)
    )
    response = await target.send(_history((Role.USER, "ping")))
    assert response.reply == "raw reply text"
    assert response.error is None
    assert response.metrics.ttft_ms is None
    assert response.metrics.duration_ms is not None


async def test_sse_accumulates_tokens_and_metrics(
    mock_server: MockLLMServer,
) -> None:
    mock_server.configure(
        "/chat/stream",
        MockResponse(sse_tokens=["Hel", "lo", " world"], sse_delay=0.05),
    )
    target = ProfileTarget(
        ProfileConfig.model_validate(_sse_profile()), client=_client(mock_server)
    )
    response = await target.send(_history((Role.USER, "hi")))
    assert response.reply == "Hello world"
    assert response.error is None
    assert response.metrics.completion_tokens == 3
    assert response.metrics.ttft_ms is not None and response.metrics.ttft_ms >= 0
    assert response.metrics.duration_ms is not None
    assert response.metrics.duration_ms >= response.metrics.ttft_ms
    if response.metrics.duration_ms > response.metrics.ttft_ms:
        assert response.metrics.tps is not None and response.metrics.tps > 0


async def test_sse_openai_style_delta_tokens(mock_server: MockLLMServer) -> None:
    mock_server.configure(
        "/chat/stream",
        MockResponse(
            sse_tokens=[
                json.dumps({"choices": [{"delta": {"content": "Hi"}}]}),
                json.dumps({"choices": [{"delta": {"content": " there"}}]}),
                "[DONE]",
            ],
            sse_delay=0.0,
        ),
    )
    target = ProfileTarget(
        ProfileConfig.model_validate(_sse_profile()), client=_client(mock_server)
    )
    response = await target.send(_history((Role.USER, "hi")))
    assert response.reply == "Hi there"
    assert response.metrics.completion_tokens == 2


async def test_http_error_surfaces_error(mock_server: MockLLMServer) -> None:
    mock_server.configure("/chat", MockResponse(status=500, json_body={"error": "boom"}))
    target = ProfileTarget(
        ProfileConfig.model_validate(_json_profile()), client=_client(mock_server)
    )
    response = await target.send(_history((Role.USER, "hi")))
    assert response.reply is None
    assert response.error is not None
    assert "500" in response.error


async def test_env_missing_raises_during_interpolation(
    mock_server: MockLLMServer,
) -> None:
    mock_server.configure("/chat", MockResponse(json_body={"data": {"reply": "x"}}))
    profile = _json_profile()
    profile["request"]["headers"]["Authorization"] = (
        "Bearer ${env:DEFINITELY_MISSING}"
    )
    target = ProfileTarget(
        ProfileConfig.model_validate(profile), client=_client(mock_server)
    )
    with pytest.raises(Exception, match="missing env var"):
        await target.send(_history((Role.USER, "hi")))


async def test_jsonpath_reply_extraction_nested() -> None:
    app = FastAPI()

    async def custom_handler() -> JSONResponse:
        return JSONResponse(content={"result": {"output": {"text": "deep reply"}}})

    app.add_api_route("/chat", custom_handler, methods=["POST"], response_model=None)
    profile = _json_profile()
    profile["request"]["body"] = '{"user_message":"${last_user_message}"}'
    profile["response"] = {"type": "json", "reply_path": "$.result.output.text"}
    target = ProfileTarget(
        ProfileConfig.model_validate(profile), client=_client_from_app(app)
    )
    response = await target.send(_history((Role.USER, "q")))
    assert response.reply == "deep reply"


async def test_connection_error_surfaces_in_target_response() -> None:
    target = ProfileTarget(
        ProfileConfig.model_validate(_json_profile(url="http://nonexistent.invalid/chat"))
    )
    response = await target.send(_history((Role.USER, "hi")))
    assert response.reply is None
    assert response.error is not None
    assert "http error" in response.error
