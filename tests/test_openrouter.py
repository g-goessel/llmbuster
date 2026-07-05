from __future__ import annotations

import json

import httpx
import pytest
from pytest_httpx import HTTPXMock

from llmbuster.domain import ChatHistory, Message, Role
from llmbuster.target.openrouter import (
    OPENROUTER_MODELS_URL,
    ModelInfo,
    build_profile,
    build_target,
    fetch_models,
)

_MODELS_PAYLOAD = {
    "data": [
        {
            "id": "openai/gpt-4o",
            "name": "GPT-4o",
            "context_length": 128000,
            "pricing": {"prompt": "0.000005", "completion": "0.000015"},
        },
        {
            "id": "anthropic/claude-3.5-sonnet",
            "name": "Claude 3.5 Sonnet",
            "context_length": 200000,
            "pricing": {"prompt": "0.000003", "completion": "0.000015"},
        },
        {
            "id": "meta-llama/llama-3.1-8b-instruct",
            "name": "Llama 3.1 8B Instruct",
            "context_length": 131072,
            "pricing": None,
        },
    ]
}


async def test_fetch_models_parses_list(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url=OPENROUTER_MODELS_URL,
        json=_MODELS_PAYLOAD,
    )
    async with httpx.AsyncClient() as client:
        models = await fetch_models(client)
    assert len(models) == 3
    assert models[0].id == "openai/gpt-4o"
    assert models[0].name == "GPT-4o"
    assert models[0].context_length == 128000
    assert models[0].pricing == {"prompt": "0.000005", "completion": "0.000015"}
    assert models[1].id == "anthropic/claude-3.5-sonnet"
    assert models[1].context_length == 200000
    assert models[2].pricing is None
    assert models[2].context_length == 131072


async def test_fetch_models_empty_list(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(url=OPENROUTER_MODELS_URL, json={"data": []})
    async with httpx.AsyncClient() as client:
        models = await fetch_models(client)
    assert models == []


async def test_fetch_models_handles_list_without_data_key(
    httpx_mock: HTTPXMock,
) -> None:
    httpx_mock.add_response(url=OPENROUTER_MODELS_URL, json=_MODELS_PAYLOAD["data"])
    async with httpx.AsyncClient() as client:
        models = await fetch_models(client)
    assert len(models) == 3


async def test_fetch_models_raises_on_http_error(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(url=OPENROUTER_MODELS_URL, status_code=500)
    async with httpx.AsyncClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await fetch_models(client)


def test_model_info_round_trip() -> None:
    model = ModelInfo(
        id="test/model",
        name="Test",
        context_length=4096,
        pricing={"prompt": "0", "completion": "0"},
    )
    dumped = model.model_dump_json()
    rebuilt = ModelInfo.model_validate_json(dumped)
    assert rebuilt == model


def test_build_profile_bakes_model_into_body() -> None:
    config = build_profile("openai/gpt-4o")
    assert config.kind == "profile"
    assert config.request.url == "https://openrouter.ai/api/v1/chat/completions"
    assert "__MODEL__" not in config.request.body
    assert "openai/gpt-4o" in config.request.body
    assert "${messages_json}" in config.request.body
    assert '"stream": true' in config.request.body
    assert config.response.type.value == "sse"
    assert config.response.reply_path is None
    assert config.session.mode.value == "stateless"


def test_build_profile_different_models() -> None:
    config_a = build_profile("openai/gpt-4o")
    config_b = build_profile("anthropic/claude-3.5-sonnet")
    assert "openai/gpt-4o" in config_a.request.body
    assert "anthropic/claude-3.5-sonnet" in config_b.request.body
    assert "openai/gpt-4o" not in config_b.request.body


def test_build_target_returns_profile_target() -> None:
    target = build_target("openai/gpt-4o")
    assert target.config.request.url == "https://openrouter.ai/api/v1/chat/completions"
    assert "openai/gpt-4o" in target.config.request.body


async def test_build_target_sends_correct_model_in_request(
    httpx_mock: HTTPXMock,
) -> None:
    sse_body = (
        b'data: {"choices":[{"delta":{"content":"hello from gpt-4o"}}]}\n\n'
        b"data: [DONE]\n\n"
    )
    httpx_mock.add_response(
        url="https://openrouter.ai/api/v1/chat/completions",
        content=sse_body,
        headers={"content-type": "text/event-stream"},
    )
    target = build_target("openai/gpt-4o")
    history = ChatHistory(messages=[Message(role=Role.USER, content="hi")])
    response = await target.send(history)
    assert response.reply == "hello from gpt-4o"
    request = json.loads(response.raw_request_json)
    body = json.loads(request["body"])
    assert body["model"] == "openai/gpt-4o"
    assert body["stream"] is True
    assert body["messages"] == [{"role": "user", "content": "hi"}]
