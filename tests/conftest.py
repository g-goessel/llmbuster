from __future__ import annotations

import pytest

from tests.mock_server import MockLLMServer, MockResponse


@pytest.fixture(autouse=True)
def _set_env_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TARGET_TOKEN", "test-token")
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")


@pytest.fixture
def mock_server() -> MockLLMServer:
    return MockLLMServer()


@pytest.fixture
def sse_response() -> MockResponse:
    return MockResponse(
        sse_tokens=["Hello", " ", "world"],
        sse_delay=0.02,
    )
