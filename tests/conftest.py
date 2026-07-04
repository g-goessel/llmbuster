from __future__ import annotations

import pytest

from tests.mock_server import MockLLMServer, MockResponse


@pytest.fixture
def mock_server() -> MockLLMServer:
    return MockLLMServer()


@pytest.fixture
def sse_response() -> MockResponse:
    return MockResponse(
        sse_tokens=["Hello", " ", "world"],
        sse_delay=0.02,
    )
