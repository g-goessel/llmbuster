from __future__ import annotations

import json

from llmbuster.utils import mask_request_json, mask_secrets


def test_mask_authorization_header() -> None:
    result = mask_secrets(
        {"headers": {"Authorization": "Bearer sk-or-v1-1234567890"}}
    )
    assert result["headers"]["Authorization"] == "Bearer s...26chars"


def test_mask_short_secret() -> None:
    result = mask_secrets({"headers": {"Authorization": "abc"}})
    assert result["headers"]["Authorization"] == "***"


def test_mask_non_sensitive_header() -> None:
    result = mask_secrets(
        {"headers": {"Content-Type": "application/json"}}
    )
    assert result["headers"]["Content-Type"] == "application/json"


def test_mask_no_headers() -> None:
    result = mask_secrets({"method": "POST"})
    assert result == {"method": "POST"}


def test_mask_request_json_masks_authorization() -> None:
    raw = json.dumps(
        {
            "method": "POST",
            "url": "https://example.com",
            "headers": {"Authorization": "Bearer sk-or-v1-abcdefghij"},
            "body": "hi",
        }
    )
    masked = mask_request_json(raw)
    assert "sk-or-v1-abcdefghij" not in masked
    assert "Bearer s" in masked


def test_mask_request_json_invalid_json_returns_original() -> None:
    raw = "not json"
    assert mask_request_json(raw) == "not json"
