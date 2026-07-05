from __future__ import annotations

import json
from typing import Any

_SENSITIVE_HEADERS = frozenset(
    {"authorization", "x-api-key", "api-key", "x-auth-token", "cookie", "set-cookie"}
)


def mask_secrets(request_obj: dict[str, Any]) -> dict[str, Any]:
    headers = request_obj.get("headers")
    if not isinstance(headers, dict):
        return request_obj
    masked: dict[str, str] = {}
    for key, val in headers.items():
        if isinstance(key, str) and key.lower() in _SENSITIVE_HEADERS:
            if isinstance(val, str) and len(val) > 8:
                masked[key] = f"{val[:8]}...{len(val)}chars"
            elif isinstance(val, str):
                masked[key] = "***"
            else:
                masked[key] = "***"
        else:
            masked[key] = val
    return {**request_obj, "headers": masked}


def mask_request_json(raw_request_json: str) -> str:
    try:
        parsed = json.loads(raw_request_json)
    except (json.JSONDecodeError, ValueError):
        return raw_request_json
    if not isinstance(parsed, dict):
        return raw_request_json
    return json.dumps(mask_secrets(parsed), indent=2, ensure_ascii=False)
