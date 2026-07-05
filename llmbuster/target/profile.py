from __future__ import annotations

import json
import time
from enum import StrEnum
from typing import Literal

import httpx
from jsonpath_ng import parse as parse_jsonpath
from pydantic import BaseModel, Field

from llmbuster.domain.models import ChatHistory, Metrics, TargetResponse
from llmbuster.target.interpolation import InterpolationContext, interpolate


class SessionMode(StrEnum):
    CLIENT_HISTORY = "client_history"
    SERVER_MANAGED = "server_managed"
    STATELESS = "stateless"


class ResponseType(StrEnum):
    JSON = "json"
    SSE = "sse"
    TEXT = "text"


class RequestConfig(BaseModel):
    method: str = "POST"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""


class ResponseConfig(BaseModel):
    type: ResponseType
    reply_path: str | None = None
    capture: dict[str, str] = Field(default_factory=dict)


class SessionConfig(BaseModel):
    mode: SessionMode = SessionMode.STATELESS


class ProfileConfig(BaseModel):
    kind: Literal["profile"] = "profile"
    name: str
    request: RequestConfig
    response: ResponseConfig
    session: SessionConfig = Field(default_factory=SessionConfig)


def _extract_jsonpath(data: object, path: str) -> object:
    matches = parse_jsonpath(path).find(data)
    if not matches:
        return None
    return matches[0].value


def _coerce_reply(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def _extract_sse_token(payload: str) -> str | None:
    if payload == "[DONE]":
        return None
    try:
        obj = json.loads(payload)
    except (json.JSONDecodeError, ValueError):
        return payload
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        choices = obj.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            delta = choices[0].get("delta")
            if isinstance(delta, dict) and "content" in delta:
                content = delta["content"]
                return content if isinstance(content, str) else json.dumps(content)
    return None


def _compute_tps(
    completion_tokens: int | None,
    duration_ms: int | None,
    ttft_ms: int | None,
) -> float | None:
    if completion_tokens is None or duration_ms is None or ttft_ms is None:
        return None
    if duration_ms <= ttft_ms:
        return None
    return completion_tokens / ((duration_ms - ttft_ms) / 1000)


_SendResult = tuple[str | None, str, Metrics, dict[str, str], str | None]


class ProfileTarget:
    def __init__(
        self,
        config: ProfileConfig,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._captures: dict[str, str] = {}

    @classmethod
    def from_dict(
        cls, data: dict[str, object], client: httpx.AsyncClient | None = None
    ) -> ProfileTarget:
        return cls(ProfileConfig.model_validate(data), client=client)

    @property
    def config(self) -> ProfileConfig:
        return self._config

    @property
    def captures(self) -> dict[str, str]:
        return dict(self._captures)

    async def send(self, history: ChatHistory) -> TargetResponse:
        mode = self._config.session.mode
        captures = {} if mode is SessionMode.STATELESS else dict(self._captures)
        for name in self._config.response.capture:
            captures.setdefault(name, "")
        ctx = InterpolationContext(history=history, captures=captures)

        request = self._config.request
        method = request.method
        url = interpolate(request.url, ctx)
        headers = {k: interpolate(v, ctx) for k, v in request.headers.items()}
        body = interpolate(request.body, ctx)
        raw_request_json = json.dumps(
            {"method": method, "url": url, "headers": headers, "body": body},
            ensure_ascii=False,
        )

        owned = self._client is None
        client = self._client if self._client is not None else httpx.AsyncClient()
        try:
            response_type = self._config.response.type
            if response_type is ResponseType.SSE:
                result = await self._send_sse(client, method, url, headers, body)
            elif response_type is ResponseType.JSON:
                result = await self._send_json(client, method, url, headers, body)
            else:
                result = await self._send_text(client, method, url, headers, body)
        except httpx.HTTPError as exc:
            return TargetResponse(
                reply=None,
                raw_request_json=raw_request_json,
                raw_response_text=None,
                metrics=Metrics(),
                captures={},
                error=f"http error: {exc!s}",
            )
        finally:
            if owned:
                await client.aclose()

        reply, raw_response_text, metrics, response_captures, error = result
        if mode is not SessionMode.STATELESS and response_captures:
            self._captures.update(response_captures)
        return TargetResponse(
            reply=reply,
            raw_request_json=raw_request_json,
            raw_response_text=raw_response_text,
            metrics=metrics,
            captures=response_captures,
            error=error,
        )

    async def _send_json(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> _SendResult:
        start = time.perf_counter()
        resp = await client.request(method, url, headers=headers, content=body)
        elapsed = round((time.perf_counter() - start) * 1000)
        raw_response_text = resp.text.strip()
        if resp.status_code >= 400:
            return (
                None,
                raw_response_text,
                Metrics(duration_ms=elapsed),
                {},
                f"HTTP {resp.status_code}",
            )
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError) as exc:
            return (
                None,
                raw_response_text,
                Metrics(duration_ms=elapsed),
                {},
                f"invalid json: {exc!s}",
            )
        reply_path = self._config.response.reply_path
        if reply_path:
            reply = _coerce_reply(_extract_jsonpath(data, reply_path))
        else:
            reply = _coerce_reply(data)
        if reply is None and isinstance(data, dict) and "error" in data:
            err = data["error"]
            if isinstance(err, dict) and "message" in err:
                error_msg = f"API error: {err['message']}"
            elif isinstance(err, str):
                error_msg = f"API error: {err}"
            else:
                error_msg = f"API error: {err!s}"
            return None, raw_response_text, Metrics(duration_ms=elapsed), {}, error_msg
        captures: dict[str, str] = {}
        for name, path in self._config.response.capture.items():
            value = _extract_jsonpath(data, path)
            captures[name] = "" if value is None else str(value)
        return reply, raw_response_text, Metrics(duration_ms=elapsed), captures, None

    async def _send_text(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> _SendResult:
        start = time.perf_counter()
        resp = await client.request(method, url, headers=headers, content=body)
        elapsed = round((time.perf_counter() - start) * 1000)
        raw_response_text = resp.text.strip()
        if resp.status_code >= 400:
            return (
                None,
                raw_response_text,
                Metrics(duration_ms=elapsed),
                {},
                f"HTTP {resp.status_code}",
            )
        return raw_response_text, raw_response_text, Metrics(duration_ms=elapsed), {}, None

    async def _send_sse(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> _SendResult:
        tokens: list[str] = []
        raw_lines: list[str] = []
        start = time.perf_counter()
        first_token: float | None = None
        last_token: float | None = None
        status_code = 200
        async with client.stream(method, url, headers=headers, content=body) as resp:
            status_code = resp.status_code
            async for line in resp.aiter_lines():
                raw_lines.append(line)
                if not line.startswith("data: "):
                    continue
                payload = line[len("data: ") :]
                token = _extract_sse_token(payload)
                if token is None:
                    continue
                now = time.perf_counter()
                if first_token is None:
                    first_token = now
                last_token = now
                tokens.append(token)
        raw_response_text = "\n".join(raw_lines).strip()
        if status_code >= 400:
            return None, raw_response_text, Metrics(), {}, f"HTTP {status_code}"
        ttft_ms = (
            round((first_token - start) * 1000) if first_token is not None else None
        )
        duration_ms = (
            round((last_token - start) * 1000) if last_token is not None else 0
        )
        completion_tokens = len(tokens)
        tps = _compute_tps(completion_tokens, duration_ms, ttft_ms)
        metrics = Metrics(
            ttft_ms=ttft_ms,
            duration_ms=duration_ms,
            tps=tps,
            completion_tokens=completion_tokens,
        )
        return "".join(tokens), raw_response_text, metrics, {}, None
