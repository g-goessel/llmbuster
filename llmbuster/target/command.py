from __future__ import annotations

import asyncio
import contextlib
import json
import os
from typing import Literal

from pydantic import BaseModel

from llmbuster.domain.models import ChatHistory, Metrics, Role, TargetResponse


class CommandConfig(BaseModel):
    kind: Literal["command"] = "command"
    name: str
    command: list[str]


class CommandTarget:
    def __init__(self, config: CommandConfig, timeout: float = 30.0) -> None:
        self._config = config
        self._timeout = timeout

    @property
    def config(self) -> CommandConfig:
        return self._config

    @property
    def timeout(self) -> float:
        return self._timeout

    def _build_request(self, history: ChatHistory) -> str:
        messages = [
            {"role": m.role.value, "content": m.content} for m in history.messages
        ]
        last_user = ""
        for msg in reversed(history.messages):
            if msg.role is Role.USER:
                last_user = msg.content
                break
        payload = {"messages": messages, "last_user_message": last_user}
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

    async def send(self, history: ChatHistory) -> TargetResponse:
        request_json = self._build_request(history)
        proc = await asyncio.create_subprocess_exec(
            *self._config.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_line, stderr_text = await self._communicate(proc, request_json)
        except _CommandTimeout as exc:
            await self._kill(proc)
            return self._response(
                request_json, reply=None, raw=None, error=str(exc)
            )

        returncode = await proc.wait()

        if stdout_line is None:
            if returncode != 0:
                error = f"process failed: returncode={returncode}"
                if stderr_text:
                    error += f", stderr={stderr_text}"
            else:
                error = "no response from process"
            return self._response(
                request_json,
                reply=None,
                raw=stderr_text or None,
                error=error,
            )

        try:
            parsed = json.loads(stdout_line)
        except (json.JSONDecodeError, ValueError) as exc:
            return self._response(
                request_json,
                reply=None,
                raw=stdout_line,
                error=f"invalid JSON response: {exc!s}",
            )

        if not isinstance(parsed, dict):
            return self._response(
                request_json,
                reply=None,
                raw=stdout_line,
                error="invalid JSON response: not an object",
            )

        reply = parsed.get("reply")
        raw_field = parsed.get("raw")
        raw_response_text = raw_field if isinstance(raw_field, str) else stdout_line
        adapter_error = parsed.get("error")
        error_msg: str | None = None
        if isinstance(adapter_error, str) and adapter_error:
            error_msg = adapter_error
        if returncode != 0 and error_msg is None:
            error_msg = f"process failed: returncode={returncode}"
            if stderr_text:
                error_msg += f", stderr={stderr_text}"

        return TargetResponse(
            reply=reply if isinstance(reply, str) else None,
            raw_request_json=request_json,
            raw_response_text=raw_response_text,
            metrics=Metrics(),
            captures={},
            error=error_msg,
        )

    async def _communicate(
        self, proc: asyncio.subprocess.Process, request_json: str
    ) -> tuple[str | None, str]:
        if proc.stdin is None or proc.stdout is None or proc.stderr is None:
            raise _CommandTimeout("process streams unavailable")
        try:
            proc.stdin.write((request_json + "\n").encode("utf-8"))
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            proc.stdin.close()

        try:
            stdout_bytes = await asyncio.wait_for(
                proc.stdout.readline(), timeout=self._timeout
            )
        except TimeoutError:
            raise _CommandTimeout(f"timeout after {self._timeout}s") from None

        stderr_bytes = await self._read_stderr(proc)

        line = stdout_bytes.decode("utf-8", errors="replace").rstrip("\n")
        return (line or None), stderr_bytes

    async def _read_stderr(self, proc: asyncio.subprocess.Process) -> str:
        if proc.stderr is None:
            return ""
        try:
            stderr_bytes = await asyncio.wait_for(
                proc.stderr.read(), timeout=self._timeout
            )
        except TimeoutError:
            raise _CommandTimeout(f"timeout after {self._timeout}s") from None
        return stderr_bytes.decode("utf-8", errors="replace")

    async def _kill(self, proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
        with contextlib.suppress(Exception):
            await proc.wait()

    def _response(
        self,
        request_json: str,
        *,
        reply: str | None,
        raw: str | None,
        error: str,
    ) -> TargetResponse:
        return TargetResponse(
            reply=reply,
            raw_request_json=request_json,
            raw_response_text=raw,
            metrics=Metrics(),
            captures={},
            error=error,
        )


class _CommandTimeout(Exception):
    pass


def load_command_from_dict(data: dict[str, object]) -> CommandTarget:
    return CommandTarget(CommandConfig.model_validate(data))


def load_command_from_file(path: str | os.PathLike[str]) -> CommandTarget:
    import yaml

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"command profile must be a mapping: {path}")
    return load_command_from_dict(data)
