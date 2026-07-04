from __future__ import annotations

import os
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime

from llmbuster.domain.models import ChatHistory, Role

_PLACEHOLDER = re.compile(r"\$\{([^}]+)\}")


class InterpolationError(ValueError):
    pass


@dataclass
class InterpolationContext:
    history: ChatHistory
    captures: dict[str, str] = field(default_factory=dict)
    extras: dict[str, str] = field(default_factory=dict)
    env: Mapping[str, str] | None = None

    def _env(self) -> Mapping[str, str]:
        return self.env if self.env is not None else os.environ


def interpolate(template: str, ctx: InterpolationContext) -> str:
    def repl(match: re.Match[str]) -> str:
        return _resolve(match.group(1), ctx)

    return _PLACEHOLDER.sub(repl, template)


def _resolve(key: str, ctx: InterpolationContext) -> str:
    if key.startswith("env:"):
        var = key[4:]
        env = ctx._env()
        if var not in env:
            raise InterpolationError(f"missing env var: {var}")
        return env[var]
    if key == "last_user_message":
        return _last_user_message(ctx.history)
    if key == "messages_json":
        return ctx.history.to_messages_json()
    if key == "uuid":
        return str(uuid.uuid4())
    if key == "timestamp":
        return datetime.now(UTC).isoformat()
    if key in ctx.captures:
        return ctx.captures[key]
    if key in ctx.extras:
        return ctx.extras[key]
    raise InterpolationError(f"unknown placeholder: {key}")


def _last_user_message(history: ChatHistory) -> str:
    for msg in reversed(history.messages):
        if msg.role is Role.USER:
            return msg.content
    raise InterpolationError("no user message in history")
