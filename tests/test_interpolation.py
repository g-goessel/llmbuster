from __future__ import annotations

import uuid
from datetime import datetime

import pytest

from llmbuster.domain import ChatHistory, Message, Role
from llmbuster.target.interpolation import (
    InterpolationContext,
    InterpolationError,
    interpolate,
)


def _ctx(
    history: ChatHistory | None = None,
    captures: dict[str, str] | None = None,
    extras: dict[str, str] | None = None,
    env: dict[str, str] | None = None,
) -> InterpolationContext:
    return InterpolationContext(
        history=history or ChatHistory(),
        captures=captures or {},
        extras=extras or {},
        env=env,
    )


def _history(*pairs: tuple[Role, str]) -> ChatHistory:
    return ChatHistory(messages=[Message(role=role, content=content) for role, content in pairs])


def test_no_placeholders_returns_unchanged() -> None:
    assert interpolate("plain text no placeholders", _ctx()) == "plain text no placeholders"


def test_last_user_message_resolves() -> None:
    history = _history(
        (Role.SYSTEM, "sys"),
        (Role.USER, "first"),
        (Role.ASSISTANT, "a1"),
        (Role.USER, "second"),
    )
    result = interpolate("q: ${last_user_message}", _ctx(history=history))
    assert result == "q: second"


def test_last_user_message_picks_most_recent() -> None:
    history = _history((Role.USER, "old"), (Role.USER, "new"))
    assert interpolate("${last_user_message}", _ctx(history=history)) == "new"


def test_last_user_message_raises_when_none() -> None:
    history = _history((Role.ASSISTANT, "a1"))
    with pytest.raises(InterpolationError, match="no user message"):
        interpolate("${last_user_message}", _ctx(history=history))


def test_messages_json_resolves() -> None:
    history = _history((Role.SYSTEM, "s"), (Role.USER, "u"))
    result = interpolate("${messages_json}", _ctx(history=history))
    assert result == history.to_messages_json()
    assert result == '[{"role":"system","content":"s"},{"role":"user","content":"u"}]'


def test_env_var_resolves() -> None:
    ctx = _ctx(env={"TARGET_TOKEN": "abc123"})
    assert interpolate("Bearer ${env:TARGET_TOKEN}", ctx) == "Bearer abc123"


def test_env_var_missing_raises() -> None:
    with pytest.raises(InterpolationError, match="missing env var: MISSING"):
        interpolate("${env:MISSING}", _ctx(env={}))


def test_env_var_uses_os_environ_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLMBUSTER_TEST_VAR", "from-os")
    assert interpolate("${env:LLMBUSTER_TEST_VAR}", _ctx()) == "from-os"


def test_uuid_resolves_to_valid_uuid() -> None:
    result = interpolate("${uuid}", _ctx())
    parsed = uuid.UUID(result)
    assert str(parsed) == result


def test_timestamp_resolves_to_iso() -> None:
    result = interpolate("${timestamp}", _ctx())
    datetime.fromisoformat(result)


def test_captured_var_resolves() -> None:
    ctx = _ctx(captures={"session_id": "sess-42"})
    assert interpolate("${session_id}", ctx) == "sess-42"


def test_extras_resolve() -> None:
    ctx = _ctx(extras={"model": "gpt-x"})
    assert interpolate("${model}", ctx) == "gpt-x"


def test_captures_take_precedence_over_extras() -> None:
    ctx = _ctx(captures={"k": "from-captures"}, extras={"k": "from-extras"})
    assert interpolate("${k}", ctx) == "from-captures"


def test_unknown_placeholder_raises() -> None:
    with pytest.raises(InterpolationError, match="unknown placeholder: nope"):
        interpolate("${nope}", _ctx())


def test_multiple_placeholders_in_one_template() -> None:
    history = _history((Role.USER, "hello"))
    ctx = _ctx(history=history, captures={"session_id": "s1"}, env={"TOKEN": "t"})
    template = '{"sid":"${session_id}","msg":"${last_user_message}","tok":"${env:TOKEN}"}'
    assert interpolate(template, ctx) == '{"sid":"s1","msg":"hello","tok":"t"}'


def test_replacement_value_containing_dollar_brace_is_not_reprocessed() -> None:
    history = _history((Role.USER, "${not_a_placeholder}"))
    result = interpolate("${last_user_message}", _ctx(history=history))
    assert result == "${not_a_placeholder}"


def test_env_var_with_colon_in_value() -> None:
    ctx = _ctx(env={"URL": "https://example.com:8080/path"})
    assert interpolate("${env:URL}", ctx) == "https://example.com:8080/path"


def test_repeated_placeholder_each_resolves_independently() -> None:
    history = _history((Role.USER, "x"))
    ctx = _ctx(history=history)
    result = interpolate("${last_user_message}-${last_user_message}", ctx)
    assert result == "x-x"
