from __future__ import annotations

import json

import pytest

from llmbuster.domain import ChatHistory, Message, Metrics, Role, Target, TargetResponse

EMPTY_JSON = "[]"


def test_append_grows_in_order() -> None:
    history = ChatHistory()
    assert history.messages == []
    history.append(Message(role=Role.SYSTEM, content="sys"))
    history.append(Message(role=Role.USER, content="u1"))
    history.append(Message(role=Role.ASSISTANT, content="a1"))
    assert [(m.role, m.content) for m in history.messages] == [
        (Role.SYSTEM, "sys"),
        (Role.USER, "u1"),
        (Role.ASSISTANT, "a1"),
    ]


def test_append_user_and_assistant_convenience() -> None:
    history = ChatHistory()
    history.append_user("hi")
    history.append_assistant("hello")
    assert [(m.role, m.content) for m in history.messages] == [
        (Role.USER, "hi"),
        (Role.ASSISTANT, "hello"),
    ]


def test_to_messages_json_empty() -> None:
    assert ChatHistory().to_messages_json() == EMPTY_JSON


def test_to_messages_json_exact_compact_output() -> None:
    history = ChatHistory(
        messages=[
            Message(role=Role.SYSTEM, content="sys"),
            Message(role=Role.USER, content="hi"),
            Message(role=Role.ASSISTANT, content="hello"),
        ]
    )
    expected = (
        '[{"role":"system","content":"sys"},'
        '{"role":"user","content":"hi"},'
        '{"role":"assistant","content":"hello"}]'
    )
    assert history.to_messages_json() == expected


def test_to_messages_json_round_trips_into_chat_history() -> None:
    original = ChatHistory(
        messages=[
            Message(role=Role.SYSTEM, content="sys"),
            Message(role=Role.USER, content="ping"),
            Message(role=Role.ASSISTANT, content="pong"),
        ]
    )
    encoded = original.to_messages_json()
    parsed = json.loads(encoded)
    rebuilt = ChatHistory(messages=[Message(**m) for m in parsed])
    assert rebuilt == original


def test_clone_is_deep_copy() -> None:
    original = ChatHistory(messages=[Message(role=Role.USER, content="orig")])
    clone = original.clone()
    assert clone == original
    clone.append_user("clone-only")
    assert clone.messages[-1].content == "clone-only"
    assert len(original.messages) == 1
    assert original.messages[0].content == "orig"
    original.append_assistant("orig-only")
    assert len(clone.messages) == 2
    assert clone.messages[-1].content == "clone-only"


def test_clone_message_objects_are_distinct() -> None:
    original = ChatHistory(messages=[Message(role=Role.USER, content="c")])
    clone = original.clone()
    assert clone.messages[0] == original.messages[0]
    clone.messages[0].content = "mutated"
    assert original.messages[0].content == "c"


class StubTarget:
    async def send(self, history: ChatHistory) -> TargetResponse:
        last_user = next(
            (m.content for m in reversed(history.messages) if m.role is Role.USER),
            "",
        )
        reply = f"echo: {last_user}"
        return TargetResponse(
            reply=reply,
            raw_request_json=history.to_messages_json(),
            raw_response_text=reply,
            metrics=Metrics(),
            captures={},
            error=None,
        )


@pytest.mark.asyncio
async def test_stub_target_protocol_conformance() -> None:
    stub = StubTarget()
    assert isinstance(stub, Target)


@pytest.mark.asyncio
async def test_stub_target_grows_history_across_turns() -> None:
    target = StubTarget()
    history = ChatHistory()
    history.append_user("first")
    response = await target.send(history)
    assert response.reply == "echo: first"
    history.append_assistant(response.reply)
    history.append_user("second")
    response2 = await target.send(history)
    assert response2.reply == "echo: second"
    assert [(m.role, m.content) for m in history.messages] == [
        (Role.USER, "first"),
        (Role.ASSISTANT, "echo: first"),
        (Role.USER, "second"),
    ]
