from __future__ import annotations

import asyncio
import json

from llmbuster.domain import (
    ChatHistory,
    Message,
    Metrics,
    Role,
    Target,
    TargetResponse,
)


def test_append_grows_in_order_across_turns() -> None:
    history = ChatHistory()
    history.append(Message(role=Role.SYSTEM, content="sys"))
    history.append(Message(role=Role.USER, content="u1"))
    history.append(Message(role=Role.ASSISTANT, content="a1"))
    history.append(Message(role=Role.USER, content="u2"))
    history.append(Message(role=Role.ASSISTANT, content="a2"))
    assert [(m.role, m.content) for m in history.messages] == [
        (Role.SYSTEM, "sys"),
        (Role.USER, "u1"),
        (Role.ASSISTANT, "a1"),
        (Role.USER, "u2"),
        (Role.ASSISTANT, "a2"),
    ]


def test_append_user_and_append_assistant() -> None:
    history = ChatHistory()
    history.append_user("hi")
    history.append_assistant("hello")
    history.append_user("again")
    assert [(m.role, m.content) for m in history.messages] == [
        (Role.USER, "hi"),
        (Role.ASSISTANT, "hello"),
        (Role.USER, "again"),
    ]


def test_clone_is_deep_copy() -> None:
    original = ChatHistory()
    original.append_user("base")
    clone = original.clone()
    clone.append_user("clone-only")
    assert [m.content for m in original.messages] == ["base"]
    assert [m.content for m in clone.messages] == ["base", "clone-only"]

    original.append_assistant("original-only")
    assert [m.content for m in original.messages] == ["base", "original-only"]
    assert [m.content for m in clone.messages] == ["base", "clone-only"]


def test_clone_messages_are_distinct_objects() -> None:
    original = ChatHistory()
    original.append_user("base")
    clone = original.clone()
    assert clone.messages[0] == original.messages[0]
    assert clone.messages[0] is not original.messages[0]
    clone.messages[0].content = "mutated"
    assert original.messages[0].content == "base"


def test_to_messages_json_exact_output() -> None:
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


def test_to_messages_json_empty_history() -> None:
    assert ChatHistory().to_messages_json() == "[]"


def test_to_messages_json_round_trip() -> None:
    history = ChatHistory(
        messages=[
            Message(role=Role.SYSTEM, content="sys"),
            Message(role=Role.USER, content="hi"),
            Message(role=Role.ASSISTANT, content="hello"),
        ]
    )
    serialized = history.to_messages_json()
    parsed = json.loads(serialized)
    rebuilt = ChatHistory(messages=[Message(**m) for m in parsed])
    assert rebuilt == history


def test_clone_preserves_content_and_roles() -> None:
    history = ChatHistory(
        messages=[
            Message(role=Role.SYSTEM, content="sys"),
            Message(role=Role.ASSISTANT, content="a"),
        ]
    )
    clone = history.clone()
    assert clone == history
    assert [(m.role, m.content) for m in clone.messages] == [
        (Role.SYSTEM, "sys"),
        (Role.ASSISTANT, "a"),
    ]


class EchoTarget:
    async def send(self, history: ChatHistory) -> TargetResponse:
        last_user = next(
            (m.content for m in reversed(history.messages) if m.role is Role.USER),
            "",
        )
        reply = f"echo: {last_user}"
        history.append_assistant(reply)
        return TargetResponse(
            reply=reply,
            raw_request_json=json.dumps({"last_user": last_user}),
            raw_response_text=reply,
            metrics=Metrics(duration_ms=10),
        )


async def test_stub_target_implements_protocol_and_grows_history() -> None:
    stub: Target = EchoTarget()
    assert isinstance(stub, Target)

    history = ChatHistory()
    history.append_user("first")
    resp1 = await stub.send(history)
    assert resp1.reply == "echo: first"
    assert [m.content for m in history.messages] == ["first", "echo: first"]

    history.append_user("second")
    resp2 = await stub.send(history)
    assert resp2.reply == "echo: second"
    assert [m.content for m in history.messages] == [
        "first",
        "echo: first",
        "second",
        "echo: second",
    ]

    history.append_user("third")
    resp3 = await stub.send(history)
    assert resp3.reply == "echo: third"
    assert len(history.messages) == 6


async def test_stub_target_clone_does_not_mutate_original() -> None:
    stub: Target = EchoTarget()
    base = ChatHistory()
    base.append_user("seed")
    snapshot = base.clone()
    await stub.send(base)
    assert snapshot.messages == [Message(role=Role.USER, content="seed")]
    assert len(base.messages) == 2


if __name__ == "__main__":
    asyncio.run(test_stub_target_implements_protocol_and_grows_history())
