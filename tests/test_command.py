from __future__ import annotations

from pathlib import Path

import pytest

from llmbuster.domain import (
    ChatHistory,
    Message,
    Role,
    Target,
    TargetResponse,
)
from llmbuster.target.command import (
    CommandConfig,
    CommandTarget,
    load_command_from_dict,
    load_command_from_file,
)

FIXTURES = Path(__file__).parent / "fixtures"
ECHO_ADAPTER = str(FIXTURES / "echo_adapter.py")
BAD_ADAPTER = str(FIXTURES / "bad_adapter.py")
BAD_JSON_ADAPTER = str(FIXTURES / "bad_json_adapter.py")


def _config(command: list[str], name: str = "test-command") -> CommandConfig:
    return CommandConfig(kind="command", name=name, command=command)


def _history(*messages: tuple[Role, str]) -> ChatHistory:
    return ChatHistory(
        messages=[Message(role=role, content=content) for role, content in messages]
    )


async def test_round_trip_echo() -> None:
    target = CommandTarget(_config(["python3", ECHO_ADAPTER]))
    response = await target.send(_history((Role.USER, "hello")))
    assert isinstance(response, TargetResponse)
    assert response.reply == "echo: hello"
    assert response.error is None
    assert "messages" in response.raw_request_json
    assert "hello" in response.raw_request_json
    assert response.raw_response_text is not None
    assert "hello" in response.raw_response_text


async def test_last_user_message_extracted() -> None:
    target = CommandTarget(_config(["python3", ECHO_ADAPTER]))
    history = _history(
        (Role.SYSTEM, "you are helpful"),
        (Role.USER, "first question"),
        (Role.ASSISTANT, "first answer"),
        (Role.USER, "second question"),
    )
    response = await target.send(history)
    assert response.reply == "echo: second question"
    assert response.error is None


async def test_empty_history_graceful() -> None:
    target = CommandTarget(_config(["python3", ECHO_ADAPTER]))
    response = await target.send(_history((Role.SYSTEM, "only system message")))
    assert response.reply == "echo: "
    assert response.error is None


async def test_non_zero_exit_surfaces_error() -> None:
    target = CommandTarget(_config(["python3", BAD_ADAPTER]))
    response = await target.send(_history((Role.USER, "ping")))
    assert response.reply is None
    assert response.error is not None
    assert "process failed" in response.error
    assert "returncode=1" in response.error


async def test_bad_json_surfaces_error() -> None:
    target = CommandTarget(_config(["python3", BAD_JSON_ADAPTER]))
    response = await target.send(_history((Role.USER, "ping")))
    assert response.reply is None
    assert response.error is not None
    assert "invalid JSON" in response.error
    assert response.raw_response_text is not None
    assert "not valid json" in response.raw_response_text


async def test_timeout_surfaces_error() -> None:
    target = CommandTarget(
        _config(["python3", "-c", "import time; time.sleep(5)"]), timeout=0.1
    )
    response = await target.send(_history((Role.USER, "ping")))
    assert response.reply is None
    assert response.error is not None
    assert "timeout" in response.error


def test_command_config_parses_spec_yaml() -> None:
    config = CommandConfig.model_validate(
        {
            "kind": "command",
            "name": "Custom client",
            "command": ["python3", "./adapters/grpc_adapter.py"],
        }
    )
    assert config.kind == "command"
    assert config.name == "Custom client"
    assert config.command == ["python3", "./adapters/grpc_adapter.py"]


def test_command_target_satisfies_protocol() -> None:
    target = CommandTarget(_config(["python3", ECHO_ADAPTER]))
    assert isinstance(target, Target)


def test_command_config_round_trip() -> None:
    original = _config(["python3", "./a.py"], name="rt")
    dumped = original.model_dump()
    restored = CommandConfig.model_validate(dumped)
    assert restored == original
    assert restored.model_dump_json() == original.model_dump_json()


async def test_load_command_from_dict() -> None:
    target = load_command_from_dict(
        {
            "kind": "command",
            "name": "from-dict",
            "command": ["python3", ECHO_ADAPTER],
        }
    )
    assert isinstance(target, CommandTarget)
    assert isinstance(target, Target)
    response = await target.send(_history((Role.USER, "from dict")))
    assert response.reply == "echo: from dict"


async def test_load_command_from_file(tmp_path: Path) -> None:
    profile = tmp_path / "command.yaml"
    profile.write_text(
        "kind: command\n"
        "name: from-file\n"
        f'command: ["python3", "{ECHO_ADAPTER}"]\n',
        encoding="utf-8",
    )
    target = load_command_from_file(profile)
    assert isinstance(target, Target)
    response = await target.send(_history((Role.USER, "from file")))
    assert response.reply == "echo: from file"


def test_load_command_from_file_not_mapping(tmp_path: Path) -> None:
    profile = tmp_path / "bad.yaml"
    profile.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_command_from_file(profile)
