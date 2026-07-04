from __future__ import annotations

from pathlib import Path

import pytest

from llmbuster.target.command import CommandTarget
from llmbuster.target.factory import (
    BUNDLED_PROFILES,
    TargetKind,
    TargetLoadError,
    bundled_profile_text,
    init_profile,
    load_target,
    load_target_from_dict,
)
from llmbuster.target.plugin import PluginTarget
from llmbuster.target.profile import ProfileTarget

FIXTURES = Path(__file__).parent / "fixtures"
ECHO_ADAPTER = str(FIXTURES / "echo_adapter.py")
MY_TARGET = str(FIXTURES / "my_target.py")


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


_PROFILE_YAML = (
    "kind: profile\n"
    'name: "Test profile"\n'
    "request:\n"
    "  method: POST\n"
    '  url: "https://chatbot.internal.example.com/api/chat"\n'
    "  headers:\n"
    '    Content-Type: "application/json"\n'
    '    Authorization: "Bearer ${env:TARGET_TOKEN}"\n'
    "  body: |\n"
    '    {"messages": ${messages_json}, "user_message": "${last_user_message}"}\n'
    "response:\n"
    "  type: json\n"
    '  reply_path: "$.data.reply"\n'
    "session:\n"
    "  mode: stateless\n"
)


def test_load_target_profile(tmp_path: Path) -> None:
    p = _write(tmp_path, "profile.yaml", _PROFILE_YAML)
    loaded = load_target(p)
    assert loaded.kind is TargetKind.PROFILE
    assert isinstance(loaded.target, ProfileTarget)
    assert loaded.name == "Test profile"
    assert loaded.config is loaded.target.config


def test_load_target_command(tmp_path: Path) -> None:
    text = (
        "kind: command\n"
        'name: "echo command"\n'
        f'command: ["python3", "{ECHO_ADAPTER}"]\n'
    )
    p = _write(tmp_path, "command.yaml", text)
    loaded = load_target(p)
    assert loaded.kind is TargetKind.COMMAND
    assert isinstance(loaded.target, CommandTarget)
    assert loaded.name == "echo command"


def test_load_target_plugin(tmp_path: Path) -> None:
    text = (
        "kind: plugin\n"
        'name: "my plugin"\n'
        f'module: "{MY_TARGET}"\n'
        'class: "MyTarget"\n'
    )
    p = _write(tmp_path, "plugin.yaml", text)
    loaded = load_target(p)
    assert loaded.kind is TargetKind.PLUGIN
    assert isinstance(loaded.target, PluginTarget)
    assert loaded.name == "my plugin"


def test_load_target_openrouter(tmp_path: Path) -> None:
    p = _write(tmp_path, "openrouter.yaml", "kind: openrouter\nmodel: openai/gpt-4o\n")
    loaded = load_target(p)
    assert loaded.kind is TargetKind.OPENROUTER
    assert isinstance(loaded.target, ProfileTarget)
    assert loaded.name == "OpenRouter"
    assert "openai/gpt-4o" in loaded.target.config.request.body


def test_load_target_unknown_kind(tmp_path: Path) -> None:
    p = _write(tmp_path, "unknown.yaml", "kind: unknown\nname: x\n")
    with pytest.raises(TargetLoadError) as excinfo:
        load_target(p)
    assert "unknown" in str(excinfo.value)


def test_load_target_missing_file(tmp_path: Path) -> None:
    with pytest.raises(TargetLoadError) as excinfo:
        load_target(tmp_path / "nonexistent.yaml")
    assert "not found" in str(excinfo.value)


def test_load_target_malformed_yaml(tmp_path: Path) -> None:
    p = _write(tmp_path, "bad.yaml", "a: b: c\n")
    with pytest.raises(TargetLoadError) as excinfo:
        load_target(p)
    assert "malformed" in str(excinfo.value).lower()


def test_load_target_not_mapping(tmp_path: Path) -> None:
    p = _write(tmp_path, "list.yaml", "- just\n- a\n- list\n")
    with pytest.raises(TargetLoadError):
        load_target(p)


def test_load_target_openrouter_missing_model(tmp_path: Path) -> None:
    p = _write(tmp_path, "or.yaml", "kind: openrouter\n")
    with pytest.raises(TargetLoadError) as excinfo:
        load_target(p)
    assert "model" in str(excinfo.value)


def test_init_profile_round_trip(tmp_path: Path) -> None:
    out = tmp_path / "out.yaml"
    init_profile(out)
    loaded = load_target(out)
    assert loaded.kind is TargetKind.PROFILE
    assert isinstance(loaded.target, ProfileTarget)
    assert loaded.target.config.response.type.value == "json"
    assert loaded.target.config.session.mode.value == "server_managed"


def test_init_profile_refuses_overwrite(tmp_path: Path) -> None:
    out = tmp_path / "out.yaml"
    init_profile(out)
    with pytest.raises(TargetLoadError):
        init_profile(out)


def test_init_profile_force_overwrites(tmp_path: Path) -> None:
    out = tmp_path / "out.yaml"
    init_profile(out)
    original = out.read_text(encoding="utf-8")
    init_profile(out, force=True)
    assert out.read_text(encoding="utf-8") == original
    assert out.exists()


def test_init_profile_unsupported_kind(tmp_path: Path) -> None:
    out = tmp_path / "out.yaml"
    with pytest.raises(TargetLoadError):
        init_profile(out, kind="command")


def test_load_target_from_dict_command() -> None:
    loaded = load_target_from_dict(
        {
            "kind": "command",
            "name": "from-dict",
            "command": ["python3", ECHO_ADAPTER],
        }
    )
    assert loaded.kind is TargetKind.COMMAND
    assert isinstance(loaded.target, CommandTarget)
    assert loaded.name == "from-dict"


def test_load_target_from_dict_profile() -> None:
    import yaml

    data = yaml.safe_load(_PROFILE_YAML)
    assert isinstance(data, dict)
    loaded = load_target_from_dict(data)
    assert loaded.kind is TargetKind.PROFILE
    assert isinstance(loaded.target, ProfileTarget)


def test_load_target_from_dict_unknown_kind() -> None:
    with pytest.raises(TargetLoadError):
        load_target_from_dict({"kind": "mystery", "name": "x"})


def test_load_target_from_dict_missing_kind() -> None:
    with pytest.raises(TargetLoadError):
        load_target_from_dict({"name": "x"})


def test_bundled_profile_text_openrouter() -> None:
    text = bundled_profile_text("openrouter")
    assert text
    assert "kind:" in text
    assert "openrouter" in text


def test_bundled_profile_text_unknown_raises() -> None:
    with pytest.raises(TargetLoadError):
        bundled_profile_text("does-not-exist")


def test_bundled_profiles_contains_openrouter() -> None:
    assert "openrouter" in BUNDLED_PROFILES
