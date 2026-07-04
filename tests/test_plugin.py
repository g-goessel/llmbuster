from __future__ import annotations

from pathlib import Path

import pytest

from llmbuster.domain import ChatHistory, Message, Role, Target, TargetResponse
from llmbuster.target.plugin import (
    PluginConfig,
    PluginLoadError,
    PluginTarget,
    load_plugin,
    load_plugin_from_dict,
    load_plugin_from_file,
)

FIXTURES = Path(__file__).parent / "fixtures"
MY_TARGET = str(FIXTURES / "my_target.py")
BAD_TARGET = str(FIXTURES / "bad_target.py")


def _config(module: str = MY_TARGET, class_name: str = "MyTarget") -> PluginConfig:
    return PluginConfig(
        kind="plugin",
        name="test-plugin",
        module=module,
        class_name=class_name,
    )


def _history(text: str = "hello plugin") -> ChatHistory:
    return ChatHistory(messages=[Message(role=Role.USER, content=text)])


async def test_conforming_adapter_round_trips() -> None:
    plugin = load_plugin(_config())
    history = _history("ping")
    response = await plugin.send(history)
    assert isinstance(response, TargetResponse)
    assert response.reply == "plugin-echo: ping"
    assert response.raw_response_text == "plugin-echo: ping"
    assert response.raw_request_json == history.to_messages_json()
    assert response.error is None
    assert response.captures == {}


def test_plugin_target_satisfies_protocol() -> None:
    plugin = load_plugin(_config())
    assert isinstance(plugin, Target)
    assert isinstance(plugin.instance, Target)
    assert isinstance(plugin, PluginTarget)


def test_non_conforming_class_raises() -> None:
    with pytest.raises(PluginLoadError) as excinfo:
        load_plugin(_config(module=BAD_TARGET, class_name="NonConformingTarget"))
    assert "Target" in str(excinfo.value) or "send" in str(excinfo.value)


def test_missing_module_file_raises() -> None:
    with pytest.raises(PluginLoadError) as excinfo:
        load_plugin(_config(module=str(FIXTURES / "does_not_exist.py")))
    assert "not found" in str(excinfo.value)


def test_missing_class_raises() -> None:
    with pytest.raises(PluginLoadError) as excinfo:
        load_plugin(_config(class_name="NoSuchClass"))
    assert "NoSuchClass" in str(excinfo.value)


def test_plugin_config_parses_class_alias() -> None:
    config = PluginConfig.model_validate(
        {
            "kind": "plugin",
            "name": "x",
            "module": "./p.py",
            "class": "MyTarget",
        }
    )
    assert config.class_name == "MyTarget"
    assert config.kind == "plugin"
    assert config.name == "x"
    assert config.module == "./p.py"


def test_plugin_config_round_trip() -> None:
    original = _config()
    dumped = original.model_dump(by_alias=True)
    restored = PluginConfig.model_validate(dumped)
    assert restored == original
    assert restored.model_dump_json(by_alias=True) == original.model_dump_json(
        by_alias=True
    )


async def test_load_plugin_from_dict() -> None:
    plugin = load_plugin_from_dict(
        {
            "kind": "plugin",
            "name": "from-dict",
            "module": MY_TARGET,
            "class": "MyTarget",
        }
    )
    assert isinstance(plugin, PluginTarget)
    response = await plugin.send(_history("from dict"))
    assert response.reply == "plugin-echo: from dict"


async def test_load_plugin_from_file(tmp_path: Path) -> None:
    profile = tmp_path / "plugin.yaml"
    profile.write_text(
        "kind: plugin\n"
        "name: from-file\n"
        f'module: "{MY_TARGET}"\n'
        'class: "MyTarget"\n',
        encoding="utf-8",
    )
    plugin = load_plugin_from_file(profile)
    assert isinstance(plugin, Target)
    response = await plugin.send(_history("from file"))
    assert response.reply == "plugin-echo: from file"


def test_load_plugin_from_file_not_mapping(tmp_path: Path) -> None:
    profile = tmp_path / "bad.yaml"
    profile.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(PluginLoadError):
        load_plugin_from_file(profile)


def test_instantiation_error_raises(tmp_path: Path) -> None:
    bad_init = tmp_path / "bad_init_target.py"
    bad_init.write_text(
        "class BoomTarget:\n"
        "    def __init__(self) -> None:\n"
        "        raise RuntimeError('boom')\n"
        "    async def send(self, history):\n"
        "        ...\n",
        encoding="utf-8",
    )
    with pytest.raises(PluginLoadError) as excinfo:
        load_plugin(_config(module=str(bad_init), class_name="BoomTarget"))
    assert "BoomTarget" in str(excinfo.value)
