from __future__ import annotations

import importlib.util
import inspect
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from llmbuster.domain.models import ChatHistory, TargetResponse
from llmbuster.domain.protocols import Target


class PluginConfig(BaseModel):
    kind: Literal["plugin"] = "plugin"
    name: str
    module: str
    class_name: str = Field(alias="class")

    model_config = {"populate_by_name": True}


class PluginTarget:
    def __init__(self, config: PluginConfig, instance: Target) -> None:
        self._config = config
        self._instance = instance

    @property
    def config(self) -> PluginConfig:
        return self._config

    @property
    def instance(self) -> Target:
        return self._instance

    async def send(self, history: ChatHistory) -> TargetResponse:
        return await self._instance.send(history)


class PluginLoadError(TypeError):
    pass


def _load_module(module_path: str) -> object:
    path = Path(module_path)
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.is_file():
        raise PluginLoadError(f"plugin module not found: {path}")
    spec = importlib.util.spec_from_file_location(
        f"llmbuster_plugin_{path.stem}_{abs(hash(str(path)))}", path
    )
    if spec is None or spec.loader is None:
        raise PluginLoadError(f"cannot load module from: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _get_class(module: object, class_name: str) -> type:
    attr = getattr(module, class_name, None)
    if attr is None:
        raise PluginLoadError(f"class '{class_name}' not found in module")
    if not isinstance(attr, type):
        raise PluginLoadError(f"'{class_name}' is not a class")
    return attr


def _verify_target_protocol(cls: type) -> None:
    send = getattr(cls, "send", None)
    if send is None:
        raise PluginLoadError(
            f"class '{cls.__name__}' does not implement 'send' (Target protocol)"
        )
    if not inspect.iscoroutinefunction(send):
        raise PluginLoadError(
            f"'{cls.__name__}.send' must be async (Target protocol)"
        )


def load_plugin(config: PluginConfig) -> PluginTarget:
    module = _load_module(config.module)
    cls = _get_class(module, config.class_name)
    _verify_target_protocol(cls)
    try:
        instance = cls()
    except Exception as exc:
        raise PluginLoadError(
            f"failed to instantiate '{config.class_name}': {exc!s}"
        ) from exc
    if not isinstance(instance, Target):
        raise PluginLoadError(
            f"'{config.class_name}' instance does not satisfy Target protocol "
            "(runtime check failed)"
        )
    return PluginTarget(config, instance)


def load_plugin_from_dict(data: dict[str, object]) -> PluginTarget:
    return load_plugin(PluginConfig.model_validate(data))


def load_plugin_from_file(path: str | os.PathLike[str]) -> PluginTarget:
    import yaml

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise PluginLoadError(f"plugin profile must be a mapping: {path}")
    return load_plugin_from_dict(data)
