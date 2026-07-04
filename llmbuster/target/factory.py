from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import ValidationError

from llmbuster.domain.protocols import Target
from llmbuster.target.command import load_command_from_dict
from llmbuster.target.openrouter import build_target
from llmbuster.target.plugin import PluginLoadError, load_plugin_from_dict
from llmbuster.target.profile import ProfileTarget

_RESOURCE_PACKAGE = "llmbuster.resources"


class TargetKind(StrEnum):
    PROFILE = "profile"
    PLUGIN = "plugin"
    COMMAND = "command"
    OPENROUTER = "openrouter"


class TargetLoadError(ValueError):
    pass


@dataclass
class LoadedTarget:
    target: Target
    kind: TargetKind
    name: str
    config: object | None = None


BUNDLED_PROFILES: list[str] = ["openrouter"]


def bundled_profile_text(name: str) -> str:
    if name not in BUNDLED_PROFILES:
        raise TargetLoadError(f"unknown bundled profile: {name}")
    return (files(_RESOURCE_PACKAGE) / f"{name}.yaml").read_text(encoding="utf-8")


def load_target_from_dict(data: dict[str, object]) -> LoadedTarget:
    if not isinstance(data, dict):
        raise TargetLoadError("target profile must be a mapping")
    kind_raw = data.get("kind")
    if not isinstance(kind_raw, str):
        raise TargetLoadError(f"missing or invalid 'kind' field: {kind_raw!r}")
    try:
        kind = TargetKind(kind_raw)
    except ValueError:
        raise TargetLoadError(f"unknown target kind: {kind_raw}") from None

    if kind is TargetKind.PROFILE:
        try:
            profile_target = ProfileTarget.from_dict(data)
        except ValidationError as exc:
            raise TargetLoadError(f"invalid profile config: {exc}") from exc
        return LoadedTarget(
            target=profile_target,
            kind=kind,
            name=profile_target.config.name,
            config=profile_target.config,
        )

    if kind is TargetKind.PLUGIN:
        try:
            plugin_target = load_plugin_from_dict(data)
        except PluginLoadError as exc:
            raise TargetLoadError(f"plugin load failed: {exc}") from exc
        except ValidationError as exc:
            raise TargetLoadError(f"invalid plugin config: {exc}") from exc
        return LoadedTarget(
            target=plugin_target,
            kind=kind,
            name=plugin_target.config.name,
            config=plugin_target.config,
        )

    if kind is TargetKind.COMMAND:
        try:
            command_target = load_command_from_dict(data)
        except ValidationError as exc:
            raise TargetLoadError(f"invalid command config: {exc}") from exc
        return LoadedTarget(
            target=command_target,
            kind=kind,
            name=command_target.config.name,
            config=command_target.config,
        )

    if kind is TargetKind.OPENROUTER:
        model = data.get("model")
        if not isinstance(model, str) or not model:
            raise TargetLoadError(
                "openrouter kind requires a non-empty 'model' field (model id)"
            )
        try:
            openrouter_target = build_target(model)
        except ValidationError as exc:
            raise TargetLoadError(f"invalid openrouter config: {exc}") from exc
        return LoadedTarget(
            target=openrouter_target,
            kind=kind,
            name="OpenRouter",
            config=openrouter_target.config,
        )

    raise TargetLoadError(f"unknown target kind: {kind_raw}")


def load_target(path: str | os.PathLike[str]) -> LoadedTarget:
    p = Path(path)
    if not p.is_file():
        raise TargetLoadError(f"target file not found: {p}")
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise TargetLoadError(f"cannot read target file {p}: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise TargetLoadError(f"malformed YAML in {p}: {exc}") from exc
    return load_target_from_dict(data)


_EXAMPLE_PROFILE_YAML = """\
# llmbuster target profile (kind: profile) — declarative HTTP target.
# See PLAN.md §5.1 for the authoritative schema. Edit the values below to match
# your own LLM endpoint, then run:  llmbuster targets test <this-file>

# Discriminator: tells the factory which target kind to build.
kind: profile

# Human-readable name. Stored in runs.target_name and shown in the TUI / CLI.
name: "Example target"

# Outgoing HTTP request definition.
request:
  # HTTP method (typically POST for chat endpoints).
  method: POST
  # Target URL. Placeholders such as ${env:VAR} are resolved at send time.
  url: "https://chatbot.internal.example.com/api/chat"
  # HTTP headers. ${env:TARGET_TOKEN} reads the TARGET_TOKEN environment variable.
  # Secrets must enter ONLY via env vars — never hardcode them in this file.
  headers:
    Content-Type: "application/json"
    Authorization: "Bearer ${env:TARGET_TOKEN}"
  # Request body template. Placeholders are filled at send time:
  #   ${messages_json}      — full ChatHistory as a JSON array
  #   ${last_user_message}  — most recent user message text
  #   ${session_id}         — a captured variable (see response.capture below)
  #   ${uuid} / ${timestamp} — generated per request
  body: |
    {
      "session_id": "${session_id}",
      "messages": ${messages_json},
      "user_message": "${last_user_message}"
    }

# How to parse the response and extract the assistant reply.
response:
  # Response transport:
  #   json — parse body and extract reply_path via JSONPath
  #   sse  — parse data: events, accumulate token deltas (yields TTFT/TPS)
  #   text — use the raw body as the reply
  type: json
  # JSONPath into the parsed JSON body that yields the assistant reply string.
  reply_path: "$.data.reply"
  # Optional values to capture from the response and carry into the next request.
  # Required for server_managed sessions (see session.mode below).
  capture:
    session_id: "$.data.session_id"

# Session handling strategy.
session:
  # client_history — resend the full message array each turn (${messages_json})
  # server_managed — server holds state; resend a captured session_id
  # stateless      — each payload is a fresh single-turn request
  mode: server_managed
"""


def init_profile(
    path: str | os.PathLike[str],
    kind: str = "profile",
    force: bool = False,
) -> None:
    if kind != "profile":
        raise TargetLoadError(
            f"unsupported init kind: {kind!r} (only 'profile' is supported)"
        )
    p = Path(path)
    if p.exists() and not force:
        raise TargetLoadError(f"file exists: {p}")
    p.write_text(_EXAMPLE_PROFILE_YAML, encoding="utf-8")
