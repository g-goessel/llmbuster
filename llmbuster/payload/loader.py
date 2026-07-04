from __future__ import annotations

from os import PathLike
from pathlib import Path

import yaml
from pydantic import ValidationError

from llmbuster.domain.models import Payload, PayloadPack

KNOWN_MUTATIONS: frozenset[str] = frozenset(
    {"base64", "leetspeak", "unicode_homoglyph", "translation"}
)


class PackLoadError(ValueError):
    pass


def load_pack(path: str | PathLike[str]) -> PayloadPack:
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise PackLoadError(f"{p}: cannot read file: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PackLoadError(f"{p}: invalid yaml: {exc}") from exc
    if not isinstance(data, dict):
        raise PackLoadError(f"{p}: expected a yaml mapping at top level, got {type(data).__name__}")
    if "category" not in data:
        raise PackLoadError(f"{p}: missing required key 'category'")
    if "payloads" not in data:
        raise PackLoadError(f"{p}: missing required key 'payloads'")
    try:
        return PayloadPack.model_validate(data)
    except ValidationError as exc:
        raise PackLoadError(f"{p}: validation failed: {exc}") from exc


def load_packs(directory: str | PathLike[str]) -> list[Payload]:
    d = Path(directory)
    if not d.exists():
        raise PackLoadError(f"{d}: directory does not exist")
    if not d.is_dir():
        raise PackLoadError(f"{d}: not a directory")
    files = sorted(d.glob("*.y*ml"))
    if not files:
        raise PackLoadError(f"{d}: no yaml pack files found")
    payloads: list[Payload] = []
    for f in files:
        pack = load_pack(f)
        payloads.extend(pack.payloads)
    return payloads


def load_packs_from_paths(paths: list[str | PathLike[str]]) -> list[Payload]:
    if not paths:
        raise PackLoadError("no pack paths provided")
    payloads: list[Payload] = []
    for raw in paths:
        pack = load_pack(raw)
        payloads.extend(pack.payloads)
    return payloads


def validate_payloads(payloads: list[Payload]) -> list[Payload]:
    seen: dict[str, int] = {}
    duplicates: set[str] = set()
    for p in payloads:
        if p.id in seen:
            duplicates.add(p.id)
        else:
            seen[p.id] = 1
    if duplicates:
        raise PackLoadError(
            f"duplicate payload ids: {sorted(duplicates)}"
        )

    known_ids = set(seen.keys())
    dangling: list[str] = []
    for p in payloads:
        if p.escalation_to is not None and p.escalation_to not in known_ids:
            dangling.append(f"{p.id} -> {p.escalation_to}")
    if dangling:
        raise PackLoadError(
            f"escalation_to references unknown payload ids: {dangling}"
        )

    unknown: list[str] = []
    for p in payloads:
        for m in p.mutations:
            if m not in KNOWN_MUTATIONS:
                unknown.append(f"{p.id}:{m}")
    if unknown:
        raise PackLoadError(
            f"unknown mutation names (allowed: {sorted(KNOWN_MUTATIONS)}): {unknown}"
        )

    return payloads


def load_and_validate(directory: str | PathLike[str]) -> list[Payload]:
    return validate_payloads(load_packs(directory))
