from __future__ import annotations

from importlib.resources import files

from llmbuster.domain.models import Payload, PayloadPack
from llmbuster.payload.loader import load_and_validate, load_pack

BUNDLED_PACKS_DIR = "llmbuster.resources.packs"


def list_bundled_packs() -> list[str]:
    root = files(BUNDLED_PACKS_DIR)
    names = [
        entry.name
        for entry in root.iterdir()
        if entry.is_file() and entry.name.endswith((".yaml", ".yml"))
    ]
    return sorted(names)


def load_bundled_packs() -> list[Payload]:
    directory = str(files(BUNDLED_PACKS_DIR))
    return load_and_validate(directory)


def load_bundled_packs_as_packs() -> list[PayloadPack]:
    root = files(BUNDLED_PACKS_DIR)
    packs: list[PayloadPack] = []
    for name in list_bundled_packs():
        packs.append(load_pack(str(root / name)))
    return packs
