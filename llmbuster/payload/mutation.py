from __future__ import annotations

import base64

KNOWN_MUTATIONS: frozenset[str] = frozenset(
    {"base64", "leetspeak", "unicode_homoglyph", "translation"}
)

AVAILABLE_MUTATIONS: frozenset[str] = frozenset(
    {"base64", "leetspeak", "unicode_homoglyph"}
)

_LEET_MAP: dict[str, str] = {
    "a": "4",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "5",
    "t": "7",
    "l": "1",
}

_HOMOGLYPH_MAP: dict[str, str] = {
    "a": "\u0430",
    "e": "\u0435",
    "o": "\u043e",
    "p": "\u0440",
    "c": "\u0441",
    "x": "\u0445",
    "y": "\u0443",
    "A": "\u0410",
    "E": "\u0415",
    "O": "\u041e",
    "P": "\u0420",
    "C": "\u0421",
    "X": "\u0425",
    "Y": "\u0423",
}


class MutationError(ValueError):
    pass


def mutate_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def mutate_leetspeak(text: str) -> str:
    out: list[str] = []
    for ch in text:
        sub = _LEET_MAP.get(ch.lower())
        out.append(sub if sub is not None else ch)
    return "".join(out)


def mutate_unicode_homoglyph(text: str) -> str:
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def mutate(text: str, name: str) -> str:
    if name == "base64":
        return mutate_base64(text)
    if name == "leetspeak":
        return mutate_leetspeak(text)
    if name == "unicode_homoglyph":
        return mutate_unicode_homoglyph(text)
    if name == "translation":
        raise NotImplementedError("translation mutation is not implemented in v1")
    raise MutationError(f"unknown mutation: {name}")
