from __future__ import annotations

import base64
import re

KNOWN_MUTATIONS: frozenset[str] = frozenset(
    {"base64", "leetspeak", "unicode_homoglyph", "translation"}
)

AVAILABLE_MUTATIONS: frozenset[str] = frozenset(
    {"base64", "leetspeak", "unicode_homoglyph", "translation"}
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

_EN_TO_FR: dict[str, str] = {
    "ignore": "ignorer",
    "instructions": "instructions",
    "system": "système",
    "prompt": "invite",
    "reveal": "révéler",
    "secret": "secret",
    "repeat": "répéter",
    "everything": "tout",
    "above": "ci-dessus",
    "including": "y compris",
    "reply": "répondre",
    "word": "mot",
    "delete": "supprimer",
    "grant": "accorder",
    "admin": "administrateur",
    "transfer": "transférer",
    "show": "montrer",
    "print": "imprimer",
    "what": "quel",
    "your": "votre",
    "are": "êtes",
    "the": "le",
    "and": "et",
    "with": "avec",
    "this": "ce",
    "that": "ce",
    "now": "maintenant",
    "all": "tous",
    "user": "utilisateur",
    "accounts": "comptes",
    "key": "clé",
    "model": "modèle",
    "data": "données",
    "previous": "précédentes",
    "rules": "règles",
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


def _match_case(source: str, target: str) -> str:
    if source[:1].isupper():
        return target[:1].upper() + target[1:]
    return target


def mutate_translation(text: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        word = match.group(0)
        lower = word.lower()
        if lower in _EN_TO_FR:
            return _match_case(word, _EN_TO_FR[lower])
        return word

    return re.sub(r"\w+", _replace, text)


def mutate(text: str, name: str) -> str:
    if name == "base64":
        return mutate_base64(text)
    if name == "leetspeak":
        return mutate_leetspeak(text)
    if name == "unicode_homoglyph":
        return mutate_unicode_homoglyph(text)
    if name == "translation":
        return mutate_translation(text)
    raise MutationError(f"unknown mutation: {name}")
