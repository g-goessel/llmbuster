from __future__ import annotations

import re

from llmbuster.detector.registry import default_registry
from llmbuster.domain.models import OwaspCategory
from llmbuster.payload.bundled import (
    BUNDLED_PACKS_DIR,
    list_bundled_packs,
    load_bundled_packs,
    load_bundled_packs_as_packs,
)

ALL_CATEGORIES = [OwaspCategory(f"LLM{i:02d}") for i in range(1, 11)]


def test_bundled_packs_dir_constant() -> None:
    assert BUNDLED_PACKS_DIR == "llmbuster.resources.packs"


def test_list_bundled_packs_returns_ten_yaml_files() -> None:
    names = list_bundled_packs()
    assert len(names) == 10
    for name in names:
        assert re.fullmatch(r"llm\d{2}_.*\.yaml", name), name


def test_load_bundled_packs_returns_30_or_more_payloads() -> None:
    payloads = load_bundled_packs()
    assert len(payloads) >= 30


def test_every_category_covered() -> None:
    packs = load_bundled_packs_as_packs()
    categories = {pack.category for pack in packs}
    for cat in ALL_CATEGORIES:
        assert cat in categories, f"missing category {cat}"


def test_every_pack_has_at_least_three_payloads() -> None:
    packs = load_bundled_packs_as_packs()
    assert len(packs) == 10
    for pack in packs:
        assert len(pack.payloads) >= 3, f"{pack.category} has fewer than 3 payloads"


def test_every_payload_detector_builds_via_registry() -> None:
    payloads = load_bundled_packs()
    for payload in payloads:
        detectors = default_registry.build_from_payload(payload)
        assert len(detectors) == len(payload.detectors)


def test_escalation_targets_exist_within_pack() -> None:
    packs = load_bundled_packs_as_packs()
    for pack in packs:
        ids = {p.id for p in pack.payloads}
        for p in pack.payloads:
            if p.escalation_to is not None:
                assert p.escalation_to in ids, f"{p.id} -> {p.escalation_to} not in pack"


def test_payload_ids_unique_across_all_packs() -> None:
    payloads = load_bundled_packs()
    ids = [p.id for p in payloads]
    assert len(ids) == len(set(ids))


def test_bundled_packs_load_without_error() -> None:
    payloads = load_bundled_packs()
    assert len(payloads) > 0
