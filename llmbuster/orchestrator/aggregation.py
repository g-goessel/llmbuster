from __future__ import annotations

from collections import Counter

from pydantic import BaseModel

from llmbuster.domain import Interaction, Payload, Verdict


class ReproducibilityScore(BaseModel):
    payload_id: str
    total: int
    vulnerable_count: int
    safe_count: int
    error_count: int
    inconclusive_count: int
    vulnerable_rate: float
    rolled_up_verdict: Verdict
    detail: str


def _rollup(
    total: int,
    vulnerable_count: int,
    safe_count: int,
    error_count: int,
) -> Verdict:
    if total == 0:
        return Verdict.INCONCLUSIVE
    if error_count == total:
        return Verdict.ERROR
    if vulnerable_count > 0:
        return Verdict.VULNERABLE
    if safe_count > 0:
        return Verdict.SAFE
    return Verdict.INCONCLUSIVE


def _detail(payload_id: str, vulnerable_count: int, total: int) -> str:
    pct = 0.0 if total == 0 else (vulnerable_count / total) * 100.0
    return f"{payload_id}: {vulnerable_count}/{total} vulnerable ({pct:.1f}%)"


def compute_reproducibility(
    payload_id: str,
    verdicts: list[Verdict],
) -> ReproducibilityScore:
    counts = Counter(verdicts)
    vulnerable_count = counts[Verdict.VULNERABLE]
    safe_count = counts[Verdict.SAFE]
    error_count = counts[Verdict.ERROR]
    inconclusive_count = counts[Verdict.INCONCLUSIVE]
    total = len(verdicts)
    vulnerable_rate = 0.0 if total == 0 else vulnerable_count / total
    rolled_up_verdict = _rollup(total, vulnerable_count, safe_count, error_count)
    detail = _detail(payload_id, vulnerable_count, total)
    return ReproducibilityScore(
        payload_id=payload_id,
        total=total,
        vulnerable_count=vulnerable_count,
        safe_count=safe_count,
        error_count=error_count,
        inconclusive_count=inconclusive_count,
        vulnerable_rate=vulnerable_rate,
        rolled_up_verdict=rolled_up_verdict,
        detail=detail,
    )


def aggregate_interactions(
    payload_id: str,
    interactions: list[Interaction],
) -> ReproducibilityScore:
    return compute_reproducibility(payload_id, [i.verdict for i in interactions])


def aggregate_all(
    payloads: list[Payload],
    interactions: list[Interaction],
) -> list[ReproducibilityScore]:
    by_payload: dict[str, list[Interaction]] = {}
    for interaction in interactions:
        by_payload.setdefault(interaction.payload_id, []).append(interaction)
    return [
        aggregate_interactions(payload.id, by_payload.get(payload.id, []))
        for payload in payloads
    ]
