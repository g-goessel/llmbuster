from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from pydantic import BaseModel

from llmbuster.domain.models import Verdict
from llmbuster.orchestrator.aggregation import compute_reproducibility
from llmbuster.store.sqlite_store import InteractionRecord

_VULNERABLE = Verdict.VULNERABLE.value
_SAFE = Verdict.SAFE.value
_ERROR = Verdict.ERROR.value
_INCONCLUSIVE = Verdict.INCONCLUSIVE.value


class CategorySummary(BaseModel):
    category: str
    total: int
    vulnerable: int
    safe: int
    error: int
    inconclusive: int
    vulnerable_rate: float
    avg_ttft_ms: float | None
    avg_tps: float | None
    avg_duration_ms: float | None


class PayloadSummary(BaseModel):
    payload_id: str
    category: str
    total: int
    vulnerable: int
    vulnerable_rate: float
    rolled_up_verdict: Verdict


class RunStats(BaseModel):
    total_interactions: int
    total_vulnerable: int
    overall_vulnerable_rate: float
    avg_ttft_ms: float | None
    avg_tps: float | None


def _avg(values: Iterable[int | float | None]) -> float | None:
    total = 0.0
    count = 0
    for value in values:
        if value is not None:
            total += value
            count += 1
    if count == 0:
        return None
    return total / count


def summarize_run(
    records: list[InteractionRecord],
) -> tuple[list[CategorySummary], list[PayloadSummary], RunStats]:
    by_category: dict[str, list[InteractionRecord]] = defaultdict(list)
    by_payload: dict[str, list[InteractionRecord]] = defaultdict(list)
    for record in records:
        by_category[record.owasp_category].append(record)
        by_payload[record.payload_id].append(record)

    categories: list[CategorySummary] = []
    for category in sorted(by_category):
        recs = by_category[category]
        total = len(recs)
        vulnerable = sum(1 for r in recs if r.verdict == _VULNERABLE)
        safe = sum(1 for r in recs if r.verdict == _SAFE)
        error = sum(1 for r in recs if r.verdict == _ERROR)
        inconclusive = sum(1 for r in recs if r.verdict == _INCONCLUSIVE)
        rate = 0.0 if total == 0 else vulnerable / total
        categories.append(
            CategorySummary(
                category=category,
                total=total,
                vulnerable=vulnerable,
                safe=safe,
                error=error,
                inconclusive=inconclusive,
                vulnerable_rate=rate,
                avg_ttft_ms=_avg(r.ttft_ms for r in recs),
                avg_tps=_avg(r.tps for r in recs),
                avg_duration_ms=_avg(r.duration_ms for r in recs),
            )
        )

    payloads: list[PayloadSummary] = []
    for payload_id, recs in by_payload.items():
        score = compute_reproducibility(
            payload_id, [Verdict(r.verdict) for r in recs]
        )
        if score.vulnerable_count == 0:
            continue
        payloads.append(
            PayloadSummary(
                payload_id=payload_id,
                category=recs[0].owasp_category,
                total=score.total,
                vulnerable=score.vulnerable_count,
                vulnerable_rate=score.vulnerable_rate,
                rolled_up_verdict=score.rolled_up_verdict,
            )
        )
    payloads.sort(key=lambda p: (-p.vulnerable, p.payload_id))

    total_interactions = len(records)
    total_vulnerable = sum(1 for r in records if r.verdict == _VULNERABLE)
    overall_rate = (
        0.0 if total_interactions == 0 else total_vulnerable / total_interactions
    )
    run_stats = RunStats(
        total_interactions=total_interactions,
        total_vulnerable=total_vulnerable,
        overall_vulnerable_rate=overall_rate,
        avg_ttft_ms=_avg(r.ttft_ms for r in records),
        avg_tps=_avg(r.tps for r in records),
    )
    return categories, payloads, run_stats
