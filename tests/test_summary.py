from __future__ import annotations

import pytest

from llmbuster.domain.models import OwaspCategory, Verdict
from llmbuster.orchestrator import (
    CategorySummary,
    PayloadSummary,
    RunStats,
    summarize_run,
)
from llmbuster.store.sqlite_store import InteractionRecord


def _rec(
    payload_id: str,
    category: OwaspCategory,
    verdict: Verdict,
    *,
    attempt: int = 0,
    ttft_ms: int | None = None,
    tps: float | None = None,
    duration_ms: int | None = None,
) -> InteractionRecord:
    return InteractionRecord(
        run_id=1,
        payload_id=payload_id,
        owasp_category=category.value,
        attempt_index=attempt,
        mutation=None,
        escalation_from=None,
        sent_history_json='{"messages":[]}',
        raw_request_json='{"body":"x"}',
        raw_response_text="raw",
        response_text="reply",
        ttft_ms=ttft_ms,
        duration_ms=duration_ms,
        tps=tps,
        prompt_tokens=5,
        completion_tokens=9,
        verdict=verdict.value,
        detector_id="canary",
        detector_detail="d",
        created_at="2026-07-04T12:00:01+00:00",
    )


def test_empty_run() -> None:
    categories, payloads, stats = summarize_run([])
    assert categories == []
    assert payloads == []
    assert isinstance(stats, RunStats)
    assert stats.total_interactions == 0
    assert stats.total_vulnerable == 0
    assert stats.overall_vulnerable_rate == 0.0
    assert stats.avg_ttft_ms is None
    assert stats.avg_tps is None


def test_single_category() -> None:
    records = [
        _rec("p1", OwaspCategory.LLM01, Verdict.VULNERABLE, ttft_ms=100, tps=10.0),
        _rec("p1", OwaspCategory.LLM01, Verdict.VULNERABLE, ttft_ms=200, tps=20.0),
        _rec("p1", OwaspCategory.LLM01, Verdict.SAFE, ttft_ms=None, tps=None),
    ]
    categories, _, _ = summarize_run(records)
    assert len(categories) == 1
    cat = categories[0]
    assert isinstance(cat, CategorySummary)
    assert cat.category == "LLM01"
    assert cat.total == 3
    assert cat.vulnerable == 2
    assert cat.safe == 1
    assert cat.error == 0
    assert cat.inconclusive == 0
    assert cat.vulnerable_rate == pytest.approx(2 / 3)
    assert cat.avg_ttft_ms == pytest.approx(150.0)
    assert cat.avg_tps == pytest.approx(15.0)
    assert cat.avg_duration_ms is None


def test_multiple_categories_sorted() -> None:
    records = [
        _rec("p1", OwaspCategory.LLM06, Verdict.VULNERABLE),
        _rec("p2", OwaspCategory.LLM01, Verdict.SAFE),
        _rec("p3", OwaspCategory.LLM03, Verdict.SAFE),
    ]
    categories, _, _ = summarize_run(records)
    assert [c.category for c in categories] == ["LLM01", "LLM03", "LLM06"]


def test_payloads_only_vulnerable() -> None:
    records = [
        _rec("p1", OwaspCategory.LLM01, Verdict.VULNERABLE),
        _rec("p1", OwaspCategory.LLM01, Verdict.SAFE),
        _rec("p1", OwaspCategory.LLM01, Verdict.SAFE),
        _rec("p2", OwaspCategory.LLM02, Verdict.SAFE),
        _rec("p2", OwaspCategory.LLM02, Verdict.SAFE),
        _rec("p2", OwaspCategory.LLM02, Verdict.SAFE),
    ]
    _, payloads, _ = summarize_run(records)
    assert len(payloads) == 1
    assert isinstance(payloads[0], PayloadSummary)
    assert payloads[0].payload_id == "p1"
    assert payloads[0].vulnerable == 1
    assert payloads[0].total == 3
    assert payloads[0].rolled_up_verdict is Verdict.VULNERABLE


def test_payloads_sorted_by_vulnerable_desc() -> None:
    records = [
        _rec("B", OwaspCategory.LLM01, Verdict.VULNERABLE),
        _rec("A", OwaspCategory.LLM01, Verdict.VULNERABLE),
        _rec("A", OwaspCategory.LLM01, Verdict.VULNERABLE),
        _rec("A", OwaspCategory.LLM01, Verdict.VULNERABLE),
    ]
    _, payloads, _ = summarize_run(records)
    assert [p.payload_id for p in payloads] == ["A", "B"]
    assert payloads[0].vulnerable == 3
    assert payloads[1].vulnerable == 1


def test_run_stats() -> None:
    records = [
        _rec("p1", OwaspCategory.LLM01, Verdict.VULNERABLE, ttft_ms=100, tps=10.0),
        _rec("p1", OwaspCategory.LLM01, Verdict.SAFE, ttft_ms=200, tps=20.0),
        _rec("p2", OwaspCategory.LLM06, Verdict.VULNERABLE, ttft_ms=300, tps=30.0),
        _rec("p2", OwaspCategory.LLM06, Verdict.ERROR, ttft_ms=None, tps=None),
    ]
    _, _, stats = summarize_run(records)
    assert stats.total_interactions == 4
    assert stats.total_vulnerable == 2
    assert stats.overall_vulnerable_rate == pytest.approx(0.5)
    assert stats.avg_ttft_ms == pytest.approx(200.0)
    assert stats.avg_tps == pytest.approx(20.0)
