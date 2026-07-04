from __future__ import annotations

import pytest

from llmbuster.domain import Interaction, Metrics, OwaspCategory, Payload, Verdict
from llmbuster.orchestrator import (
    ReproducibilityScore,
    aggregate_all,
    aggregate_interactions,
    compute_reproducibility,
)

V = Verdict.VULNERABLE
S = Verdict.SAFE
ERR = Verdict.ERROR
INC = Verdict.INCONCLUSIVE


def _interaction(payload_id: str, verdict: Verdict, attempt_index: int = 0) -> Interaction:
    return Interaction(
        run_id=1,
        payload_id=payload_id,
        owasp_category=OwaspCategory.LLM01,
        attempt_index=attempt_index,
        sent_history_json='{"messages":[]}',
        raw_request_json='{"body":"x"}',
        raw_response_text="raw",
        response_text="reply",
        metrics=Metrics(),
        verdict=verdict,
    )


def test_all_vulnerable() -> None:
    score = compute_reproducibility("p1", [V, V, V, V, V])
    assert score.total == 5
    assert score.vulnerable_count == 5
    assert score.vulnerable_rate == 1.0
    assert score.rolled_up_verdict is Verdict.VULNERABLE
    assert "5/5" in score.detail


def test_mixed_vulnerable_and_safe() -> None:
    score = compute_reproducibility("p1", [V, V, V, S, S])
    assert score.vulnerable_rate == pytest.approx(0.6)
    assert score.rolled_up_verdict is Verdict.VULNERABLE


def test_single_vulnerable_out_of_five() -> None:
    score = compute_reproducibility("p1", [V, S, S, S, S])
    assert score.vulnerable_rate == pytest.approx(0.2)
    assert score.rolled_up_verdict is Verdict.VULNERABLE


def test_all_safe() -> None:
    score = compute_reproducibility("p1", [S, S, S, S, S])
    assert score.vulnerable_count == 0
    assert score.vulnerable_rate == 0.0
    assert score.rolled_up_verdict is Verdict.SAFE


def test_all_errors() -> None:
    score = compute_reproducibility("p1", [ERR, ERR, ERR, ERR, ERR])
    assert score.error_count == 5
    assert score.rolled_up_verdict is Verdict.ERROR


def test_errors_and_safe() -> None:
    score = compute_reproducibility("p1", [ERR, ERR, S, S, S])
    assert score.error_count == 2
    assert score.safe_count == 3
    assert score.rolled_up_verdict is Verdict.SAFE


def test_errors_vulnerable_and_safe() -> None:
    score = compute_reproducibility("p1", [ERR, ERR, V, S, S])
    assert score.rolled_up_verdict is Verdict.VULNERABLE


def test_all_inconclusive() -> None:
    score = compute_reproducibility("p1", [INC, INC, INC])
    assert score.inconclusive_count == 3
    assert score.rolled_up_verdict is Verdict.INCONCLUSIVE


def test_empty_list() -> None:
    score = compute_reproducibility("p1", [])
    assert score.total == 0
    assert score.vulnerable_rate == 0.0
    assert score.rolled_up_verdict is Verdict.INCONCLUSIVE


def test_counts_are_correct() -> None:
    score = compute_reproducibility("p1", [V, S, S, ERR, INC])
    assert score.vulnerable_count == 1
    assert score.safe_count == 2
    assert score.error_count == 1
    assert score.inconclusive_count == 1
    assert score.total == 5
    assert score.vulnerable_rate == pytest.approx(0.2)
    assert score.rolled_up_verdict is Verdict.VULNERABLE


def test_aggregate_interactions() -> None:
    interactions = [
        _interaction("p1", V, 0),
        _interaction("p1", S, 1),
        _interaction("p1", V, 2),
    ]
    score = aggregate_interactions("p1", interactions)
    assert score.payload_id == "p1"
    assert score.total == 3
    assert score.vulnerable_count == 2
    assert score.safe_count == 1
    assert score.rolled_up_verdict is Verdict.VULNERABLE


def test_aggregate_all_groups_by_payload() -> None:
    p1 = Payload(id="p1", prompt="a")
    p2 = Payload(id="p2", prompt="b")
    p3 = Payload(id="p3", prompt="c")
    interactions = [
        _interaction("p1", V, 0),
        _interaction("p1", S, 1),
        _interaction("p2", S, 0),
        _interaction("p2", S, 1),
    ]
    scores = aggregate_all([p1, p2, p3], interactions)
    assert [s.payload_id for s in scores] == ["p1", "p2", "p3"]
    assert scores[0].rolled_up_verdict is Verdict.VULNERABLE
    assert scores[0].total == 2
    assert scores[1].rolled_up_verdict is Verdict.SAFE
    assert scores[1].total == 2
    assert scores[2].total == 0
    assert scores[2].rolled_up_verdict is Verdict.INCONCLUSIVE


def test_reproducibility_score_round_trip() -> None:
    score = compute_reproducibility("p1", [V, V, S, ERR, INC])
    dumped = score.model_dump_json()
    rebuilt = ReproducibilityScore.model_validate_json(dumped)
    assert rebuilt == score
    assert rebuilt.rolled_up_verdict is Verdict.VULNERABLE


def test_detail_string_format() -> None:
    score = compute_reproducibility("p1", [V, V, V, S, S])
    assert "3" in score.detail
    assert "5" in score.detail
    assert "%" in score.detail
    assert "60.0" in score.detail
