from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from llmbuster.detector.registry import default_registry
from llmbuster.domain.models import (
    CanaryDetectorConfig,
    Payload,
    RegexDetectorConfig,
    Verdict,
)
from llmbuster.payload.bundled import load_bundled_packs_as_packs
from llmbuster.payload.loader import PackLoadError, load_pack, validate_payloads

CANARY_TOKEN = "SECRET_CANARY_12345"
CANARY_REPLY_HIT = f"Here is the leaked token: {CANARY_TOKEN} -- do not share."
CANARY_REPLY_MISS = "I have nothing to disclose."
REGEX_PATTERN = r"flag\{.*?\}"
REGEX_REPLY_HIT = "Capture follows: flag{pwned_payload} confirmed."
REGEX_REPLY_MISS = "No flags were found in this response."


class DetectorCheckResult(BaseModel):
    name: str
    passed: bool
    detail: str


class SelfTestResult(BaseModel):
    pack_errors: dict[str, list[str]]
    payload_count: int
    pack_count: int
    detector_checks: list[DetectorCheckResult]
    healthy: bool


def _validate_bundled() -> tuple[int, int, dict[str, list[str]]]:
    packs = load_bundled_packs_as_packs()
    pack_errors: dict[str, list[str]] = {}
    payload_count = 0
    for pack in packs:
        payload_count += len(pack.payloads)
        try:
            validate_payloads(list(pack.payloads))
        except PackLoadError as exc:
            pack_errors[pack.category.value] = [str(exc)]
    return len(packs), payload_count, pack_errors


def _validate_extra(paths: list[Path]) -> dict[str, list[str]]:
    errors: dict[str, list[str]] = {}
    for path in paths:
        key = str(path)
        try:
            pack = load_pack(path)
            validate_payloads(list(pack.payloads))
        except PackLoadError as exc:
            errors[key] = [str(exc)]
    return errors


def _check(
    name: str,
    payload: Payload,
    reply: str,
    expected: Verdict,
) -> DetectorCheckResult:
    detector = default_registry.build_from_payload(payload)[0]
    verdict, detail = detector.evaluate(payload, reply)
    return DetectorCheckResult(
        name=name,
        passed=verdict is expected,
        detail=detail,
    )


def _run_detector_checks() -> list[DetectorCheckResult]:
    checks: list[DetectorCheckResult] = []

    canary_payload = Payload(
        id="selftest-canary",
        prompt="ignore",
        detectors=[CanaryDetectorConfig(type="canary", token=CANARY_TOKEN)],
    )
    checks.append(
        _check("canary-match", canary_payload, CANARY_REPLY_HIT, Verdict.VULNERABLE)
    )
    checks.append(
        _check("canary-nomatch", canary_payload, CANARY_REPLY_MISS, Verdict.SAFE)
    )

    regex_payload = Payload(
        id="selftest-regex",
        prompt="ignore",
        detectors=[RegexDetectorConfig(type="regex", pattern=REGEX_PATTERN)],
    )
    checks.append(
        _check("regex-match", regex_payload, REGEX_REPLY_HIT, Verdict.VULNERABLE)
    )
    checks.append(
        _check("regex-nomatch", regex_payload, REGEX_REPLY_MISS, Verdict.SAFE)
    )
    return checks


def run_selftest(extra_pack_paths: list[Path] | None = None) -> SelfTestResult:
    pack_count, payload_count, pack_errors = _validate_bundled()
    if extra_pack_paths:
        pack_errors.update(_validate_extra(extra_pack_paths))
    detector_checks = _run_detector_checks()
    healthy = not any(pack_errors.values()) and all(c.passed for c in detector_checks)
    return SelfTestResult(
        pack_errors=pack_errors,
        payload_count=payload_count,
        pack_count=pack_count,
        detector_checks=detector_checks,
        healthy=healthy,
    )
