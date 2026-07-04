from __future__ import annotations

import re

import pytest

from llmbuster.detector import (
    CanaryDetector,
    DetectorRegistry,
    RegexDetector,
    UnknownDetectorError,
    default_registry,
)
from llmbuster.domain import (
    CanaryDetectorConfig,
    Detector,
    Payload,
    RegexDetectorConfig,
    Verdict,
)


def _payload() -> Payload:
    return Payload(id="p1", prompt="x")


def test_canary_vulnerable() -> None:
    detector = CanaryDetector("PWNED")
    verdict, detail = detector.evaluate(_payload(), "reply PWNED here")
    assert verdict is Verdict.VULNERABLE
    assert "PWNED" in detail


def test_canary_safe() -> None:
    detector = CanaryDetector("PWNED")
    verdict, detail = detector.evaluate(_payload(), "nothing here")
    assert verdict is Verdict.SAFE
    assert "PWNED" in detail


def test_canary_case_sensitive() -> None:
    detector = CanaryDetector("PWNED")
    verdict, _ = detector.evaluate(_payload(), "the word is pwned")
    assert verdict is Verdict.SAFE


def test_canary_none_reply() -> None:
    detector = CanaryDetector("PWNED")
    verdict, detail = detector.evaluate(_payload(), None)
    assert verdict is Verdict.ERROR
    assert "no reply" in detail


def test_canary_substring_match() -> None:
    detector = CanaryDetector("SEC")
    verdict, _ = detector.evaluate(_payload(), "SECRETS here")
    assert verdict is Verdict.VULNERABLE


def test_regex_vulnerable() -> None:
    detector = RegexDetector("secret")
    verdict, _ = detector.evaluate(_payload(), "the secret is 42")
    assert verdict is Verdict.VULNERABLE


def test_regex_safe() -> None:
    detector = RegexDetector("secret")
    verdict, _ = detector.evaluate(_payload(), "nothing here")
    assert verdict is Verdict.SAFE


def test_regex_ignorecase_flag() -> None:
    detector = RegexDetector("SECRET", flags="IGNORECASE")
    verdict, _ = detector.evaluate(_payload(), "the secret is here")
    assert verdict is Verdict.VULNERABLE


def test_regex_multiline_flag() -> None:
    detector = RegexDetector("^injected", flags="MULTILINE")
    reply = "first line\ninjected payload"
    verdict, _ = detector.evaluate(_payload(), reply)
    assert verdict is Verdict.VULNERABLE


def test_regex_combined_flags() -> None:
    detector = RegexDetector("^INJECTED", flags="IGNORECASE|MULTILINE")
    reply = "first line\ninjected payload"
    verdict, _ = detector.evaluate(_payload(), reply)
    assert verdict is Verdict.VULNERABLE


def test_regex_none_reply() -> None:
    detector = RegexDetector("secret")
    verdict, detail = detector.evaluate(_payload(), None)
    assert verdict is Verdict.ERROR
    assert "no reply" in detail


def test_regex_invalid_pattern_raises_value_error() -> None:
    with pytest.raises((ValueError, re.error)):
        RegexDetector("[")


def test_canary_satisfies_detector_protocol() -> None:
    assert isinstance(CanaryDetector("x"), Detector)


def test_regex_satisfies_detector_protocol() -> None:
    assert isinstance(RegexDetector("x"), Detector)


def test_registry_builds_canary_from_config() -> None:
    config = CanaryDetectorConfig(type="canary", token="PWNED")
    detector = default_registry.build(config)
    assert isinstance(detector, CanaryDetector)
    assert detector.token == "PWNED"


def test_registry_builds_regex_from_config() -> None:
    config = RegexDetectorConfig(type="regex", pattern="secret", flags="IGNORECASE")
    detector = default_registry.build(config)
    assert isinstance(detector, RegexDetector)


def test_registry_build_from_payload() -> None:
    payload = Payload(
        id="p1",
        prompt="x",
        detectors=[
            CanaryDetectorConfig(type="canary", token="PWNED"),
            RegexDetectorConfig(type="regex", pattern="secret"),
        ],
    )
    detectors = default_registry.build_from_payload(payload)
    assert len(detectors) == 2
    assert isinstance(detectors[0], CanaryDetector)
    assert isinstance(detectors[1], RegexDetector)


def test_registry_unknown_type_raises() -> None:
    registry = DetectorRegistry()

    class FakeConfig:
        type = "unknown"

    with pytest.raises(UnknownDetectorError):
        registry.build(FakeConfig())  # type: ignore[arg-type]
