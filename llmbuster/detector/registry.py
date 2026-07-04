from __future__ import annotations

from llmbuster.detector.heuristic import CanaryDetector, RegexDetector
from llmbuster.domain import (
    CanaryDetectorConfig,
    Detector,
    DetectorConfig,
    Payload,
    RegexDetectorConfig,
)


class UnknownDetectorError(ValueError):
    pass


class DetectorRegistry:
    def __init__(self) -> None:
        self._registry: dict[str, type[Detector]] = {}

    def register(self, type_name: str, detector_cls: type[Detector]) -> None:
        self._registry[type_name] = detector_cls

    def build(self, config: DetectorConfig) -> Detector:
        if isinstance(config, CanaryDetectorConfig):
            return CanaryDetector(token=config.token)
        if isinstance(config, RegexDetectorConfig):
            return RegexDetector(pattern=config.pattern, flags=config.flags)
        raise UnknownDetectorError(f"unknown detector type: {config!r}")

    def build_from_payload(self, payload: Payload) -> list[Detector]:
        return [self.build(config) for config in payload.detectors]


default_registry = DetectorRegistry()
default_registry.register("canary", CanaryDetector)
default_registry.register("regex", RegexDetector)
