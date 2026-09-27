from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Measurement:
    label: str
    digest: str
    size_bytes: int

    @classmethod
    def from_bytes(cls, label: str, content: bytes) -> Measurement:
        return cls(label=label, digest=hashlib.sha256(content).hexdigest(), size_bytes=len(content))

    @classmethod
    def from_file(cls, label: str, path: Path) -> Measurement:
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
        return cls(label=label, digest=digest.hexdigest(), size_bytes=size)

    def canonical(self) -> str:
        return f"{self.label}:{self.size_bytes}:{self.digest}"


class MeasurementChain:
    def __init__(self, measurements: Iterable[Measurement] = ()) -> None:
        self._measurements = tuple(measurements)

    @property
    def measurements(self) -> tuple[Measurement, ...]:
        return self._measurements

    def append(self, measurement: Measurement) -> MeasurementChain:
        return MeasurementChain((*self._measurements, measurement))

    def root_digest(self) -> str:
        current = "0" * 64
        for measurement in self._measurements:
            current = hashlib.sha256((current + measurement.canonical()).encode()).hexdigest()
        return current

    def expected_digest_map(self) -> dict[str, str]:
        return {measurement.label: measurement.digest for measurement in self._measurements}

    def verify_expected(self, expected: dict[str, str]) -> bool:
        actual = self.expected_digest_map()
        return all(actual.get(label) == digest for label, digest in expected.items())
