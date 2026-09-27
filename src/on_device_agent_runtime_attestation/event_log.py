from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

ZERO_DIGEST = "0" * 64


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class MeasurementEvent:
    sequence_number: int
    register_index: int
    label: str
    digest: str
    event_type: str = "measurement"
    metadata: dict[str, str] = field(default_factory=dict)

    def canonical(self) -> str:
        payload = {
            "digest": self.digest,
            "event_type": self.event_type,
            "label": self.label,
            "metadata": self.metadata,
            "register_index": self.register_index,
            "sequence_number": self.sequence_number,
        }
        return _canonical_json(payload)


@dataclass(frozen=True, slots=True)
class RegisterBank:
    values: dict[int, str]

    @classmethod
    def empty(cls, register_count: int = 8) -> RegisterBank:
        return cls({index: ZERO_DIGEST for index in range(register_count)})

    def extend(self, event: MeasurementEvent) -> RegisterBank:
        if event.register_index not in self.values:
            raise ValueError("unknown register")
        old_value = self.values[event.register_index]
        new_value = hashlib.sha256((old_value + event.canonical()).encode()).hexdigest()
        values = dict(self.values)
        values[event.register_index] = new_value
        return RegisterBank(values)

    def subset(self, indices: set[int]) -> dict[int, str]:
        return {index: self.values[index] for index in sorted(indices)}


class MeasurementLog:
    def __init__(self, register_count: int = 8) -> None:
        self._register_count = register_count
        self._events: list[MeasurementEvent] = []
        self._bank = RegisterBank.empty(register_count)

    @property
    def events(self) -> tuple[MeasurementEvent, ...]:
        return tuple(self._events)

    @property
    def bank(self) -> RegisterBank:
        return self._bank

    def append(
        self,
        *,
        register_index: int,
        label: str,
        digest: str,
        event_type: str = "measurement",
        metadata: dict[str, str] | None = None,
    ) -> MeasurementEvent:
        event = MeasurementEvent(
            sequence_number=len(self._events) + 1,
            register_index=register_index,
            label=label,
            digest=digest,
            event_type=event_type,
            metadata={} if metadata is None else dict(metadata),
        )
        self._bank = self._bank.extend(event)
        self._events.append(event)
        return event

    def event_log_digest(self) -> str:
        digest = hashlib.sha256()
        for event in self._events:
            digest.update(event.canonical().encode())
        return digest.hexdigest()

    def replay(self) -> RegisterBank:
        return replay_events(self._events, self._register_count)


def replay_events(
    events: tuple[MeasurementEvent, ...] | list[MeasurementEvent], register_count: int = 8
) -> RegisterBank:
    expected_sequence = 1
    bank = RegisterBank.empty(register_count)
    for event in events:
        if event.sequence_number != expected_sequence:
            raise ValueError("event log sequence is not contiguous")
        bank = bank.extend(event)
        expected_sequence += 1
    return bank


def event_log_digest(events: tuple[MeasurementEvent, ...] | list[MeasurementEvent]) -> str:
    digest = hashlib.sha256()
    for event in events:
        digest.update(event.canonical().encode())
    return digest.hexdigest()
