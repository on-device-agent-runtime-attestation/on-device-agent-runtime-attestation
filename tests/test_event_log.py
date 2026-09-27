from __future__ import annotations

import hashlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from on_device_agent_runtime_attestation.event_log import (
    ZERO_DIGEST,
    MeasurementEvent,
    MeasurementLog,
    RegisterBank,
    event_log_digest,
    replay_events,
)


def test_empty_register_bank_has_zero_values() -> None:
    bank = RegisterBank.empty(4)
    assert bank.values == {0: ZERO_DIGEST, 1: ZERO_DIGEST, 2: ZERO_DIGEST, 3: ZERO_DIGEST}


def test_extend_changes_only_selected_register() -> None:
    bank = RegisterBank.empty(3)
    event = MeasurementEvent(1, 1, "runtime", "a" * 64)
    changed = bank.extend(event)
    assert changed.values[1] != bank.values[1]
    assert changed.values[0] == bank.values[0]
    assert changed.values[2] == bank.values[2]


def test_extend_rejects_unknown_register() -> None:
    with pytest.raises(ValueError, match="unknown register"):
        RegisterBank.empty(1).extend(MeasurementEvent(1, 3, "runtime", "b" * 64))


def test_event_canonicalization_is_stable() -> None:
    one = MeasurementEvent(1, 0, "runtime", "c" * 64, metadata={"b": "2", "a": "1"})
    two = MeasurementEvent(1, 0, "runtime", "c" * 64, metadata={"a": "1", "b": "2"})
    assert one.canonical() == two.canonical()


def test_log_append_assigns_contiguous_sequence_numbers() -> None:
    log = MeasurementLog(2)
    assert log.append(register_index=0, label="boot", digest="d" * 64).sequence_number == 1
    assert log.append(register_index=1, label="runtime", digest="e" * 64).sequence_number == 2


def test_log_replay_matches_live_bank() -> None:
    log = MeasurementLog(3)
    log.append(register_index=0, label="boot", digest="f" * 64)
    log.append(register_index=1, label="runtime", digest="1" * 64)
    assert log.replay() == log.bank


def test_replay_rejects_missing_sequence() -> None:
    events = [MeasurementEvent(2, 0, "runtime", "1" * 64)]
    with pytest.raises(ValueError, match="contiguous"):
        replay_events(events)


def test_replay_rejects_reordered_events() -> None:
    first = MeasurementEvent(1, 0, "boot", "1" * 64)
    second = MeasurementEvent(2, 0, "runtime", "2" * 64)
    with pytest.raises(ValueError, match="contiguous"):
        replay_events([second, first])


def test_event_log_digest_changes_when_order_changes() -> None:
    first = MeasurementEvent(1, 0, "boot", "1" * 64)
    second = MeasurementEvent(2, 0, "runtime", "2" * 64)
    swapped = (
        MeasurementEvent(1, 0, "runtime", "2" * 64),
        MeasurementEvent(2, 0, "boot", "1" * 64),
    )
    assert event_log_digest([first, second]) != event_log_digest(swapped)


def test_event_log_digest_is_sha256_hex() -> None:
    event = MeasurementEvent(1, 0, "boot", hashlib.sha256(b"x").hexdigest())
    digest = event_log_digest([event])
    assert len(digest) == 64
    int(digest, 16)


@given(st.lists(st.binary(min_size=0, max_size=32), min_size=1, max_size=20))
def test_property_replay_matches_incremental_extension(contents: list[bytes]) -> None:
    log = MeasurementLog(4)
    for index, content in enumerate(contents):
        log.append(
            register_index=index % 4,
            label=f"event-{index}",
            digest=hashlib.sha256(content).hexdigest(),
        )
    assert replay_events(log.events, 4) == log.bank


@given(st.text(min_size=1, max_size=20), st.text(min_size=1, max_size=20))
def test_property_label_changes_register_digest(label_one: str, label_two: str) -> None:
    event_one = MeasurementEvent(1, 0, label_one, "a" * 64)
    event_two = MeasurementEvent(1, 0, label_two, "a" * 64)
    if event_one.canonical() != event_two.canonical():
        assert RegisterBank.empty(1).extend(event_one) != RegisterBank.empty(1).extend(event_two)
