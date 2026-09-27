from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from on_device_agent_runtime_attestation.appraisal import (
    AppraisalOutcome,
    AppraisalPolicy,
    GoldenReference,
)
from on_device_agent_runtime_attestation.keys import KeyHierarchy


def _policy() -> AppraisalPolicy:
    return AppraisalPolicy(
        GoldenReference({0: "a", 1: "b"}, frozenset({"boot", "runtime"})),
        degraded_allowed_tools=frozenset({"ordinary_read"}),
        trusted_allowed_tools=frozenset({"ordinary_read", "mutation"}),
    )


def test_trusted_appraisal_when_all_registers_match() -> None:
    assert _policy().appraise({0: "a", 1: "b"}, {"boot", "runtime"}) == AppraisalOutcome.TRUSTED


def test_degraded_appraisal_when_one_register_differs() -> None:
    assert _policy().appraise({0: "a", 1: "c"}, {"boot", "runtime"}) == AppraisalOutcome.DEGRADED


def test_untrusted_appraisal_when_two_registers_differ() -> None:
    assert _policy().appraise({0: "x", 1: "y"}, {"boot", "runtime"}) == AppraisalOutcome.UNTRUSTED


def test_untrusted_appraisal_when_required_label_missing() -> None:
    assert _policy().appraise({0: "a", 1: "b"}, {"boot"}) == AppraisalOutcome.UNTRUSTED


def test_trusted_policy_allows_write_file() -> None:
    assert _policy().tool_allowed(AppraisalOutcome.TRUSTED, "mutation")


def test_degraded_policy_denies_write_file() -> None:
    assert not _policy().tool_allowed(AppraisalOutcome.DEGRADED, "mutation")


def test_untrusted_policy_denies_read_only_file() -> None:
    assert not _policy().tool_allowed(AppraisalOutcome.UNTRUSTED, "ordinary_read")


def test_key_hierarchy_rotates_identifier() -> None:
    hierarchy = KeyHierarchy(root_key=b"root")
    first = hierarchy.active_key_identifier
    second = hierarchy.rotate_attestation_key().key_identifier
    assert first != second


def test_key_hierarchy_derives_stable_material() -> None:
    one = KeyHierarchy(root_key=b"root")
    two = KeyHierarchy(root_key=b"root")
    assert one.signing_key() == two.signing_key()


def test_key_hierarchy_revocation_removes_verification_key() -> None:
    hierarchy = KeyHierarchy(root_key=b"root")
    key_identifier = hierarchy.active_key_identifier
    hierarchy.revoke(key_identifier)
    assert hierarchy.verify_key(key_identifier) is None
    assert hierarchy.is_revoked(key_identifier)


def test_signing_with_revoked_key_fails() -> None:
    hierarchy = KeyHierarchy(root_key=b"root")
    key_identifier = hierarchy.active_key_identifier
    hierarchy.revoke(key_identifier)
    with pytest.raises(ValueError, match="revoked"):
        hierarchy.signing_key(key_identifier)


@given(
    st.dictionaries(
        st.integers(min_value=0, max_value=3),
        st.text(min_size=1, max_size=8),
        min_size=1,
        max_size=4,
    )
)
def test_property_appraisal_is_total(registers: dict[int, str]) -> None:
    policy = AppraisalPolicy(
        GoldenReference({0: "a"}, frozenset()),
        degraded_allowed_tools=frozenset(),
        trusted_allowed_tools=frozenset(),
    )
    assert policy.appraise(registers, set()) in set(AppraisalOutcome)


@given(st.sampled_from(list(AppraisalOutcome)), st.text(min_size=1, max_size=20))
def test_property_untrusted_never_allows_tools(outcome: AppraisalOutcome, tool: str) -> None:
    policy = _policy()
    if outcome == AppraisalOutcome.UNTRUSTED:
        assert not policy.tool_allowed(outcome, tool)
