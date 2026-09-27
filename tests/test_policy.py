from __future__ import annotations

from on_device_agent_runtime_attestation.policy import Policy, ToolRequest


def test_destination_outside_domain_is_denied() -> None:
    policy = Policy.default()
    request = ToolRequest("agent", "email.send", {"to": "outside@example.net"})
    assert not policy.destination_allowed(request)


def test_internal_subdomain_is_allowed() -> None:
    policy = Policy.default()
    request = ToolRequest("agent", "http.get", {"url": "https://events.acme.test/item"})
    assert policy.destination_allowed(request)
