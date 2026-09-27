from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IdentityDocument:
    subject: str
    trust_domain: str
    not_before_unix_ms: int
    not_after_unix_ms: int

    @classmethod
    def for_agent(
        cls, agent_identifier: str, *, trust_domain: str = "acme.test", lifetime_seconds: int = 300
    ) -> IdentityDocument:
        now = int(time.time() * 1000)
        return cls(
            f"spiffe://{trust_domain}/agent/{agent_identifier}",
            trust_domain,
            now,
            now + lifetime_seconds * 1000,
        )

    def is_valid(self, *, expected_trust_domain: str, now_unix_ms: int | None = None) -> bool:
        now = int(time.time() * 1000) if now_unix_ms is None else now_unix_ms
        return (
            self.trust_domain == expected_trust_domain
            and self.subject.startswith(f"spiffe://{expected_trust_domain}/")
            and self.not_before_unix_ms <= now <= self.not_after_unix_ms
        )
