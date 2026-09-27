from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AttestationKeyRecord:
    key_identifier: str
    key_material: bytes
    generation: int
    revoked: bool = False


class KeyHierarchy:
    """Software reference hierarchy for root keys and attestation keys."""

    def __init__(self, root_key: bytes | None = None) -> None:
        self._root_key = root_key if root_key is not None else secrets.token_bytes(32)
        self._generation = 0
        self._active_identifier = ""
        self._records: dict[str, AttestationKeyRecord] = {}
        self.rotate_attestation_key()

    @property
    def active_key_identifier(self) -> str:
        return self._active_identifier

    def rotate_attestation_key(self) -> AttestationKeyRecord:
        self._generation += 1
        key_identifier = f"software-attestation-key-{self._generation}"
        material = hmac.digest(self._root_key, key_identifier.encode(), "sha256")
        record = AttestationKeyRecord(key_identifier, material, self._generation)
        self._records[key_identifier] = record
        self._active_identifier = key_identifier
        return record

    def revoke(self, key_identifier: str) -> None:
        record = self._records[key_identifier]
        self._records[key_identifier] = AttestationKeyRecord(
            record.key_identifier,
            record.key_material,
            record.generation,
            revoked=True,
        )

    def signing_key(self, key_identifier: str | None = None) -> bytes:
        identifier = self._active_identifier if key_identifier is None else key_identifier
        record = self._records[identifier]
        if record.revoked:
            raise ValueError("attestation key revoked")
        return record.key_material

    def verify_key(self, key_identifier: str) -> bytes | None:
        record = self._records.get(key_identifier)
        if record is None or record.revoked:
            return None
        return record.key_material

    def is_revoked(self, key_identifier: str) -> bool:
        record = self._records.get(key_identifier)
        return record is None or record.revoked
