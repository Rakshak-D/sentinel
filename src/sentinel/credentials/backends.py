"""Unavailable production backend and synthetic in-memory test backend."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from sentinel.credentials.types import (
    BackendAvailability,
    CredentialBrokerError,
    CredentialFailureCode,
    CredentialStatus,
    SecretRef,
    SecretReferenceState,
)


class _CredentialBackend(Protocol):
    """Private broker backend contract; not injectable through public construction."""

    def status(self, reference: SecretRef) -> CredentialStatus: ...


class UnavailableCredentialBackend:
    """Fail-closed production default until an OS-protected backend is verified."""

    __slots__ = ()

    def status(self, reference: SecretRef) -> CredentialStatus:
        del reference
        return CredentialStatus(
            backend=BackendAvailability.UNAVAILABLE,
            reference=SecretReferenceState.UNKNOWN,
        )


@dataclass(frozen=True, slots=True, repr=False)
class _TestEntry:
    reference: SecretRef
    value: bytes = field(repr=False)
    revoked: bool = False


class SyntheticCredentialAccess:
    """Synthetic-only secret handle; repr/str never reveal the in-memory bytes.

    ``reveal_for_test`` exists solely so contract tests can prove the explicit
    in-memory path works. This class is not a serialization or production DTO.
    """

    __slots__ = ("__value",)

    def __init__(self, value: bytes) -> None:
        self.__value = bytes(value)

    def reveal_for_test(self) -> bytes:
        """Return the synthetic bytes to the test that explicitly requested them."""

        return bytes(self.__value)

    def __repr__(self) -> str:
        return "SyntheticCredentialAccess(<redacted>)"

    def __str__(self) -> str:
        return "<synthetic credential redacted>"


class InMemoryTestBackend:
    """Process-memory-only backend for automated tests; never a secure store."""

    __slots__ = ("_entries",)

    def __init__(self) -> None:
        self._entries: dict[str, _TestEntry] = {}

    def status(self, reference: SecretRef) -> CredentialStatus:
        if reference.revoked_at is not None:
            state = SecretReferenceState.REVOKED
        else:
            entry = self._matching_entry(reference)
            state = (
                SecretReferenceState.MISSING
                if entry is None
                else SecretReferenceState.REVOKED
                if entry.revoked
                else SecretReferenceState.PRESENT
            )
        return CredentialStatus(backend=BackendAvailability.AVAILABLE, reference=state)

    def put_for_test(self, reference: SecretRef, value: bytes) -> None:
        if type(value) is not bytes or not value or len(value) > 4096:
            raise CredentialBrokerError(CredentialFailureCode.INVALID_SYNTHETIC_CREDENTIAL)
        if reference.revoked_at is not None:
            raise CredentialBrokerError(CredentialFailureCode.REFERENCE_REVOKED)

        existing = self._entries.get(reference.secret_ref_id)
        if existing is not None:
            if existing.reference == reference and existing.value == value:
                return
            raise CredentialBrokerError(CredentialFailureCode.REGISTRATION_CONFLICT)
        self._entries[reference.secret_ref_id] = _TestEntry(reference=reference, value=bytes(value))

    def revoke_for_test(self, reference: SecretRef) -> None:
        entry = self._matching_entry(reference)
        if entry is None:
            raise CredentialBrokerError(CredentialFailureCode.REFERENCE_MISSING)
        if entry.revoked:
            return
        self._entries[reference.secret_ref_id] = _TestEntry(
            reference=entry.reference,
            value=entry.value,
            revoked=True,
        )

    def resolve_for_test(self, reference: SecretRef) -> SyntheticCredentialAccess:
        if reference.revoked_at is not None:
            raise CredentialBrokerError(CredentialFailureCode.REFERENCE_REVOKED)
        entry = self._matching_entry(reference)
        if entry is None:
            raise CredentialBrokerError(CredentialFailureCode.REFERENCE_MISSING)
        if entry.revoked:
            raise CredentialBrokerError(CredentialFailureCode.REFERENCE_REVOKED)
        return SyntheticCredentialAccess(entry.value)

    def _matching_entry(self, reference: SecretRef) -> _TestEntry | None:
        entry = self._entries.get(reference.secret_ref_id)
        if entry is not None and entry.reference != reference:
            raise CredentialBrokerError(CredentialFailureCode.INVALID_REFERENCE)
        return entry
