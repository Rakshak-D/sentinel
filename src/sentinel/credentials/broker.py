"""Credential broker facade with no production secret-retrieval operation."""

from __future__ import annotations

from sentinel.credentials.backends import (
    InMemoryTestBackend,
    SyntheticCredentialAccess,
    UnavailableCredentialBackend,
    _CredentialBackend,
)
from sentinel.credentials.types import (
    BackendAvailability,
    CredentialBrokerError,
    CredentialFailureCode,
    CredentialStatus,
    validate_secret_ref,
)


class CredentialBroker:
    """Expose safe status in production and explicit test-only memory operations.

    Normal construction always selects the unavailable backend. There is no
    public backend injection, caller identity parameter, approval flag, or
    production value-retrieval method. ``for_tests`` is an explicit construction
    path for synthetic automated contract tests only.
    """

    __slots__ = ("_backend", "_test_backend")
    _backend: _CredentialBackend
    _test_backend: InMemoryTestBackend | None

    def __init__(self) -> None:
        object.__setattr__(self, "_backend", UnavailableCredentialBackend())
        object.__setattr__(self, "_test_backend", None)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("CredentialBroker backend selection is immutable.")

    @classmethod
    def for_tests(cls) -> CredentialBroker:
        """Construct an isolated in-memory broker for synthetic tests only."""

        broker = cls()
        backend = InMemoryTestBackend()
        object.__setattr__(broker, "_backend", backend)
        object.__setattr__(broker, "_test_backend", backend)
        return broker

    def status(self, reference: object) -> CredentialStatus:
        """Report backend/reference state without returning credential bytes."""

        validated = validate_secret_ref(reference)
        try:
            return self._backend.status(validated)
        except CredentialBrokerError:
            raise
        except Exception:
            raise CredentialBrokerError(CredentialFailureCode.BACKEND_FAILURE) from None

    @property
    def backend_availability(self) -> BackendAvailability:
        """Return backend capability without validating or probing any credential."""

        try:
            availability = self._backend.availability
        except Exception:
            return BackendAvailability.UNAVAILABLE
        return (
            availability
            if type(availability) is BackendAvailability
            else BackendAvailability.UNAVAILABLE
        )

    def put_for_test(self, reference: object, value: bytes) -> None:
        """Register synthetic bytes in the explicit test backend only."""

        backend = self._require_test_backend()
        validated = validate_secret_ref(reference)
        try:
            backend.put_for_test(validated, value)
        except CredentialBrokerError:
            raise
        except Exception:
            raise CredentialBrokerError(CredentialFailureCode.BACKEND_FAILURE) from None

    def revoke_for_test(self, reference: object) -> None:
        """Revoke a synthetic reference; repeated revocation is idempotent."""

        backend = self._require_test_backend()
        validated = validate_secret_ref(reference)
        try:
            backend.revoke_for_test(validated)
        except CredentialBrokerError:
            raise
        except Exception:
            raise CredentialBrokerError(CredentialFailureCode.BACKEND_FAILURE) from None

    def resolve_for_test(self, reference: object) -> SyntheticCredentialAccess:
        """Resolve synthetic bytes for an explicitly constructed test broker only."""

        backend = self._require_test_backend()
        validated = validate_secret_ref(reference)
        try:
            return backend.resolve_for_test(validated)
        except CredentialBrokerError:
            raise
        except Exception:
            raise CredentialBrokerError(CredentialFailureCode.BACKEND_FAILURE) from None

    def _require_test_backend(self) -> InMemoryTestBackend:
        backend = self._test_backend
        if backend is None:
            raise CredentialBrokerError(CredentialFailureCode.BACKEND_UNAVAILABLE)
        return backend
