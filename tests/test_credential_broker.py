from datetime import UTC, datetime, timedelta, timezone

import pytest

from sentinel.credentials.backends import InMemoryTestBackend
from sentinel.credentials.broker import CredentialBroker, CredentialBrokerError
from sentinel.credentials.types import (
    BackendAvailability,
    CredentialFailureCode,
    SecretRef,
    SecretReferenceState,
)


def make_reference(**overrides: object) -> SecretRef:
    fields: dict[str, object] = {
        "secret_ref_id": "secret.synthetic.primary",
        "provider": "gmail",
        "keychain_locator": "sentinel:gmail/primary",
        "scope_manifest_sha256": "a" * 64,
        "os_owner_binding": "windows-owner:synthetic",
        "created_at": datetime(2026, 11, 2, 12, tzinfo=timezone(timedelta(hours=5, minutes=30))),
        "revoked_at": None,
    }
    fields.update(overrides)
    return SecretRef(**fields)  # type: ignore[arg-type]


def test_default_broker_is_unavailable_and_does_not_retrieve() -> None:
    reference = make_reference()
    broker = CredentialBroker()

    status = broker.status(reference)
    assert status.backend == BackendAvailability.UNAVAILABLE
    assert status.reference == SecretReferenceState.UNKNOWN
    with pytest.raises(CredentialBrokerError) as caught:
        broker.resolve_for_test(reference)
    assert caught.value.code == CredentialFailureCode.BACKEND_UNAVAILABLE


def test_default_backend_cannot_be_replaced_through_public_construction_or_assignment() -> None:
    broker = CredentialBroker()
    with pytest.raises(TypeError):
        CredentialBroker(backend=InMemoryTestBackend())  # type: ignore[call-arg]
    with pytest.raises(AttributeError):
        broker._test_backend = InMemoryTestBackend()  # type: ignore[misc]


def test_explicit_synthetic_backend_supports_status_resolve_and_revoke() -> None:
    reference = make_reference()
    broker = CredentialBroker.for_tests()
    canary = b"SYNTHETIC_CREDENTIAL_CANARY_DO_NOT_LOG"

    assert broker.status(reference).reference == SecretReferenceState.MISSING
    broker.put_for_test(reference, canary)
    available_status = broker.status(reference)
    assert available_status.backend == BackendAvailability.AVAILABLE
    assert available_status.reference == SecretReferenceState.PRESENT
    access = broker.resolve_for_test(reference)
    assert access.reveal_for_test() == canary
    assert canary.decode("ascii") not in repr(access)
    assert canary.decode("ascii") not in str(access)
    status_json = broker.status(reference).model_dump_json()
    assert canary.decode("ascii") not in status_json

    broker.revoke_for_test(reference)
    broker.revoke_for_test(reference)
    assert broker.status(reference).reference == SecretReferenceState.REVOKED
    with pytest.raises(CredentialBrokerError) as caught:
        broker.resolve_for_test(reference)
    assert caught.value.code == CredentialFailureCode.REFERENCE_REVOKED


def test_missing_and_revoked_references_are_distinguishable() -> None:
    broker = CredentialBroker.for_tests()
    missing = make_reference(secret_ref_id="secret.synthetic.missing")
    revoked = make_reference(secret_ref_id="secret.synthetic.revoked")

    assert broker.status(missing).reference == SecretReferenceState.MISSING
    with pytest.raises(CredentialBrokerError) as missing_error:
        broker.resolve_for_test(missing)
    assert missing_error.value.code == CredentialFailureCode.REFERENCE_MISSING

    broker.put_for_test(revoked, b"synthetic")
    broker.revoke_for_test(revoked)
    broker.revoke_for_test(revoked)
    assert broker.status(revoked).reference == SecretReferenceState.REVOKED
    with pytest.raises(CredentialBrokerError) as revoked_error:
        broker.resolve_for_test(revoked)
    assert revoked_error.value.code == CredentialFailureCode.REFERENCE_REVOKED


def test_repeated_identical_registration_is_idempotent_but_conflict_fails() -> None:
    reference = make_reference()
    broker = CredentialBroker.for_tests()

    broker.put_for_test(reference, b"synthetic")
    broker.put_for_test(reference, b"synthetic")
    with pytest.raises(CredentialBrokerError) as caught:
        broker.put_for_test(reference, b"different-synthetic")
    assert caught.value.code == CredentialFailureCode.REGISTRATION_CONFLICT


def test_invalid_unchecked_model_copy_is_rejected_before_backend_operation() -> None:
    reference = make_reference()
    invalid_construct = SecretRef.model_construct(
        **{**reference.__dict__, "scope_manifest_sha256": "wrong"}
    )
    invalid_copy = reference.model_copy(update={"scope_manifest_sha256": "wrong"})

    for invalid in (invalid_construct, invalid_copy):
        with pytest.raises(CredentialBrokerError) as caught:
            CredentialBroker.for_tests().status(invalid)
        assert caught.value.code == CredentialFailureCode.INVALID_REFERENCE
        assert reference.secret_ref_id == invalid.secret_ref_id


def test_backend_exception_is_mapped_to_bounded_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    broker = CredentialBroker.for_tests()
    canary = "SYNTHETIC_CREDENTIAL_CANARY_DO_NOT_LOG"

    def explode(_backend: InMemoryTestBackend, _reference: SecretRef) -> object:
        raise RuntimeError(f"internal error contained {canary}")

    monkeypatch.setattr(InMemoryTestBackend, "status", explode)
    with pytest.raises(CredentialBrokerError) as caught:
        broker.status(make_reference())
    assert caught.value.code == CredentialFailureCode.BACKEND_FAILURE
    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)


def test_hostile_object_string_methods_are_not_used() -> None:
    class Hostile:
        called = False

        def __str__(self) -> str:
            self.called = True
            return "SYNTHETIC_SECRET_CANARY"

        def __repr__(self) -> str:
            self.called = True
            return "SYNTHETIC_SECRET_CANARY"

    hostile = Hostile()
    with pytest.raises(CredentialBrokerError):
        CredentialBroker.for_tests().status(hostile)  # type: ignore[arg-type]
    assert hostile.called is False


def test_unchecked_reference_with_hostile_field_is_revalidated_without_stringifying() -> None:
    class Hostile:
        called = False

        def __str__(self) -> str:
            self.called = True
            return "SYNTHETIC_SECRET_CANARY"

        def __repr__(self) -> str:
            self.called = True
            return "SYNTHETIC_SECRET_CANARY"

    hostile = Hostile()
    unchecked = SecretRef.model_construct(
        secret_ref_id="secret.synthetic.primary",
        provider=hostile,
        keychain_locator="sentinel:gmail/primary",
        scope_manifest_sha256="a" * 64,
        os_owner_binding="windows-owner:synthetic",
        created_at=datetime(2026, 11, 2, tzinfo=UTC),
        revoked_at=None,
    )

    with pytest.raises(CredentialBrokerError) as caught:
        CredentialBroker.for_tests().status(unchecked)
    assert caught.value.code == CredentialFailureCode.INVALID_REFERENCE
    assert hostile.called is False


def test_approved_flag_is_not_a_credential_authority() -> None:
    broker = CredentialBroker.for_tests()
    reference = make_reference()
    broker.put_for_test(reference, b"synthetic")

    with pytest.raises(TypeError):
        broker.resolve_for_test(reference, approved=True)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        broker.resolve_for_test(reference, caller="owner")  # type: ignore[call-arg]
