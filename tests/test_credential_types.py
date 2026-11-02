from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from sentinel.credentials.types import SecretRef


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


def test_valid_reference_metadata_is_immutable_and_normalized_to_utc() -> None:
    reference = make_reference()

    assert reference.secret_ref_id == "secret.synthetic.primary"
    assert reference.provider == "gmail"
    assert reference.created_at == datetime(2026, 11, 2, 6, 30, tzinfo=UTC)
    assert "sentinel:gmail/primary" not in repr(reference)
    assert "windows-owner:synthetic" not in repr(reference)
    with pytest.raises((AttributeError, TypeError, ValueError)):
        reference.provider = "github"  # type: ignore[misc]

    restored = SecretRef.model_validate_json(reference.model_dump_json())
    assert restored == reference

    revoked = make_reference(
        revoked_at=datetime(2026, 11, 2, 12, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    )
    assert revoked.revoked_at == datetime(2026, 11, 2, 6, 30, tzinfo=UTC)


def test_reference_fields_match_the_blueprint_secret_refs_record() -> None:
    assert set(SecretRef.model_fields) == {
        "secret_ref_id",
        "provider",
        "keychain_locator",
        "scope_manifest_sha256",
        "os_owner_binding",
        "created_at",
        "revoked_at",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("secret_ref_id", "../secret"),
        ("provider", "Bad Provider"),
        ("keychain_locator", "https://example.invalid/token"),
        ("scope_manifest_sha256", "not-a-sha256"),
        ("os_owner_binding", "owner\nforged"),
        ("created_at", datetime(2026, 11, 2, 12)),
    ],
)
def test_invalid_reference_identifiers_hashes_and_timestamps_fail(
    field: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        make_reference(**{field: value})


def test_revocation_timestamp_cannot_precede_creation() -> None:
    with pytest.raises(ValidationError):
        make_reference(revoked_at=datetime(2026, 11, 1, tzinfo=UTC))


def test_unknown_raw_credential_fields_are_rejected_without_echoing_value() -> None:
    canary = "SYNTHETIC_CREDENTIAL_CANARY_DO_NOT_LOG"

    with pytest.raises(ValidationError) as caught:
        make_reference(access_token=canary)

    assert canary not in str(caught.value)
    assert canary not in repr(caught.value)


def test_reference_json_contains_metadata_but_no_secret_value() -> None:
    canary = "SYNTHETIC_CREDENTIAL_CANARY_DO_NOT_LOG"
    reference = make_reference()

    assert canary not in reference.model_dump_json()
    assert "keychain_locator" in reference.model_dump_json()


def test_missing_required_reference_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        SecretRef(secret_ref_id="secret.synthetic.primary")
