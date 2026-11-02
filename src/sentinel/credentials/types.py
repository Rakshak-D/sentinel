"""Strict credential reference and status types without secret values."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

SecretReferenceId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9._:-]*$"),
]
ProviderIdentifier = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_.-]*$"),
]
KeychainLocator = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=10,
        max_length=255,
        pattern=r"^sentinel:[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    ),
]
ScopeManifestSha256 = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
]
OwnerBindingReference = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
    ),
]


class SecretReferenceValidationError(ValueError):
    """Safe validation failure with no echoed metadata values."""

    def __str__(self) -> str:
        return "Secret reference metadata is invalid."


class CredentialFailureCode(StrEnum):
    """Bounded failure categories; values never contain backend exception text."""

    INVALID_REFERENCE = "invalid_reference"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    REFERENCE_MISSING = "reference_missing"
    REFERENCE_REVOKED = "reference_revoked"
    REGISTRATION_CONFLICT = "registration_conflict"
    OPERATION_UNAVAILABLE = "operation_unavailable"
    INVALID_SYNTHETIC_CREDENTIAL = "invalid_synthetic_credential"
    BACKEND_FAILURE = "backend_failure"


_FAILURE_MESSAGES: dict[CredentialFailureCode, str] = {
    CredentialFailureCode.INVALID_REFERENCE: "Credential reference is invalid.",
    CredentialFailureCode.BACKEND_UNAVAILABLE: "Credential backend is unavailable.",
    CredentialFailureCode.REFERENCE_MISSING: "Credential reference is missing.",
    CredentialFailureCode.REFERENCE_REVOKED: "Credential reference is revoked.",
    CredentialFailureCode.REGISTRATION_CONFLICT: "Synthetic reference registration conflicts.",
    CredentialFailureCode.OPERATION_UNAVAILABLE: "Credential operation is unavailable.",
    CredentialFailureCode.INVALID_SYNTHETIC_CREDENTIAL: "Synthetic credential input is invalid.",
    CredentialFailureCode.BACKEND_FAILURE: "Credential backend operation failed.",
}


class CredentialBrokerError(RuntimeError):
    """Public broker failure with a stable code and a fixed non-sensitive message."""

    def __init__(self, code: CredentialFailureCode) -> None:
        safe_code = (
            code
            if type(code) is CredentialFailureCode
            else CredentialFailureCode.BACKEND_FAILURE
        )
        self.code = safe_code
        super().__init__(_FAILURE_MESSAGES[safe_code])


class BackendAvailability(StrEnum):
    """Whether a broker backend is configured and can answer reference queries."""

    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class SecretReferenceState(StrEnum):
    """Reference existence state, separate from backend availability."""

    UNKNOWN = "UNKNOWN"
    MISSING = "MISSING"
    PRESENT = "PRESENT"
    REVOKED = "REVOKED"


class _FrozenCredentialModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        hide_input_in_errors=True,
    )


class SecretRef(_FrozenCredentialModel):
    """Normative §10 secret-reference metadata; it never contains secret bytes.

    The keychain locator and OS owner binding are opaque references. They are
    excluded from the object's repr and are not part of model/tool/diagnostic DTOs.
    """

    secret_ref_id: SecretReferenceId
    provider: ProviderIdentifier
    keychain_locator: KeychainLocator = Field(repr=False)
    scope_manifest_sha256: ScopeManifestSha256
    os_owner_binding: OwnerBindingReference = Field(repr=False)
    created_at: AwareDatetime
    revoked_at: AwareDatetime | None = None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Self:
        try:
            return super().model_validate(obj, **kwargs)
        except (ValidationError, TypeError, ValueError):
            raise SecretReferenceValidationError() from None

    @classmethod
    def model_validate_json(
        cls, json_data: str | bytes | bytearray, **kwargs: Any
    ) -> Self:
        try:
            return super().model_validate_json(json_data, **kwargs)
        except (ValidationError, TypeError, ValueError):
            raise SecretReferenceValidationError() from None

    @field_validator("created_at", "revoked_at")
    @classmethod
    def normalize_timestamp_to_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_revocation_order(self) -> SecretRef:
        if self.revoked_at is not None and self.revoked_at < self.created_at:
            raise ValueError("revocation must not precede creation")
        return self


class CredentialStatus(_FrozenCredentialModel):
    """Safe status only; it contains no locator, owner identity, or secret value."""

    backend: BackendAvailability
    reference: SecretReferenceState


def validate_secret_ref(value: object) -> SecretRef:
    """Revalidate exact references and mappings without exposing Pydantic errors."""

    if type(value) is SecretRef:
        raw_value: object = dict(value.__dict__)
    elif type(value) is dict:
        raw_value = value
    else:
        raise CredentialBrokerError(CredentialFailureCode.INVALID_REFERENCE)
    try:
        return SecretRef.model_validate(raw_value)
    except SecretReferenceValidationError:
        raise CredentialBrokerError(CredentialFailureCode.INVALID_REFERENCE) from None
