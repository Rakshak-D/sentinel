"""Immutable, bounded data contracts for synthetic WebAuthn verification."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    StringConstraints,
    field_validator,
    model_validator,
)


class OwnerProofErrorCode(StrEnum):
    INVALID_INPUT = "invalid_input"
    SCHEMA_UNAVAILABLE = "schema_unavailable"
    DATABASE_UNAVAILABLE = "database_unavailable"
    PROPOSAL_UNAVAILABLE = "proposal_unavailable"
    CREDENTIAL_UNAVAILABLE = "credential_unavailable"
    CHALLENGE_UNAVAILABLE = "challenge_unavailable"
    ASSERTION_REJECTED = "assertion_rejected"
    REPLAY_REJECTED = "replay_rejected"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    OPERATION_FAILED = "operation_failed"


_ERROR_TEXT = {
    OwnerProofErrorCode.INVALID_INPUT: "The authentication input is invalid.",
    OwnerProofErrorCode.SCHEMA_UNAVAILABLE: "The current owner-proof schema is unavailable.",
    OwnerProofErrorCode.DATABASE_UNAVAILABLE: (
        "The selected authentication database is unavailable."
    ),
    OwnerProofErrorCode.PROPOSAL_UNAVAILABLE: "The selected pending proposal is unavailable.",
    OwnerProofErrorCode.CREDENTIAL_UNAVAILABLE: (
        "No eligible synthetic test credential is available."
    ),
    OwnerProofErrorCode.CHALLENGE_UNAVAILABLE: (
        "The selected authentication challenge is unavailable."
    ),
    OwnerProofErrorCode.ASSERTION_REJECTED: "The synthetic assertion was rejected.",
    OwnerProofErrorCode.REPLAY_REJECTED: "The challenge has already been consumed.",
    OwnerProofErrorCode.DEPENDENCY_UNAVAILABLE: "The optional WebAuthn verifier is unavailable.",
    OwnerProofErrorCode.OPERATION_FAILED: "The owner-proof operation could not be completed.",
}


class OwnerProofError(RuntimeError):
    """Registered failure categories; no path, assertion or key material is retained."""

    def __init__(self, code: OwnerProofErrorCode) -> None:
        if type(code) is not OwnerProofErrorCode:
            raise TypeError("owner-proof error code must be registered")
        self.code = code
        super().__init__(_ERROR_TEXT[code])


class _FrozenModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
        hide_input_in_errors=True,
    )


_CHALLENGE_ID = Annotated[
    StrictStr,
    StringConstraints(strict=True, pattern=r"^[0-9a-f]{32}$", max_length=32),
]


class AuthenticationChallengeOptions(_FrozenModel):
    """Synthetic-only server options; options JSON is hidden from repr."""

    schema_version: Literal["sentinel.owner-proof-options.v1"] = "sentinel.owner-proof-options.v1"
    challenge_id: _CHALLENGE_ID
    options_json: Annotated[StrictStr, Field(min_length=2, max_length=8192, repr=False)]
    credential_classification: Literal["SYNTHETIC_TEST_ONLY"] = "SYNTHETIC_TEST_ONLY"
    owner_verified: Literal[False] = False
    executable: Literal[False] = False


class OwnerProofChallenge(_FrozenModel):
    """Immutable challenge binding; contains metadata and challenge bytes only."""

    schema_version: Literal["sentinel.owner-proof-challenge.v1"] = (
        "sentinel.owner-proof-challenge.v1"
    )
    challenge_id: _CHALLENGE_ID
    challenge_b64url: Annotated[
        StrictStr,
        StringConstraints(strict=True, pattern=r"^[A-Za-z0-9_-]{43}$", max_length=43),
        Field(repr=False),
    ]
    proposal_id: Annotated[
        StrictStr, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64)
    ]
    proposal_snapshot_sha256: Annotated[
        StrictStr, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64)
    ]
    fixture_sha256: Annotated[
        StrictStr, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64)
    ]
    manifest_sha256: Annotated[
        StrictStr, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64)
    ]
    source_set_sha256: Annotated[
        StrictStr, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64)
    ]
    source_item_id: UUID
    source_envelope_id: UUID
    source_content_sha256: Annotated[
        StrictStr, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64)
    ]
    citation_bindings_json: Annotated[StrictStr, Field(min_length=2, max_length=4096, repr=False)]
    citation_bindings_sha256: Annotated[
        StrictStr, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64)
    ]
    policy_request_sha256: Annotated[
        StrictStr, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64)
    ]
    policy_sha256: Annotated[
        StrictStr, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64)
    ]
    registry_sha256: Annotated[
        StrictStr, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64)
    ]
    config_sha256: Annotated[
        StrictStr, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64)
    ]
    credential_id: Annotated[
        StrictStr, StringConstraints(strict=True, min_length=1, max_length=684)
    ]
    owner_association: Literal["synthetic-test-owner"]
    rp_id: Literal["sentinel.test"]
    expected_origin: Literal["https://sentinel.test"]
    created_at: datetime
    expires_at: datetime
    purpose: Literal["sentinel.pending-proposal-review.webauthn-get.v1"]
    scope: Literal["SYNTHETIC_TEST_ONLY_NON_EXECUTABLE"]

    @field_validator("created_at", "expires_at")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        offset = value.utcoffset()
        if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
            raise ValueError("owner-proof timestamps must be aware UTC values")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_valid_window(self) -> OwnerProofChallenge:
        if self.expires_at <= self.created_at:
            raise ValueError("owner-proof challenge expiry must follow creation")
        return self

    def __repr__(self) -> str:
        return "OwnerProofChallenge(<challenge material omitted>)"


class SyntheticAssertionVerification(_FrozenModel):
    """Cryptographic result; deliberately never denotes owner authority."""

    schema_version: Literal["sentinel.owner-proof-verification.v1"] = (
        "sentinel.owner-proof-verification.v1"
    )
    outcome: Literal["SYNTHETIC_ASSERTION_VERIFIED"] = "SYNTHETIC_ASSERTION_VERIFIED"
    challenge_id: _CHALLENGE_ID
    new_sign_count: Annotated[StrictInt, Field(ge=0, le=4_294_967_295)]
    credential_classification: Literal["SYNTHETIC_TEST_ONLY"] = "SYNTHETIC_TEST_ONLY"
    owner_verified: Literal[False] = False
    executable: Literal[False] = False


class OwnerProofStatus(_FrozenModel):
    """Read-only status whose production owner-verification state is always unavailable."""

    schema_version: Literal["sentinel.owner-proof-status.v1"] = "sentinel.owner-proof-status.v1"
    backend_state: Literal["AVAILABLE", "MISSING_DEPENDENCY"]
    schema_state: Literal["CURRENT", "MIGRATION_REQUIRED"]
    credential_state: Literal["NO_PROTECTED_ENROLLMENT", "SYNTHETIC_TEST_ONLY"]
    synthetic_test_credentials: Annotated[StrictInt, Field(ge=0, le=1000)]
    production_owner_verification: Literal["UNAVAILABLE"] = "UNAVAILABLE"
    owner_verified: Literal[False] = False
    executable: Literal[False] = False


__all__ = [
    "AuthenticationChallengeOptions",
    "OwnerProofChallenge",
    "OwnerProofError",
    "OwnerProofErrorCode",
    "OwnerProofStatus",
    "SyntheticAssertionVerification",
]
