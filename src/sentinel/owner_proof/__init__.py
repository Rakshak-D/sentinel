"""Synthetic-only durable WebAuthn challenge verification foundation."""

from sentinel.owner_proof.formatters import (
    format_json_owner_proof_status,
    format_text_owner_proof_status,
)
from sentinel.owner_proof.service import (
    build_owner_proof_status,
    issue_synthetic_assertion_options,
    verify_synthetic_assertion,
)
from sentinel.owner_proof.types import (
    AuthenticationChallengeOptions,
    OwnerProofChallenge,
    OwnerProofError,
    OwnerProofErrorCode,
    OwnerProofStatus,
    SyntheticAssertionVerification,
)

__all__ = [
    "AuthenticationChallengeOptions",
    "OwnerProofChallenge",
    "OwnerProofError",
    "OwnerProofErrorCode",
    "OwnerProofStatus",
    "SyntheticAssertionVerification",
    "build_owner_proof_status",
    "format_json_owner_proof_status",
    "format_text_owner_proof_status",
    "issue_synthetic_assertion_options",
    "verify_synthetic_assertion",
]
