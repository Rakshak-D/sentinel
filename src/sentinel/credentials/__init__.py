"""Credential reference and fail-closed broker contracts.

Production construction exposes reference status only. Synthetic values are
available only through the explicitly test-named in-memory construction path.
"""

from sentinel.credentials.backends import SyntheticCredentialAccess
from sentinel.credentials.broker import CredentialBroker
from sentinel.credentials.types import (
    BackendAvailability,
    CredentialBrokerError,
    CredentialFailureCode,
    CredentialStatus,
    KeychainLocator,
    OwnerBindingReference,
    ProviderIdentifier,
    ScopeManifestSha256,
    SecretRef,
    SecretReferenceId,
    SecretReferenceState,
    SecretReferenceValidationError,
    validate_secret_ref,
)

__all__ = [
    "BackendAvailability",
    "CredentialBroker",
    "CredentialBrokerError",
    "CredentialFailureCode",
    "CredentialStatus",
    "KeychainLocator",
    "OwnerBindingReference",
    "ProviderIdentifier",
    "ScopeManifestSha256",
    "SecretReferenceId",
    "SecretReferenceState",
    "SecretReferenceValidationError",
    "SecretRef",
    "SyntheticCredentialAccess",
    "validate_secret_ref",
]
