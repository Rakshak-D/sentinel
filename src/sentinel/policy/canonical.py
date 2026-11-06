"""Versioned deterministic serialization and domain-separated policy digests."""

from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel

from sentinel.policy.registry import (
    BUILTIN_REGISTRY,
    POLICY_ID,
    POLICY_RULES,
    POLICY_VERSION,
    UNIMPLEMENTED_RULE_IDS,
    CapabilityRegistry,
)
from sentinel.policy.types import (
    CapabilityRegistration,
    PolicyDecision,
    PolicyRequest,
    PolicyStatusReport,
)


def _json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")


def _validated_dump(value: object, model_type: type[BaseModel]) -> dict[str, object]:
    if type(value) is not model_type:
        raise TypeError("policy canonicalization accepts only exact validated policy DTOs")
    instance = value
    raw = instance.model_dump(mode="python")
    validated = model_type.model_validate(raw, strict=True)
    return validated.model_dump(mode="json")


def canonical_policy_bytes(value: object) -> bytes:
    """Serialize one exact supported policy DTO to sorted compact UTF-8 JSON."""
    supported: tuple[type[BaseModel], ...] = (
        PolicyRequest,
        CapabilityRegistry,
        CapabilityRegistration,
        PolicyDecision,
        PolicyStatusReport,
    )
    if type(value) not in supported:
        raise TypeError("policy canonicalization accepts only registered policy DTO types")
    model_type = type(value)
    if not issubclass(model_type, BaseModel):
        raise TypeError("policy canonicalization accepts only registered policy DTO types")
    return _json_bytes(_validated_dump(value, model_type))


def _domain_sha256(domain: str, payload: bytes) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\x00" + payload).hexdigest()


def request_sha256(request: PolicyRequest) -> str:
    """Hash v2 request metadata, including the source-binding identity."""
    return _domain_sha256("sentinel.policy.request.v2", canonical_policy_bytes(request))


def registration_sha256(registration: CapabilityRegistration) -> str:
    """Identify one exact passive registration; this is not a signature."""
    return _domain_sha256(
        "sentinel.capability-registration.v1", canonical_policy_bytes(registration)
    )


def registry_sha256(registry: CapabilityRegistry) -> str:
    """Hash exact canonical registry bytes under the registry domain."""
    return _domain_sha256("sentinel.capability-registry.v1", canonical_policy_bytes(registry))


def policy_sha256() -> str:
    """Hash the CR2-C rule manifest; this identifies metadata, not code trust."""
    manifest = {
        "schema_version": "sentinel.policy-manifest.v3",
        "policy_id": POLICY_ID,
        "policy_version": POLICY_VERSION,
        "ordered_rules": [rule.model_dump(mode="json") for rule in POLICY_RULES],
        "unimplemented_rules": list(UNIMPLEMENTED_RULE_IDS),
        "default_outcome": "DENY",
    }
    return _domain_sha256("sentinel.policy-manifest.v3", _json_bytes(manifest))


def builtin_registry_sha256() -> str:
    """Return the pinned hash of the application-defined static registry."""
    return registry_sha256(BUILTIN_REGISTRY)


__all__ = [
    "builtin_registry_sha256",
    "canonical_policy_bytes",
    "policy_sha256",
    "registration_sha256",
    "registry_sha256",
    "request_sha256",
]
