"""Strict metadata-only contract for one synthetic source review preview."""

from __future__ import annotations

import hashlib
import hmac
import json
import weakref
from dataclasses import dataclass
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    StrictInt,
    StrictStr,
    StringConstraints,
    model_validator,
)

from sentinel.contracts import SensitivityLabel, TrustLabel
from sentinel.policy.types import Capability, PolicyRuleId

_SHA256 = Annotated[
    StrictStr,
    StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64),
]
_ProviderItemId = Annotated[
    StrictStr,
    StringConstraints(
        strict=True,
        pattern=r"^example-owner/fixture-project#(?:101|102|103)$",
        max_length=40,
    ),
]
_PREVIEW_ATTESTATION_DOMAIN = b"sentinel.synthetic-proposal-preview.attestation.v1\x00"
_PREVIEW_ATTESTATION_SEAL = object()


@dataclass(frozen=True, eq=False)
class _PreviewAttestation:
    """Internal marker excluded from value equality; identity is checked explicitly."""

    seal: object
    instance_ref: weakref.ReferenceType[SyntheticProposalPreview]
    payload_sha256: str

    def __eq__(self, other: object) -> bool:
        # Pydantic compares private attributes during model equality. Comparing weakrefs
        # normally delegates to referent equality, which recursively compares this model.
        return type(other) is _PreviewAttestation


class SyntheticProposalPreview(BaseModel):
    """Immutable preview metadata; source body, authority and execution are absent."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
        hide_input_in_errors=True,
    )
    _verification_attestation: object = PrivateAttr(default=None)

    schema_version: Literal["sentinel.synthetic-proposal-preview.v1"] = (
        "sentinel.synthetic-proposal-preview.v1"
    )
    synthetic_data: Literal[True] = True
    preview_id: _SHA256
    proposal_kind: Literal["REVIEW_SOURCE"] = "REVIEW_SOURCE"
    proposal_title: Annotated[StrictStr, Field(min_length=1, max_length=80)]
    issue_number: Annotated[StrictInt, Field(ge=101, le=103)]
    source_item_id: UUID
    source_envelope_id: UUID
    provider_item_id: _ProviderItemId
    source_content_sha256: _SHA256
    source_binding_sha256: _SHA256
    evidence_span_ids: Annotated[tuple[UUID, ...], Field(min_length=1, max_length=5)]
    source_trust: TrustLabel
    source_sensitivity: SensitivityLabel
    derived_trust: TrustLabel
    derived_sensitivity: SensitivityLabel
    proposed_capability: Capability
    policy_rule_id: PolicyRuleId
    policy_request_sha256: _SHA256
    policy_sha256: _SHA256
    registry_sha256: _SHA256
    status: Literal["PREVIEW_ONLY"] = "PREVIEW_ONLY"
    disclaimer: Literal[
        "Possible review only; not an actual task assignment; not an accepted task, "
        "persisted proposal, approval, or grant."
    ] = (
        "Possible review only; not an actual task assignment; not an accepted task, "
        "persisted proposal, approval, or grant."
    )
    executable: Literal[False] = False

    @model_validator(mode="after")
    def enforce_closed_preview_contract(self) -> SyntheticProposalPreview:
        if (
            self.provider_item_id != f"example-owner/fixture-project#{self.issue_number}"
            or self.proposal_title != f"Review synthetic GitHub issue #{self.issue_number}"
            or self.source_trust is not TrustLabel.T4_EXTERNAL
            or self.source_sensitivity is not SensitivityLabel.PUBLIC
            or self.derived_trust is not TrustLabel.T3_DERIVED
            or self.derived_sensitivity is not SensitivityLabel.PUBLIC
            or self.proposed_capability is not Capability.C2_WRITE_LOCAL_PROPOSAL
            or self.policy_rule_id is not PolicyRuleId.P06
            or self.executable is not False
            or len(self.evidence_span_ids) != len(set(self.evidence_span_ids))
        ):
            raise ValueError("preview does not match the fixed synthetic review contract")
        return self


def _canonical_validated_payload(
    preview: SyntheticProposalPreview,
) -> tuple[bytes, SyntheticProposalPreview]:
    """Return canonical bytes for a strict snapshot of the complete public schema."""
    raw = preview.model_dump(mode="python")
    validated = SyntheticProposalPreview.model_validate(raw, strict=True)
    canonical = json.dumps(
        validated.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")
    return canonical, validated


def _preview_attestation_digest(canonical_payload: bytes) -> str:
    return hashlib.sha256(_PREVIEW_ATTESTATION_DOMAIN + canonical_payload).hexdigest()


def _mark_verified_preview(preview: SyntheticProposalPreview) -> SyntheticProposalPreview:
    """Attest the exact fully validated instance after the trusted P06 path."""
    if type(preview) is not SyntheticProposalPreview:
        raise TypeError("verified preview requires the registered preview type")
    canonical_payload, _ = _canonical_validated_payload(preview)
    preview._verification_attestation = _PreviewAttestation(
        seal=_PREVIEW_ATTESTATION_SEAL,
        instance_ref=weakref.ref(preview),
        payload_sha256=_preview_attestation_digest(canonical_payload),
    )
    return preview


def _verified_preview_snapshot(value: object) -> SyntheticProposalPreview | None:
    """Return a strict rendering snapshot only for an unchanged attested instance."""
    if type(value) is not SyntheticProposalPreview:
        return None
    try:
        attestation = value._verification_attestation
        if type(attestation) is not _PreviewAttestation:
            return None
        if (
            attestation.seal is not _PREVIEW_ATTESTATION_SEAL
            or type(attestation.instance_ref) is not weakref.ReferenceType
            or attestation.instance_ref() is not value
            or type(attestation.payload_sha256) is not str
        ):
            return None
        canonical_payload, validated = _canonical_validated_payload(value)
        actual_digest = _preview_attestation_digest(canonical_payload)
        if not hmac.compare_digest(actual_digest, attestation.payload_sha256):
            return None
        return validated
    except Exception:
        return None


__all__ = ["SyntheticProposalPreview"]
