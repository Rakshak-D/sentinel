"""Immutable read-only review check metadata for pending proposals."""

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

_SHA256 = Annotated[
    StrictStr,
    StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$", max_length=64),
]


class ProposalReviewReadiness(StrEnum):
    READY_FOR_OWNER_REVIEW = "READY_FOR_OWNER_REVIEW"
    EXPIRED = "EXPIRED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    RECORD_INVALID = "RECORD_INVALID"


class ProposalReviewReason(StrEnum):
    CURRENT_SOURCE_MATCHED = "CURRENT_SOURCE_MATCHED"
    EXPIRY_REACHED = "EXPIRY_REACHED"


class ProposalReviewCheck(BaseModel):
    """Body-free report; readiness is not owner approval or execution authority."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
        hide_input_in_errors=True,
    )

    schema_version: Literal["sentinel.proposal-review-check.v1"] = (
        "sentinel.proposal-review-check.v1"
    )
    proposal_id: _SHA256
    stored_status: Literal["PENDING_REVIEW"]
    review_readiness: ProposalReviewReadiness
    source_binding_sha256: _SHA256
    source_item_id: UUID
    source_content_sha256: _SHA256
    evidence_span_count: Annotated[StrictInt, Field(ge=1, le=5)]
    created_at: datetime
    expires_at: datetime
    checked_at: datetime
    reason_code: ProposalReviewReason
    owner_verified: Literal[False] = False
    executable: Literal[False] = False

    @field_validator("created_at", "expires_at", "checked_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        offset = value.utcoffset()
        if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
            raise ValueError("proposal review timestamps must be aware UTC values")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_consistent_readiness(self) -> ProposalReviewCheck:
        if self.expires_at <= self.created_at:
            raise ValueError("proposal review expiry must follow creation")
        if self.review_readiness is ProposalReviewReadiness.READY_FOR_OWNER_REVIEW:
            if (
                self.checked_at >= self.expires_at
                or self.reason_code is not ProposalReviewReason.CURRENT_SOURCE_MATCHED
            ):
                raise ValueError("ready proposal review metadata is inconsistent")
        elif self.review_readiness is ProposalReviewReadiness.EXPIRED:
            if (
                self.checked_at < self.expires_at
                or self.reason_code is not ProposalReviewReason.EXPIRY_REACHED
            ):
                raise ValueError("expired proposal review metadata is inconsistent")
        else:
            raise ValueError("unavailable proposal review state cannot be formatted as a report")
        return self


__all__ = [
    "ProposalReviewCheck",
    "ProposalReviewReadiness",
    "ProposalReviewReason",
]
