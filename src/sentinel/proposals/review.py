"""Read-only validation of one persisted synthetic pending proposal."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import NoReturn

from sentinel.policy.source_binding import (
    PublicReadBindingError,
    PublicSourceBinding,
    VerifiedGithubPublicRead,
    resolve_github_fixture_public_read,
    validate_verified_github_public_read,
)
from sentinel.proposals.persistence import (
    ProposalPersistenceError,
    ProposalPersistenceErrorCode,
    get_github_fixture_proposal,
)
from sentinel.proposals.persistence_types import SyntheticPendingProposal
from sentinel.proposals.review_types import (
    ProposalReviewCheck,
    ProposalReviewReadiness,
    ProposalReviewReason,
)

_PROPOSAL_ID_LENGTH = 64


class ProposalReviewErrorCode(StrEnum):
    INVALID_ID = "invalid_id"
    NOT_FOUND = "not_found"
    SOURCE_UNAVAILABLE = "source_unavailable"
    RECORD_INVALID = "record_invalid"
    DATABASE_UNAVAILABLE = "database_unavailable"
    CHECK_FAILED = "check_failed"


_ERROR_MESSAGES = {
    ProposalReviewErrorCode.INVALID_ID: "A valid explicit proposal ID is required.",
    ProposalReviewErrorCode.NOT_FOUND: "The selected pending proposal was not found.",
    ProposalReviewErrorCode.SOURCE_UNAVAILABLE: (
        "Current verified synthetic source evidence is unavailable."
    ),
    ProposalReviewErrorCode.RECORD_INVALID: "Stored pending proposal metadata is invalid.",
    ProposalReviewErrorCode.DATABASE_UNAVAILABLE: "The selected database is unavailable.",
    ProposalReviewErrorCode.CHECK_FAILED: "The proposal review check could not be completed.",
}


class ProposalReviewError(RuntimeError):
    """Registered path-free failure for review-check operations."""

    def __init__(self, code: ProposalReviewErrorCode) -> None:
        if type(code) is not ProposalReviewErrorCode:
            raise TypeError("proposal review error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


def _utc_now() -> datetime:
    """One replaceable internal seam for deterministic boundary tests."""
    return datetime.now(UTC)


def _valid_proposal_id(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == _PROPOSAL_ID_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _raise_persistence_error(error: ProposalPersistenceError) -> NoReturn:
    mapping = {
        ProposalPersistenceErrorCode.NOT_FOUND: ProposalReviewErrorCode.NOT_FOUND,
        ProposalPersistenceErrorCode.SOURCE_UNAVAILABLE: (
            ProposalReviewErrorCode.SOURCE_UNAVAILABLE
        ),
        ProposalPersistenceErrorCode.DATABASE_UNAVAILABLE: (
            ProposalReviewErrorCode.DATABASE_UNAVAILABLE
        ),
    }
    code = mapping.get(error.code, ProposalReviewErrorCode.RECORD_INVALID)
    raise ProposalReviewError(code) from None


def _read_proposal(database: str | Path, proposal_id: str) -> SyntheticPendingProposal:
    try:
        proposal = get_github_fixture_proposal(database, proposal_id=proposal_id)
        if type(proposal) is not SyntheticPendingProposal:
            raise ProposalReviewError(ProposalReviewErrorCode.RECORD_INVALID)
        validated = SyntheticPendingProposal.model_validate(
            proposal.model_dump(mode="python"), strict=True
        )
        if validated != proposal:
            raise ProposalReviewError(ProposalReviewErrorCode.RECORD_INVALID)
        return validated
    except ProposalPersistenceError as error:
        _raise_persistence_error(error)
    except ProposalReviewError:
        raise
    except Exception:
        raise ProposalReviewError(ProposalReviewErrorCode.RECORD_INVALID) from None


def _resolve_current_source(
    database: str | Path,
    store_root: str | Path,
) -> VerifiedGithubPublicRead:
    try:
        verified = resolve_github_fixture_public_read(database, store_root=store_root)
        if (
            type(verified) is not VerifiedGithubPublicRead
            or not validate_verified_github_public_read(verified)
        ):
            raise ProposalReviewError(ProposalReviewErrorCode.SOURCE_UNAVAILABLE)
        return verified
    except ProposalReviewError:
        raise
    except PublicReadBindingError:
        raise ProposalReviewError(ProposalReviewErrorCode.SOURCE_UNAVAILABLE) from None
    except Exception:
        raise ProposalReviewError(ProposalReviewErrorCode.SOURCE_UNAVAILABLE) from None


def _require_source_match(
    proposal: SyntheticPendingProposal,
    verified: VerifiedGithubPublicRead,
) -> PublicSourceBinding:
    binding = verified.binding
    if (
        len(binding.sources) != 3
        or binding.source_set_sha256 != proposal.source_binding_sha256
        or binding.manifest_sha256 != proposal.source_manifest_sha256
    ):
        raise ProposalReviewError(ProposalReviewErrorCode.SOURCE_UNAVAILABLE)
    matches = tuple(
        item for item in binding.sources if item.item_id == proposal.source_item_id
    )
    if len(matches) != 1:
        raise ProposalReviewError(ProposalReviewErrorCode.SOURCE_UNAVAILABLE)
    source = matches[0]
    if (
        source.source_id != proposal.source_envelope_id
        or source.content_sha256 != proposal.source_content_sha256
        or source.trust is not proposal.source_trust
        or source.sensitivity is not proposal.source_sensitivity
        or tuple(citation.span_id for citation in source.citations)
        != proposal.evidence_span_ids
    ):
        raise ProposalReviewError(ProposalReviewErrorCode.SOURCE_UNAVAILABLE)

    evidence_matches = tuple(
        item
        for item in verified.evidence.items
        if item.item_id == proposal.source_item_id
    )
    if len(evidence_matches) != 1:
        raise ProposalReviewError(ProposalReviewErrorCode.SOURCE_UNAVAILABLE)
    evidence = evidence_matches[0]
    if (
        evidence.source_envelope_id != proposal.source_envelope_id
        or evidence.content_sha256 != proposal.source_content_sha256
        or tuple(citation.span_id for citation in evidence.citations)
        != proposal.evidence_span_ids
    ):
        raise ProposalReviewError(ProposalReviewErrorCode.SOURCE_UNAVAILABLE)
    return source


def _capture_checked_at() -> datetime:
    try:
        value = _utc_now()
        if not isinstance(value, datetime):
            raise ValueError
        offset = value.utcoffset()
        if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
            raise ValueError
        return value.astimezone(UTC)
    except Exception:
        raise ProposalReviewError(ProposalReviewErrorCode.CHECK_FAILED) from None


def check_github_fixture_proposal(
    database: str | Path,
    *,
    store_root: str | Path,
    proposal_id: str,
) -> ProposalReviewCheck:
    """Validate saved lineage, current fixture bytes and expiry without mutation."""
    if not _valid_proposal_id(proposal_id):
        raise ProposalReviewError(ProposalReviewErrorCode.INVALID_ID)
    try:
        stored = _read_proposal(database, proposal_id)
        first_read = _resolve_current_source(database, store_root)
        _require_source_match(stored, first_read)

        # Detect ordinary record/source replacement during the check. These are
        # separate read-only validations; they are not an atomic filesystem snapshot.
        if _read_proposal(database, proposal_id) != stored:
            raise ProposalReviewError(ProposalReviewErrorCode.RECORD_INVALID)
        second_read = _resolve_current_source(database, store_root)
        source = _require_source_match(stored, second_read)
        if second_read.binding.source_set_sha256 != first_read.binding.source_set_sha256:
            raise ProposalReviewError(ProposalReviewErrorCode.SOURCE_UNAVAILABLE)

        checked_at = _capture_checked_at()
        expired = checked_at >= stored.expires_at
        return ProposalReviewCheck(
            proposal_id=stored.proposal_id,
            stored_status=stored.status,
            review_readiness=(
                ProposalReviewReadiness.EXPIRED
                if expired
                else ProposalReviewReadiness.READY_FOR_OWNER_REVIEW
            ),
            source_binding_sha256=second_read.binding.source_set_sha256,
            source_item_id=source.item_id,
            source_content_sha256=source.content_sha256,
            evidence_span_count=len(source.citations),
            created_at=stored.created_at,
            expires_at=stored.expires_at,
            checked_at=checked_at,
            reason_code=(
                ProposalReviewReason.EXPIRY_REACHED
                if expired
                else ProposalReviewReason.CURRENT_SOURCE_MATCHED
            ),
            owner_verified=False,
            executable=False,
        )
    except ProposalReviewError:
        raise
    except Exception:
        raise ProposalReviewError(ProposalReviewErrorCode.CHECK_FAILED) from None


__all__ = [
    "ProposalReviewError",
    "ProposalReviewErrorCode",
    "check_github_fixture_proposal",
]
