"""Bounded synthetic proposal previews and pending-record persistence."""

from sentinel.proposals.persistence import (
    ProposalPersistenceError,
    ProposalPersistenceErrorCode,
    list_github_fixture_proposals,
    save_github_fixture_proposal,
)
from sentinel.proposals.persistence_types import (
    ProposalListReport,
    ProposalSaveReport,
    SyntheticPendingProposal,
)
from sentinel.proposals.preview import (
    ProposalPreviewError,
    ProposalPreviewErrorCode,
    build_github_issue_proposal_preview,
)
from sentinel.proposals.types import SyntheticProposalPreview

__all__ = [
    "ProposalPreviewError",
    "ProposalPreviewErrorCode",
    "ProposalPersistenceError",
    "ProposalPersistenceErrorCode",
    "ProposalListReport",
    "ProposalSaveReport",
    "SyntheticPendingProposal",
    "SyntheticProposalPreview",
    "build_github_issue_proposal_preview",
    "list_github_fixture_proposals",
    "save_github_fixture_proposal",
]
