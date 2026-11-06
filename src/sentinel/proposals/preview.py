"""Build one fixed in-memory review preview from verified fixture evidence."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path

import sentinel.policy.evaluator as policy_evaluator
from sentinel.contracts import SensitivityLabel, TrustLabel
from sentinel.policy import (
    Capability,
    PolicyDecision,
    PolicyOutcome,
    PolicyReasonCode,
    PolicyRequest,
    PolicyRuleId,
)
from sentinel.policy.canonical import request_sha256
from sentinel.policy.registry import BUILTIN_REGISTRY
from sentinel.policy.source_binding import (
    PublicSourceBinding,
    VerifiedGithubPublicRead,
    resolve_github_fixture_public_read,
    validate_verified_github_public_read,
)
from sentinel.proposals.types import SyntheticProposalPreview, _mark_verified_preview

_PREVIEW_ID_DOMAIN = b"sentinel.synthetic-proposal-preview.identity.v1\x00"
_PREVIEW_TEMPLATE_VERSION = "v1"
_ALLOWED_ISSUES = frozenset({101, 102, 103})


class ProposalPreviewErrorCode(StrEnum):
    INVALID_SELECTION = "invalid_selection"
    SOURCE_UNAVAILABLE = "source_unavailable"
    POLICY_DENIED = "policy_denied"
    PREVIEW_INVALID = "preview_invalid"


_ERROR_MESSAGES = {
    ProposalPreviewErrorCode.INVALID_SELECTION: "An explicit supported issue number is required.",
    ProposalPreviewErrorCode.SOURCE_UNAVAILABLE: "Verified synthetic source is unavailable.",
    ProposalPreviewErrorCode.POLICY_DENIED: "Synthetic proposal preview was denied.",
    ProposalPreviewErrorCode.PREVIEW_INVALID: "Synthetic proposal preview could not be verified.",
}


class ProposalPreviewError(RuntimeError):
    """Bounded preview failure with no source paths, body text or raw exception."""

    def __init__(self, code: ProposalPreviewErrorCode) -> None:
        if type(code) is not ProposalPreviewErrorCode:
            raise TypeError("preview error code must be registered")
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


def _preview_identity(
    *,
    selected: PublicSourceBinding,
    source_binding_sha256: str,
) -> str:
    payload = {
        "domain": "sentinel.synthetic-proposal-preview.identity.v1",
        "source_item_id": str(selected.item_id),
        "source_binding_sha256": source_binding_sha256,
        "proposal_kind": "REVIEW_SOURCE",
        "template_version": _PREVIEW_TEMPLATE_VERSION,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8", errors="strict")
    return hashlib.sha256(_PREVIEW_ID_DOMAIN + canonical).hexdigest()


def _selected_source(
    verified_read: VerifiedGithubPublicRead,
    issue_number: int,
) -> PublicSourceBinding:
    provider_item_id = f"example-owner/fixture-project#{issue_number}"
    binding_matches = tuple(
        source
        for source in verified_read.binding.sources
        if source.provider_item_id == provider_item_id
    )
    evidence_matches = tuple(
        item for item in verified_read.evidence.items if item.provider_item_id == provider_item_id
    )
    if len(binding_matches) != 1 or len(evidence_matches) != 1:
        raise ProposalPreviewError(ProposalPreviewErrorCode.SOURCE_UNAVAILABLE)
    source = binding_matches[0]
    item = evidence_matches[0]
    if (
        item.item_id != source.item_id
        or item.source_envelope_id != source.source_id
        or item.content_sha256 != source.content_sha256
        or item.trust is not TrustLabel.T4_EXTERNAL
        or item.sensitivity is not SensitivityLabel.PUBLIC
        or tuple(
            (citation.span_id, citation.start_byte, citation.end_byte, citation.text_sha256)
            for citation in item.citations
        )
        != tuple(
            (citation.span_id, citation.start_byte, citation.end_byte, citation.text_sha256)
            for citation in source.citations
        )
    ):
        raise ProposalPreviewError(ProposalPreviewErrorCode.SOURCE_UNAVAILABLE)
    return source


def _decision_matches(
    decision: object,
    *,
    request: PolicyRequest,
    selected: PublicSourceBinding,
    source_binding_sha256: str,
) -> bool:
    if type(decision) is not PolicyDecision:
        return False
    try:
        validated = PolicyDecision.model_validate(decision.model_dump(mode="python"), strict=True)
        expected_evidence_ids = (
            request.request_id,
            selected.source_id,
            *(citation.span_id for citation in selected.citations),
        )
        return (
            validated.outcome is PolicyOutcome.ALLOW
            and validated.rule_id is PolicyRuleId.P06
            and validated.reason_code is PolicyReasonCode.PROPOSAL_PREVIEW_ALLOWED
            and validated.executable is False
            and validated.request_sha256 == request_sha256(request)
            and validated.policy_sha256 == request.policy_sha256
            and validated.registry_sha256 == request.registry_sha256
            and validated.evidence_binding_sha256 == source_binding_sha256
            and validated.evidence_ids == expected_evidence_ids
        )
    except Exception:
        return False


def build_github_issue_proposal_preview(
    database: str | Path,
    *,
    store_root: str | Path,
    issue_number: int,
) -> SyntheticProposalPreview:
    """Resolve one verified snapshot, evaluate P09/P06 and return body-free metadata."""
    if type(issue_number) is not int or issue_number not in _ALLOWED_ISSUES:
        raise ProposalPreviewError(ProposalPreviewErrorCode.INVALID_SELECTION)
    try:
        verified_read = resolve_github_fixture_public_read(database, store_root=store_root)
        if type(
            verified_read
        ) is not VerifiedGithubPublicRead or not validate_verified_github_public_read(
            verified_read
        ):
            raise ProposalPreviewError(ProposalPreviewErrorCode.SOURCE_UNAVAILABLE)
        selected = _selected_source(verified_read, issue_number)
        request, context = policy_evaluator.build_verified_proposal_preview_policy_input(
            verified_read,
            issue_number=issue_number,
        )
        decision = policy_evaluator.evaluate_policy(
            request=request,
            context=context,
            registry=BUILTIN_REGISTRY,
            evidence_binding=verified_read,
        )
        if not _decision_matches(
            decision,
            request=request,
            selected=selected,
            source_binding_sha256=verified_read.binding.source_set_sha256,
        ):
            raise ProposalPreviewError(ProposalPreviewErrorCode.POLICY_DENIED)
        preview = SyntheticProposalPreview(
            preview_id=_preview_identity(
                selected=selected,
                source_binding_sha256=verified_read.binding.source_set_sha256,
            ),
            proposal_title=f"Review synthetic GitHub issue #{issue_number}",
            issue_number=issue_number,
            source_item_id=selected.item_id,
            source_envelope_id=selected.source_id,
            provider_item_id=selected.provider_item_id,
            source_content_sha256=selected.content_sha256,
            source_binding_sha256=verified_read.binding.source_set_sha256,
            evidence_span_ids=tuple(citation.span_id for citation in selected.citations),
            source_trust=selected.trust,
            source_sensitivity=selected.sensitivity,
            derived_trust=TrustLabel.T3_DERIVED,
            derived_sensitivity=SensitivityLabel.PUBLIC,
            proposed_capability=Capability.C2_WRITE_LOCAL_PROPOSAL,
            policy_rule_id=PolicyRuleId.P06,
            policy_request_sha256=request_sha256(request),
            policy_sha256=request.policy_sha256,
            registry_sha256=request.registry_sha256,
        )
        validated_preview = SyntheticProposalPreview.model_validate(
            preview.model_dump(mode="python"), strict=True
        )
        return _mark_verified_preview(validated_preview)
    except ProposalPreviewError:
        raise
    except Exception:
        raise ProposalPreviewError(ProposalPreviewErrorCode.SOURCE_UNAVAILABLE) from None


__all__ = [
    "ProposalPreviewError",
    "ProposalPreviewErrorCode",
    "build_github_issue_proposal_preview",
]
