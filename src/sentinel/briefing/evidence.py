"""Construction of the read-only synthetic GitHub evidence briefing."""

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import sentinel.policy.evaluator as policy_evaluator
from sentinel.briefing.types import (
    BriefingError,
    BriefingErrorCode,
    EvidenceBriefing,
    EvidenceCitation,
    EvidenceItem,
)
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.ingestion.types import VerifiedGithubEvidenceItem
from sentinel.policy import PolicyOutcome, PolicyReasonCode, PolicyRuleId
from sentinel.policy.canonical import request_sha256
from sentinel.policy.source_binding import (
    resolve_github_fixture_public_read,
    validate_verified_github_public_read,
)

BRIEF_SCHEMA_VERSION = "sentinel.synthetic-evidence-brief.v1"
BRIEFING_TYPE = "Synthetic GitHub evidence briefing"
FIXTURE_ORIGIN = "Packaged synthetic GitHub issue fixture"
ORDERING_DESCRIPTION = "source_at ascending as a UTC instant, then provider item ID"


def _order_items(items: Iterable[EvidenceItem]) -> tuple[EvidenceItem, ...]:
    values = tuple(items)
    for item in values:
        if type(item.source_at) is not datetime:
            raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE)
        if item.source_at.utcoffset() is None:
            raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE)
    return tuple(
        sorted(
            values,
            key=lambda item: (item.source_at.astimezone(UTC), item.provider_item_id),
        )
    )


def _as_evidence_item(item: VerifiedGithubEvidenceItem) -> EvidenceItem:
    if type(item) is not VerifiedGithubEvidenceItem:
        raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE)
    citations = tuple(
        EvidenceCitation(
            span_id=citation.span_id,
            start_byte=citation.start_byte,
            end_byte=citation.end_byte,
            text_sha256=citation.text_sha256,
            cited_text=citation.cited_text,
        )
        for citation in sorted(
            item.citations,
            key=lambda citation: (citation.start_byte, citation.end_byte, str(citation.span_id)),
        )
    )
    return EvidenceItem(
        provider_item_id=item.provider_item_id,
        item_id=item.item_id,
        source_envelope_id=item.source_envelope_id,
        content_sha256=item.content_sha256,
        source_at=item.source_at,
        observed_at=item.observed_at,
        trust=item.trust.value,
        sensitivity=item.sensitivity.value,
        citations=citations,
    )


def build_github_fixture_brief(
    database: str | Path,
    *,
    store_root: str | Path,
) -> EvidenceBriefing:
    """Build the fixed briefing only after the verified P09/P04 read decision."""
    try:
        verified_read = resolve_github_fixture_public_read(database, store_root=store_root)
        if not validate_verified_github_public_read(verified_read):
            raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE)
        request, context = policy_evaluator.build_verified_public_read_policy_input(
            verified_read
        )
        decision = policy_evaluator.evaluate_policy(
            request=request,
            context=context,
            evidence_binding=verified_read,
        )
        if (
            decision.outcome is not PolicyOutcome.ALLOW
            or decision.rule_id is not PolicyRuleId.P04
            or decision.reason_code is not PolicyReasonCode.PUBLIC_READ_ALLOWED
            or decision.executable is not False
            or decision.request_sha256 != request_sha256(request)
            or decision.policy_sha256 != request.policy_sha256
            or decision.registry_sha256 != request.registry_sha256
            or decision.evidence_binding_sha256 != verified_read.binding.source_set_sha256
            or decision.evidence_ids != (request.request_id, *request.source_ids)
        ):
            raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE)
        verified = verified_read.evidence
    except BriefingError:
        raise
    except Exception:
        raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE) from None
    if (
        verified.provider_id != "github.fixture"
        or verified.fixture_version != EXPECTED_MANIFEST.fixture_version
        or verified.fixture_sha256 != EXPECTED_MANIFEST.fixture_sha256
        or verified.manifest_sha256 != EXPECTED_MANIFEST.sha256
        or len(verified.items) != 3
    ):
        raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE)
    items = _order_items(_as_evidence_item(item) for item in verified.items)
    if sum(len(item.citations) for item in items) != 9:
        raise BriefingError(BriefingErrorCode.EVIDENCE_UNAVAILABLE)
    return EvidenceBriefing(
        schema_version=BRIEF_SCHEMA_VERSION,
        fixture_origin=FIXTURE_ORIGIN,
        fixture_version=verified.fixture_version,
        fixture_sha256=verified.fixture_sha256,
        manifest_sha256=verified.manifest_sha256,
        synthetic_data=True,
        provider_id=verified.provider_id,
        items=items,
    )
