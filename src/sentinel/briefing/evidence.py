"""Construction of the read-only synthetic GitHub evidence briefing."""

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from sentinel.briefing.types import (
    BriefingError,
    BriefingErrorCode,
    EvidenceBriefing,
    EvidenceCitation,
    EvidenceItem,
)
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.ingestion.blob_readback import read_blob_backed_github_evidence
from sentinel.ingestion.types import VerifiedGithubEvidenceItem

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
    """Build a complete briefing only after trusted evidence verification."""
    verified = read_blob_backed_github_evidence(database, store_root=store_root)
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
