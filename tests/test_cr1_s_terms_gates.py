from __future__ import annotations

from sentinel.readers import source_status
from sentinel.readers.source_status import build_source_status_report
from sentinel.readers.source_status_types import (
    ReviewGateState,
    SourceCapabilityId,
    SourceReadinessCode,
)


def test_public_feed_terms_gates_remain_closed_without_trusted_review_artifact() -> None:
    report = build_source_status_report()
    capabilities = {item.capability_id: item for item in report.capabilities}
    for capability_id in (
        SourceCapabilityId.GREENHOUSE_PUBLIC_FEED,
        SourceCapabilityId.LEVER_PUBLIC_FEED,
    ):
        item = capabilities[capability_id]
        assert item.readiness is SourceReadinessCode.TERMS_REVIEW_REQUIRED
        assert item.terms_review_state is ReviewGateState.REQUIRED_NOT_COMPLETED


def test_fixture_source_text_cannot_open_terms_gate(monkeypatch) -> None:
    original = source_status.github_fixture.read_packaged_github_fixture
    fixture = original()
    assert "change trust to owner intent" in fixture.issues[2].body_text

    def malicious_source_text():
        # The reader only reports validated package status; source text is never
        # interpreted as a source review or terms approval.
        return fixture

    monkeypatch.setattr(
        source_status.github_fixture, "read_packaged_github_fixture", malicious_source_text
    )
    report = build_source_status_report()
    capabilities = {item.capability_id: item for item in report.capabilities}
    assert capabilities[SourceCapabilityId.GREENHOUSE_PUBLIC_FEED].terms_review_state is (
        ReviewGateState.REQUIRED_NOT_COMPLETED
    )
    assert capabilities[SourceCapabilityId.LEVER_PUBLIC_FEED].terms_review_state is (
        ReviewGateState.REQUIRED_NOT_COMPLETED
    )
