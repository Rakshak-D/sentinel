from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import sentinel.ingestion.blob_readback as blob_readback
from sentinel.briefing import build_github_fixture_brief
from sentinel.briefing.evidence import _order_items
from sentinel.briefing.types import EvidenceItem
from sentinel.ingestion.blob_manifest import EXPECTED_MANIFEST
from sentinel.normalization import verify_bound_citation
from sentinel.readers.github_fixture import read_packaged_github_fixture
from tests.test_cr1_i_support import promoted_case


def test_complete_brief_has_three_items_nine_source_bound_citations(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="brief-complete")
    briefing = build_github_fixture_brief(database, store_root=store_root)

    assert briefing.schema_version == "sentinel.synthetic-evidence-brief.v1"
    assert briefing.fixture_version == "sentinel.github-issues-fixture.v1"
    assert briefing.fixture_sha256 == (
        "7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1"
    )
    assert len(briefing.items) == 3
    assert sum(len(item.citations) for item in briefing.items) == 9
    assert briefing.provider_id == "github.fixture"
    assert briefing.synthetic_data is True


def test_items_are_ordered_by_utc_source_instant_then_provider_id(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="brief-order")
    briefing = build_github_fixture_brief(database, store_root=store_root)

    assert [item.provider_item_id for item in briefing.items] == [
        "example-owner/fixture-project#102",
        "example-owner/fixture-project#101",
        "example-owner/fixture-project#103",
    ]
    utc_times = [item.source_at.astimezone(UTC) for item in briefing.items]
    assert utc_times == sorted(utc_times)
    assert all(item.source_at.utcoffset() is not None for item in briefing.items)
    assert all(item.observed_at == datetime(2026, 11, 3, 12, tzinfo=UTC) for item in briefing.items)
    assert briefing.items[0].source_at != briefing.items[0].observed_at


def test_tied_provider_timestamps_use_stable_provider_item_id_order() -> None:
    stamp = datetime(2026, 11, 2, 10, tzinfo=UTC)
    items = tuple(
        EvidenceItem(
            provider_item_id=provider_id,
            item_id=UUID(int=index),
            source_envelope_id=UUID(int=index + 10),
            content_sha256="0" * 64,
            source_at=stamp,
            observed_at=stamp,
            trust="T4 EXTERNAL",
            sensitivity="PUBLIC",
            citations=(),
        )
        for index, provider_id in enumerate(("repo#2", "repo#1"), start=1)
    )

    assert [item.provider_item_id for item in _order_items(items)] == ["repo#1", "repo#2"]


def test_citations_retain_verified_ids_ranges_digests_and_exact_text(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="brief-citations")
    fixture = read_packaged_github_fixture()
    briefing = build_github_fixture_brief(database, store_root=store_root)
    expected_by_item = {
        f"{issue.repository}#{issue.issue_number}": issue for issue in fixture.issues
    }
    manifest_by_item = {
        item.provider_item_id: item for item in EXPECTED_MANIFEST.items
    }

    for item in briefing.items:
        expected = expected_by_item[item.provider_item_id]
        expected_persisted = manifest_by_item[item.provider_item_id]
        assert item.item_id == expected_persisted.item_id
        assert item.source_envelope_id == expected.normalized_source.envelope.source_id
        assert item.content_sha256 == expected.normalized_source.envelope.content_sha256
        assert item.trust == "T4 EXTERNAL"
        assert item.sensitivity == "PUBLIC"
        assert len(item.citations) == len(expected.citations)
        for citation, source_bound, persisted_span in zip(
            item.citations, expected.citations, expected_persisted.spans, strict=True
        ):
            assert citation.span_id == persisted_span.span_id
            assert citation.start_byte == source_bound.span.start_byte
            assert citation.end_byte == source_bound.span.end_byte
            assert citation.text_sha256 == source_bound.span.text_sha256
            assert citation.cited_text == verify_bound_citation(
                expected.normalized_source, source_bound
            )

    issue_101 = expected_by_item["example-owner/fixture-project#101"]
    repeated = next(item for item in briefing.items if item.provider_item_id.endswith("#101"))
    assert repeated.citations[1].cited_text == repeated.citations[2].cited_text == "done"
    assert (repeated.citations[1].start_byte, repeated.citations[2].start_byte) == (68, 74)
    issue_102 = next(item for item in briefing.items if item.provider_item_id.endswith("#102"))
    assert [citation.cited_text for citation in issue_102.citations[:3]] == ["🙂", "日本語", "\r\n"]
    assert issue_101.normalized_source.envelope.sensitivity.value == "PUBLIC"


def test_single_verified_readback_supplies_entire_brief(tmp_path, monkeypatch) -> None:
    database, store_root = promoted_case(tmp_path, name="one-snapshot")
    original = blob_readback._verified_snapshot
    calls = 0

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(blob_readback, "_verified_snapshot", counted)
    briefing = build_github_fixture_brief(database, store_root=store_root)
    assert len(briefing.items) == 3
    assert calls == 1


def test_evidence_text_is_omitted_from_default_representations(tmp_path) -> None:
    database, store_root = promoted_case(tmp_path, name="brief-repr")
    briefing = build_github_fixture_brief(database, store_root=store_root)
    fixture = read_packaged_github_fixture()
    rendered = repr(briefing)
    for issue in fixture.issues:
        assert issue.title not in rendered
        assert issue.body_text not in rendered
