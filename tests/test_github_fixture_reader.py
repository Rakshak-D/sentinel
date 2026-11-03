"""Behavioral tests for the fixed, synthetic GitHub-style issue fixture."""

import hashlib
import json
from datetime import datetime
from uuid import uuid5

import pytest

from sentinel.contracts import SensitivityLabel, TrustLabel
from sentinel.readers import (
    FIXTURE_OBSERVED_AT,
    FIXTURE_SCHEMA_VERSION,
    FIXTURE_SHA256,
    GithubFixtureError,
    GithubFixtureErrorCode,
    read_packaged_github_fixture,
)
from sentinel.readers import github_fixture as reader_impl


def _valid_document() -> dict[str, object]:
    return {
        "fixture_version": FIXTURE_SCHEMA_VERSION,
        "issues": [
            {
                "repository": "example-owner/fixture-project",
                "issue_number": 101,
                "updated_at": "2026-11-02T10:30:00Z",
                "title": "Synthetic issue title",
                "body": "Synthetic issue body contains a note.",
                "evidence_spans": [
                    {
                        "span_id": "d767cdd2-90cb-45d6-9291-95d0c8aa0d09",
                        "start_byte": 16,
                        "end_byte": 26,
                        "expected_text": "body conta",
                    }
                ],
            }
        ],
    }


def _raw(document: dict[str, object] | None = None) -> bytes:
    return json.dumps(
        document if document is not None else _valid_document(),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _parse(raw_json: bytes):
    return reader_impl._parse_fixture_bytes(raw_json, observed_at=FIXTURE_OBSERVED_AT)


def test_packaged_fixture_parses_with_version_hash_and_multiple_issues() -> None:
    result = read_packaged_github_fixture()
    raw = reader_impl._read_fixture_resource()

    assert result.fixture_version == FIXTURE_SCHEMA_VERSION
    assert result.fixture_sha256 == FIXTURE_SHA256 == hashlib.sha256(raw).hexdigest()
    assert len(result.issues) == 3
    assert all(
        issue.normalized_source.envelope.content_sha256 != result.fixture_sha256
        for issue in result.issues
    )


def test_stable_source_ids_and_different_issue_ids() -> None:
    first = read_packaged_github_fixture()
    second = read_packaged_github_fixture()

    assert [issue.source_id for issue in first.issues] == [
        issue.source_id for issue in second.issues
    ]
    assert len({issue.source_id for issue in first.issues}) == len(first.issues)
    expected_first_id = uuid5(
        reader_impl.GITHUB_FIXTURE_NAMESPACE,
        "sentinel:github.fixture:example-owner/fixture-project#101",
    )
    assert first.issues[0].source_id == expected_first_id


def test_issue_metadata_and_trusted_observation_time_are_separate() -> None:
    result = read_packaged_github_fixture()
    issue = result.issues[1]

    assert issue.repository == "example-owner/fixture-project"
    assert issue.issue_number == 102
    assert issue.title == "Synthetic Unicode and line ending sample"
    assert issue.updated_at == datetime.fromisoformat("2026-11-02T10:31:00+05:30")
    assert issue.updated_at.tzinfo is not None
    assert issue.normalized_source.envelope.observed_at == FIXTURE_OBSERVED_AT
    assert issue.normalized_source.envelope.observed_at != issue.updated_at


def test_exact_body_bytes_hashes_and_trusted_labels() -> None:
    result = read_packaged_github_fixture()

    for issue in result.issues:
        body_bytes = issue.body_text.encode("utf-8")
        envelope = issue.normalized_source.envelope
        assert issue.normalized_source.original_bytes == body_bytes
        assert envelope.content_sha256 == hashlib.sha256(body_bytes).hexdigest()
        assert issue.normalized_source.payload_sha256 == hashlib.sha256(body_bytes).hexdigest()
        assert envelope.provider_id == "github.fixture"
        assert envelope.trust is TrustLabel.T4_EXTERNAL
        assert envelope.sensitivity is SensitivityLabel.PUBLIC


def test_revision_changes_digest_but_retains_stable_item_identity() -> None:
    document = _valid_document()
    first = _parse(_raw(document)).issues[0]
    changed = _valid_document()
    changed_issue = changed["issues"][0]  # type: ignore[index]
    assert isinstance(changed_issue, dict)
    changed_issue["body"] = "Synthetic revised issue body."
    changed_issue["evidence_spans"] = []
    revision = _parse(_raw(changed)).issues[0]

    assert revision.source_id == first.source_id
    assert revision.normalized_source.envelope.content_sha256 != (
        first.normalized_source.envelope.content_sha256
    )


def test_results_are_immutable_and_body_has_no_automatic_dump() -> None:
    issue = read_packaged_github_fixture().issues[0]

    with pytest.raises((AttributeError, TypeError)):
        issue.issue_number = 5  # type: ignore[misc]
    assert "body_text" not in issue.__dataclass_fields__
    assert issue.body_text == issue.normalized_source.original_bytes.decode("utf-8")
    assert issue.body_text not in repr(issue)


def test_prompt_injection_text_stays_untrusted_fixture_content() -> None:
    issue = read_packaged_github_fixture().issues[2]

    assert "ignore prior instructions" in issue.body_text
    assert issue.normalized_source.envelope.trust is TrustLabel.T4_EXTERNAL
    assert issue.normalized_source.envelope.sensitivity is SensitivityLabel.PUBLIC


def test_repeated_reads_produce_equal_issue_results() -> None:
    first = read_packaged_github_fixture()
    second = read_packaged_github_fixture()

    assert first.fixture_version == second.fixture_version
    assert first.fixture_sha256 == second.fixture_sha256
    assert [
        (
            issue.repository,
            issue.issue_number,
            issue.updated_at,
            issue.source_id,
            issue.normalized_source.envelope.content_sha256,
            issue.citations,
        )
        for issue in first.issues
    ] == [
        (
            issue.repository,
            issue.issue_number,
            issue.updated_at,
            issue.source_id,
            issue.normalized_source.envelope.content_sha256,
            issue.citations,
        )
        for issue in second.issues
    ]


def test_missing_packaged_resource_fails_with_fixed_category(monkeypatch) -> None:
    def missing_resource() -> bytes:
        raise FileNotFoundError("synthetic path canary")

    monkeypatch.setattr(reader_impl, "_read_fixture_resource", missing_resource)
    with pytest.raises(GithubFixtureError) as error:
        read_packaged_github_fixture()

    assert error.value.code is GithubFixtureErrorCode.FIXTURE_UNAVAILABLE
    assert "synthetic path canary" not in str(error.value)


def test_modified_packaged_bytes_fail_pinned_digest_check(monkeypatch) -> None:
    original = reader_impl._read_fixture_resource()
    monkeypatch.setattr(reader_impl, "_read_fixture_resource", lambda: original + b" ")

    with pytest.raises(GithubFixtureError) as error:
        read_packaged_github_fixture()
    assert error.value.code is GithubFixtureErrorCode.FIXTURE_HASH_MISMATCH


def test_non_byte_input_is_rejected_without_stringification() -> None:
    class Hostile:
        calls = 0

        def __str__(self) -> str:
            self.calls += 1
            raise AssertionError("unexpected string conversion")

        def __repr__(self) -> str:
            self.calls += 1
            raise AssertionError("unexpected repr conversion")

    value = Hostile()
    with pytest.raises(GithubFixtureError) as error:
        reader_impl._parse_fixture_bytes(value, observed_at=FIXTURE_OBSERVED_AT)  # type: ignore[arg-type]
    assert error.value.code is GithubFixtureErrorCode.INVALID_FIXTURE
    assert value.calls == 0
