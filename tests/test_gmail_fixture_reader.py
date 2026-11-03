"""Behavioral tests for the fixed synthetic Gmail message fixture."""

import json
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid5

import pytest

from sentinel.contracts import SensitivityLabel, TrustLabel
from sentinel.readers import (
    GMAIL_FIXTURE_OBSERVED_AT,
    GMAIL_FIXTURE_SCHEMA_VERSION,
    GMAIL_FIXTURE_SHA256,
    GmailFixtureError,
    read_packaged_gmail_fixture,
)
from sentinel.readers import gmail_fixture as reader_impl


def _parse(raw: bytes):
    return reader_impl._parse_fixture_bytes(raw)


def _raw(document: dict[str, object]) -> bytes:
    return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def test_packaged_collection_loads_with_pinned_version_bytes_and_hash() -> None:
    result = read_packaged_gmail_fixture()
    raw = reader_impl._read_gmail_fixture_resource()

    assert result.fixture_version == GMAIL_FIXTURE_SCHEMA_VERSION
    assert result.fixture_sha256 == GMAIL_FIXTURE_SHA256
    assert len(raw) == 3028
    assert len(result.messages) == 3


def test_message_metadata_and_fixed_observation_time_are_separate() -> None:
    result = read_packaged_gmail_fixture()
    message = result.messages[0]

    assert result.mailbox_alias == "synthetic-inbox"
    assert message.message_id == "msg_demo_001"
    assert message.thread_id == "thread_demo_shared"
    assert message.subject == "SYNTHETIC_SUBJECT_CANARY: Sample status note"
    assert message.internal_date == datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
    assert message.normalized_source.envelope.observed_at == GMAIL_FIXTURE_OBSERVED_AT
    assert message.internal_date != message.normalized_source.envelope.observed_at


def test_reader_assigns_private_external_labels_and_stable_source_identity() -> None:
    result = read_packaged_gmail_fixture()
    ids = [message.source_id for message in result.messages]

    assert len(set(ids)) == len(ids)
    assert ids[0] == uuid5(
        NAMESPACE_URL,
        "sentinel:gmail.fixture:synthetic-inbox#msg_demo_001",
    )
    assert all(
        message.normalized_source.envelope.provider_id == "gmail.fixture"
        and message.normalized_source.envelope.trust is TrustLabel.T4_EXTERNAL
        and message.normalized_source.envelope.sensitivity is SensitivityLabel.PRIVATE
        for message in result.messages
    )


def test_alias_changes_source_identity_and_body_revision_changes_only_digest() -> None:
    raw = reader_impl._read_gmail_fixture_resource()
    document = json.loads(raw)
    original = _parse(raw).messages[0]

    other_alias = dict(document)
    other_alias["mailbox_alias"] = "synthetic-archive"
    alias_result = _parse(_raw(other_alias))

    revision_doc = json.loads(raw)
    body = revision_doc["messages"][0]["message"]["payload"]["body"]
    import base64

    changed = base64.urlsafe_b64decode(body["data"] + "=" * (-len(body["data"]) % 4)) + b" revision"
    body["data"] = base64.urlsafe_b64encode(changed).rstrip(b"=").decode("ascii")
    body["size"] = len(changed)
    revision = _parse(_raw(revision_doc)).messages[0]

    assert alias_result.messages[0].source_id != original.source_id
    assert revision.source_id == original.source_id
    assert revision.normalized_source.envelope.content_sha256 != (
        original.normalized_source.envelope.content_sha256
    )


def test_result_is_immutable_and_default_repr_omits_subject_and_body() -> None:
    result = read_packaged_gmail_fixture()
    message = result.messages[0]

    assert "SYNTHETIC_SUBJECT_CANARY" not in repr(message)
    assert "SYNTHETIC_PRIVATE_BODY_CANARY" not in repr(result)
    assert "parser flagged two sample tasks" not in repr(result)
    assert message.body_text == message.body_bytes.decode("utf-8")
    with pytest.raises((AttributeError, TypeError)):
        message.message_id = "changed"  # type: ignore[misc]


def test_repeated_reads_are_deterministic() -> None:
    first = read_packaged_gmail_fixture()
    second = read_packaged_gmail_fixture()

    assert first.fixture_version == second.fixture_version
    assert first.fixture_sha256 == second.fixture_sha256
    assert [
        (
            item.mailbox_alias,
            item.message_id,
            item.thread_id,
            item.internal_date,
            item.source_id,
            item.normalized_source.envelope.content_sha256,
            item.citations,
        )
        for item in first.messages
    ] == [
        (
            item.mailbox_alias,
            item.message_id,
            item.thread_id,
            item.internal_date,
            item.source_id,
            item.normalized_source.envelope.content_sha256,
            item.citations,
        )
        for item in second.messages
    ]


def test_reader_errors_are_fixed_and_do_not_expose_subject_or_body_canaries() -> None:
    raw = reader_impl._read_gmail_fixture_resource()
    document = json.loads(raw)
    message = document["messages"][0]["message"]
    message["payload"]["body"]["size"] += 1
    with pytest.raises(GmailFixtureError) as error:
        _parse(_raw(document))

    assert "SYNTHETIC_SUBJECT_CANARY" not in str(error.value)
    assert "SYNTHETIC_PRIVATE_BODY_CANARY" not in str(error.value)
