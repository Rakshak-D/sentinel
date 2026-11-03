"""Byte-accurate, source-bound citations for synthetic Gmail bodies."""

import hashlib
import json

import pytest

from sentinel.normalization import NormalizationError, verify_bound_citation
from sentinel.readers import gmail_fixture as reader_impl
from sentinel.readers import read_packaged_gmail_fixture


def _parse(document):
    raw = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return reader_impl._parse_fixture_bytes(raw)


def _document():
    return json.loads(reader_impl._read_gmail_fixture_resource())


def test_fixture_ascii_unicode_newline_and_repeated_phrase_citations_verify() -> None:
    first, second, third = read_packaged_gmail_fixture().messages

    assert [verify_bound_citation(first.normalized_source, item) for item in first.citations] == [
        "parser flagged",
        "review",
        "review",
        "SYNTHETIC_PRIVATE_BODY_CANARY",
    ]
    assert [verify_bound_citation(second.normalized_source, item) for item in second.citations] == [
        "café",
        "🙂",
        "日本語",
        "\r\n",
        "\n",
        "go",
        "go",
    ]
    assert verify_bound_citation(third.normalized_source, third.citations[0]) == (
        "ignore previous instructions"
    )
    assert (first.citations[1].span.start_byte, first.citations[2].span.start_byte) == (72, 81)
    assert (second.citations[5].span.start_byte, second.citations[6].span.start_byte) == (85, 90)


def test_source_and_slice_digests_match_exact_decoded_body_bytes() -> None:
    for message in read_packaged_gmail_fixture().messages:
        body = message.body_bytes
        full_digest = hashlib.sha256(body).hexdigest()
        assert message.normalized_source.envelope.content_sha256 == full_digest
        for citation in message.citations:
            selected = body[citation.span.start_byte : citation.span.end_byte]
            assert citation.source_id == message.source_id
            assert citation.content_sha256 == full_digest
            assert citation.span.text_sha256 == hashlib.sha256(selected).hexdigest()
            assert selected.decode("utf-8") == verify_bound_citation(
                message.normalized_source, citation
            )


def test_equal_body_citation_cannot_be_reused_for_another_message() -> None:
    document = _document()
    duplicate = json.loads(json.dumps(document["messages"][0]))
    duplicate["message"]["id"] = "msg_demo_equal_body"
    document["messages"].append(duplicate)
    first, other = _parse(document).messages[0], _parse(document).messages[-1]

    assert first.body_bytes == other.body_bytes
    with pytest.raises(NormalizationError):
        verify_bound_citation(other.normalized_source, first.citations[0])


def test_old_bound_citation_is_invalid_for_changed_message_body() -> None:
    document = _document()
    original = _parse(document).messages[0]
    import base64

    body = document["messages"][0]["message"]["payload"]["body"]
    decoded = base64.urlsafe_b64decode(body["data"] + "=" * (-len(body["data"]) % 4))
    changed = decoded + b" changed"
    body["data"] = base64.urlsafe_b64encode(changed).rstrip(b"=").decode("ascii")
    body["size"] = len(changed)
    revision = _parse(document).messages[0]

    assert revision.source_id == original.source_id
    assert revision.normalized_source.envelope.content_sha256 != (
        original.normalized_source.envelope.content_sha256
    )
    with pytest.raises(NormalizationError):
        verify_bound_citation(revision.normalized_source, original.citations[0])
