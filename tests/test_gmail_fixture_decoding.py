"""Strict base64url decoding and exact decoded-byte provenance tests."""

import base64
import hashlib
import json

import pytest

from sentinel.readers import GmailFixtureError, read_packaged_gmail_fixture
from sentinel.readers import gmail_fixture as reader_impl


def _document():
    return json.loads(reader_impl._read_gmail_fixture_resource())


def _parse(document):
    return reader_impl._parse_fixture_bytes(
        json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )


def test_body_data_is_canonical_unpadded_base64url_and_size_is_decoded_bytes() -> None:
    document = _document()
    result = read_packaged_gmail_fixture()

    for wrapper, message in zip(document["messages"], result.messages, strict=True):
        body = wrapper["message"]["payload"]["body"]
        encoded = body["data"]
        decoded = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
        assert base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == encoded
        assert body["size"] == len(decoded) == len(message.body_bytes)
        assert message.body_bytes == decoded
        assert message.normalized_source.envelope.content_sha256 == hashlib.sha256(
            decoded
        ).hexdigest()


def test_utf8_unicode_crlf_and_lf_bytes_survive_without_normalization() -> None:
    result = read_packaged_gmail_fixture()
    unicode_message = result.messages[1]
    expected = (
        "Unicode note: café 🙂 and 日本語.\r\n"
        "Line two preserves LF too.\nRepeated phrase: go / go."
    )

    assert unicode_message.body_bytes == expected.encode("utf-8")
    assert b"\r\n" in unicode_message.body_bytes
    assert b"\n" in unicode_message.body_bytes
    assert unicode_message.body_text == expected


@pytest.mark.parametrize("encoded", ["AA+", "AA/", "A?", "A A", "A\nA", "Zg==", "Zh"])
def test_invalid_or_noncanonical_base64url_is_rejected(encoded: str) -> None:
    document = _document()
    body = document["messages"][0]["message"]["payload"]["body"]
    body["data"] = encoded
    body["size"] = 1

    with pytest.raises(GmailFixtureError):
        _parse(document)


def test_missing_non_string_and_size_mismatched_body_data_are_rejected() -> None:
    document = _document()
    body = document["messages"][0]["message"]["payload"]["body"]
    body.pop("data")
    with pytest.raises(GmailFixtureError):
        _parse(document)

    document = _document()
    body = document["messages"][0]["message"]["payload"]["body"]
    body["data"] = 42
    with pytest.raises(GmailFixtureError):
        _parse(document)

    document = _document()
    body = document["messages"][0]["message"]["payload"]["body"]
    body["size"] += 1
    with pytest.raises(GmailFixtureError):
        _parse(document)


def test_oversized_and_invalid_utf8_decoded_body_are_rejected() -> None:
    document = _document()
    body = document["messages"][0]["message"]["payload"]["body"]
    oversized = b"x" * (reader_impl.MAX_GMAIL_BODY_BYTES + 1)
    body["data"] = base64.urlsafe_b64encode(oversized).rstrip(b"=").decode("ascii")
    body["size"] = len(oversized)
    with pytest.raises(GmailFixtureError):
        _parse(document)

    document = _document()
    body = document["messages"][0]["message"]["payload"]["body"]
    invalid_utf8 = b"\xff"
    body["data"] = base64.urlsafe_b64encode(invalid_utf8).rstrip(b"=").decode("ascii")
    body["size"] = len(invalid_utf8)
    with pytest.raises(GmailFixtureError):
        _parse(document)
