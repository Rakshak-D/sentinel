from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

import sentinel.readers.local_text as local_text
from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.normalization import MAX_PLAIN_TEXT_BYTES
from sentinel.readers import (
    LocalTextError,
    LocalTextErrorCode,
    LocalTextFormat,
    read_allowlisted_local_text,
)


def test_txt_reader_preserves_exact_bytes_and_conservative_labels(tmp_path, monkeypatch) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    payload = "\ufeffLine one\r\nEmoji \U0001f9ed\nJapanese \u65e5\u672c\u8a9e  done done".encode()
    selected = root / "sample.txt"
    selected.write_bytes(payload)
    observed_at = datetime(2026, 11, 5, 8, 10, tzinfo=UTC)
    monkeypatch.setattr(local_text, "_utc_now", lambda: observed_at)

    result = read_allowlisted_local_text(allowed_root=root, file_path=selected)

    assert result.byte_length == len(payload)
    assert result.content_sha256 == hashlib.sha256(payload).hexdigest()
    assert result.source_id == result.normalized_source.envelope.source_id
    assert result.normalized_source.original_bytes == payload
    assert result.normalized_source.text.encode("utf-8") == payload
    assert result.normalized_source.envelope.content_sha256 == hashlib.sha256(payload).hexdigest()
    assert result.normalized_source.envelope.observed_at == observed_at
    assert result.trust is TrustLabel.T4_EXTERNAL
    assert result.sensitivity is SensitivityLabel.PRIVATE
    assert result.source_format is LocalTextFormat.TXT
    assert result.file_metadata.byte_length == len(payload)
    assert str(selected) not in repr(result)
    assert result.normalized_source.text not in repr(result)
    with pytest.raises((FrozenInstanceError, AttributeError)):
        result.source_id = result.source_id  # type: ignore[misc]
    with pytest.raises(ValidationError):
        result.normalized_source.envelope.content_sha256 = "0" * 64


@pytest.mark.parametrize(
    ("filename", "payload", "source_format"),
    [
        ("note.txt", b"plain text\n", LocalTextFormat.TXT),
        (
            "note.md",
            "# Markdown is data\r\n\u65e5\u672c\u8a9e \U0001f9ed".encode(),
            LocalTextFormat.MARKDOWN,
        ),
        ("NOTE.MD", b"<b>not rendered</b>\n", LocalTextFormat.MARKDOWN),
    ],
)
def test_supported_extensions_are_plain_utf8_data(
    tmp_path, filename, payload, source_format
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / filename
    selected.write_bytes(payload)

    result = read_allowlisted_local_text(allowed_root=root, file_path=selected)

    assert result.source_format is source_format
    assert result.normalized_source.original_bytes == payload
    assert result.normalized_source.mime_type == "text/plain; charset=utf-8"


def test_stable_source_identity_binds_relative_identity_and_full_digest(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "sub" / "note.txt"
    selected.parent.mkdir()
    selected.write_bytes(b"same bytes\r\n")
    first = read_allowlisted_local_text(allowed_root=root, file_path=selected)
    repeated = read_allowlisted_local_text(allowed_root=root, file_path=selected)
    case_alias = read_allowlisted_local_text(
        allowed_root=type(root)(str(root).upper()),
        file_path=type(selected)(str(selected).upper()),
    )
    selected.write_bytes(b"changed bytes\r\n")
    changed = read_allowlisted_local_text(allowed_root=root, file_path=selected)

    assert first.source_id == repeated.source_id
    assert first.source_id == case_alias.source_id
    assert first.content_sha256 == repeated.content_sha256
    assert changed.source_id != first.source_id
    assert changed.content_sha256 != first.content_sha256


def test_content_size_limit_is_exact_and_does_not_truncate(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    exact = root / "exact.txt"
    exact.write_bytes(b"x" * MAX_PLAIN_TEXT_BYTES)
    accepted = read_allowlisted_local_text(allowed_root=root, file_path=exact)
    assert accepted.byte_length == MAX_PLAIN_TEXT_BYTES
    oversized = root / "large.txt"
    oversized.write_bytes(b"x" * (MAX_PLAIN_TEXT_BYTES + 1))

    with pytest.raises(LocalTextError) as error:
        read_allowlisted_local_text(allowed_root=root, file_path=oversized)

    assert error.value.code is LocalTextErrorCode.TOO_LARGE
    assert str(oversized) not in str(error.value)


def test_invalid_utf8_is_rejected_without_exposing_content(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    canary = b"SYNTHETIC_INVALID_UTF8_CANARY\xff"
    selected = root / "bad.txt"
    selected.write_bytes(canary)

    with pytest.raises(LocalTextError) as error:
        read_allowlisted_local_text(allowed_root=root, file_path=selected)

    assert error.value.code is LocalTextErrorCode.INVALID_UTF8
    assert canary.decode("latin-1") not in str(error.value)
    assert str(selected) not in str(error.value)


def test_observation_clock_is_trusted_and_not_file_timestamp(tmp_path, monkeypatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "note.txt"
    selected.write_bytes(b"untrusted file timestamp\n")
    expected = datetime(2026, 11, 5, 0, 0, tzinfo=UTC)
    monkeypatch.setattr(local_text, "_utc_now", lambda: expected)

    result = read_allowlisted_local_text(allowed_root=root, file_path=selected)

    assert result.normalized_source.envelope.observed_at == expected
    assert result.file_metadata.modified_at_utc != result.normalized_source.envelope.observed_at


@pytest.mark.parametrize("suffix", [".html", ".rtf", ".md.txtx", ""])
def test_unsupported_extension_is_rejected(tmp_path, suffix) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / f"note{suffix}"
    selected.write_bytes(b"not supported")

    with pytest.raises(LocalTextError) as error:
        read_allowlisted_local_text(allowed_root=root, file_path=selected)

    assert error.value.code is LocalTextErrorCode.UNSUPPORTED_FORMAT
    assert str(selected) not in str(error.value)


def test_read_does_not_change_bytes_or_print_source_by_default(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    payload = b"PRIVATE-SYNTHETIC-BODY-CANARY\r\n"
    selected = root / "note.txt"
    selected.write_bytes(payload)
    before = selected.read_bytes()

    result = read_allowlisted_local_text(allowed_root=root, file_path=selected)

    assert selected.read_bytes() == before
    assert list(root.iterdir()) == [selected]
    assert payload.decode() not in repr(result)
