from __future__ import annotations

import hashlib
from dataclasses import replace
from uuid import uuid4

import pytest

from sentinel.readers import (
    LocalTextError,
    LocalTextErrorCode,
    read_allowlisted_local_text,
    verify_local_text_span,
)


def test_citation_uses_exact_utf8_half_open_bytes_and_stable_span_id(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    payload = "before \U0001f9ed \u65e5\u672c\u8a9e done done\r\nafter".encode()
    selected = root / "note.txt"
    selected.write_bytes(payload)
    source = read_allowlisted_local_text(allowed_root=root, file_path=selected)
    excerpt = "\U0001f9ed \u65e5\u672c\u8a9e".encode()
    start = payload.index(excerpt)
    end = start + len(excerpt)

    first = verify_local_text_span(
        source, start_byte=start, end_byte=end, expected_text=excerpt.decode()
    )
    repeated = verify_local_text_span(
        source, start_byte=start, end_byte=end, expected_text=excerpt.decode()
    )

    assert first.cited_text == excerpt.decode()
    assert first.bound_citation.source_id == source.source_id
    assert first.bound_citation.content_sha256 == hashlib.sha256(payload).hexdigest()
    assert first.bound_citation.span.start_byte == start
    assert first.bound_citation.span.end_byte == end
    assert first.bound_citation.span.text_sha256 == hashlib.sha256(excerpt).hexdigest()
    assert first.bound_citation.span.span_id == repeated.bound_citation.span.span_id


def test_repeated_phrase_offsets_are_distinct(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    payload = b"done/done"
    selected = root / "note.md"
    selected.write_bytes(payload)
    source = read_allowlisted_local_text(allowed_root=root, file_path=selected)

    first = verify_local_text_span(source, start_byte=0, end_byte=4, expected_text="done")
    second = verify_local_text_span(source, start_byte=5, end_byte=9, expected_text="done")

    assert first.cited_text == second.cited_text
    assert first.bound_citation.span.span_id != second.bound_citation.span.span_id
    assert first.bound_citation.span.text_sha256 == second.bound_citation.span.text_sha256


@pytest.mark.parametrize(
    ("start", "end"),
    [(-1, 1), (0, 0), (3, 2), (0, 99), (2, 3)],
)
def test_invalid_or_utf8_splitting_ranges_fail_closed(tmp_path, start, end) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "note.txt"
    selected.write_bytes("a\U0001f9edb".encode())
    source = read_allowlisted_local_text(allowed_root=root, file_path=selected)

    with pytest.raises(LocalTextError) as error:
        verify_local_text_span(source, start_byte=start, end_byte=end)

    assert error.value.code is LocalTextErrorCode.INVALID_CITATION


def test_boolean_offsets_and_wrong_expected_text_are_rejected(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "note.txt"
    selected.write_bytes(b"alpha")
    source = read_allowlisted_local_text(allowed_root=root, file_path=selected)

    for start, end, expected in [(False, 1, None), (0, 5, "wrong")]:
        with pytest.raises(LocalTextError) as error:
            verify_local_text_span(source, start_byte=start, end_byte=end, expected_text=expected)
        assert error.value.code is LocalTextErrorCode.INVALID_CITATION


def test_tampered_read_metadata_cannot_be_used_to_bind_a_citation(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "note.txt"
    selected.write_bytes(b"alpha")
    source = read_allowlisted_local_text(allowed_root=root, file_path=selected)

    for altered in (
        replace(source, source_id=uuid4()),
        replace(source, content_sha256="0" * 64),
        replace(source, byte_length=4),
    ):
        with pytest.raises(LocalTextError) as error:
            verify_local_text_span(altered, start_byte=0, end_byte=1)
        assert error.value.code is LocalTextErrorCode.INVALID_SOURCE
