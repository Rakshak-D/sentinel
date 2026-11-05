from __future__ import annotations

import hashlib

from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.readers import (
    LocalFileSearch,
    read_allowlisted_local_text,
    search_selected_local_text_files,
    verify_local_text_span,
)


def test_one_file_returns_exact_verified_ascii_matches_and_zero_match_file(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    first = root / "first.txt"
    second = root / "second.md"
    first.write_bytes(b"Done done done")
    second.write_bytes(b"nothing here")

    result = search_selected_local_text_files(
        allowed_root=root,
        file_paths=(first, second),
        query="done",
    )

    assert isinstance(result, LocalFileSearch)
    assert result.selected_file_count == 2
    assert result.total_match_count == 2
    assert result.trust is TrustLabel.T4_EXTERNAL
    assert result.sensitivity is SensitivityLabel.PRIVATE
    assert [file.ordinal for file in result.files] == [1, 2]
    assert [len(file.matches) for file in result.files] == [2, 0]
    matches = result.files[0].matches
    assert [(match.start_byte, match.end_byte) for match in matches] == [(5, 9), (10, 14)]
    assert all(
        match.content_sha256 == hashlib.sha256(first.read_bytes()).hexdigest() for match in matches
    )
    assert all(match.text_sha256 == hashlib.sha256(b"done").hexdigest() for match in matches)
    assert matches[0].span_id != matches[1].span_id
    source = read_allowlisted_local_text(allowed_root=root, file_path=first)
    repeated_source = read_allowlisted_local_text(allowed_root=root, file_path=first)
    assert repeated_source.source_id == source.source_id
    for match in matches:
        citation = verify_local_text_span(
            source,
            start_byte=match.start_byte,
            end_byte=match.end_byte,
            expected_text="done",
        )
        assert citation.bound_citation.span.span_id == match.span_id
        assert citation.bound_citation.content_sha256 == match.content_sha256


def test_changed_payload_gets_a_new_source_revision_identity(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "revision.txt"
    selected.write_bytes(b"first needle")
    first = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query="needle"
    ).files[0]

    selected.write_bytes(b"second needle")
    second = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query="needle"
    ).files[0]

    assert first.source_id != second.source_id
    assert first.content_sha256 != second.content_sha256


def test_overlapping_occurrences_are_returned_in_byte_order(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "overlap.txt"
    selected.write_bytes(b"banana")

    result = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query="ana"
    )
    repeated = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query="ana"
    )

    assert [(match.start_byte, match.end_byte) for match in result.files[0].matches] == [
        (1, 4),
        (3, 6),
    ]
    assert [m.span_id for m in result.files[0].matches] == [
        m.span_id for m in repeated.files[0].matches
    ]


def test_eight_selected_files_preserve_argument_order_and_eight_mib_bound(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    paths = []
    for ordinal in range(8):
        selected = root / f"file-{ordinal}.txt"
        selected.write_bytes(b"x" * 1_048_576)
        paths.append(selected)

    result = search_selected_local_text_files(
        allowed_root=root, file_paths=tuple(paths), query="not-present"
    )

    assert result.selected_file_count == 8
    assert [file.ordinal for file in result.files] == list(range(1, 9))
    assert [file.byte_length for file in result.files] == [1_048_576] * 8
    assert result.total_match_count == 0


def test_result_is_immutable_and_does_not_retain_body_or_query(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "private.txt"
    selected.write_text("PRIVATE-CANARY target", encoding="utf-8")

    result = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query="target"
    )

    assert "PRIVATE-CANARY" not in repr(result)
    assert "target" not in repr(result)
    assert result.files[0].matches[0].preview is None
