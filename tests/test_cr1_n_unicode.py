from __future__ import annotations

from sentinel.readers import search_selected_local_text_files


def test_emoji_japanese_crlf_and_composed_decomposed_matching_are_byte_exact(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "unicode.txt"
    composed = "caf\u00e9"
    decomposed = "cafe\u0301"
    payload = f"start \U0001f9ed {composed}\r\n{decomposed} \u65e5\u672c\u8a9e".encode()
    selected.write_bytes(payload)

    emoji = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query="\U0001f9ed"
    )
    japanese = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query="\u65e5\u672c\u8a9e"
    )
    composed_result = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query=composed
    )
    decomposed_result = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query=decomposed
    )

    assert [(m.start_byte, m.end_byte) for m in emoji.files[0].matches] == [(6, 10)]
    assert [(m.start_byte, m.end_byte) for m in composed_result.files[0].matches] == [(11, 16)]
    assert [(m.start_byte, m.end_byte) for m in decomposed_result.files[0].matches] == [(18, 24)]
    assert [(m.start_byte, m.end_byte) for m in japanese.files[0].matches] == [(25, 34)]


def test_matching_is_case_sensitive_and_does_not_normalize_unicode(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "case.txt"
    selected.write_bytes("Done done café cafe\u0301".encode())

    upper = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query="Done"
    )
    lower = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query="done"
    )
    composed = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query="café"
    )
    decomposed = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query="cafe\u0301"
    )

    assert [len(x.files[0].matches) for x in (upper, lower, composed, decomposed)] == [1, 1, 1, 1]
    assert upper.files[0].matches[0].start_byte != lower.files[0].matches[0].start_byte
    assert composed.files[0].matches[0].start_byte != decomposed.files[0].matches[0].start_byte


def test_maximum_128_character_512_byte_query_is_accepted(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    query = "🧭" * 128
    selected = root / "max-query.txt"
    selected.write_bytes(query.encode("utf-8"))

    result = search_selected_local_text_files(
        allowed_root=root, file_paths=(selected,), query=query
    )

    assert result.total_match_count == 1
    assert result.files[0].matches[0].start_byte == 0
    assert result.files[0].matches[0].end_byte == 512
