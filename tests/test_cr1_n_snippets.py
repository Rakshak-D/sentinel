from __future__ import annotations

import hashlib

from sentinel.readers import (
    format_json_local_file_search,
    read_allowlisted_local_text,
    search_selected_local_text_files,
    verify_local_text_span,
)


def test_opt_in_preview_is_bounded_line_local_and_independently_hashed(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "lines.txt"
    payload = ("x" * 50 + "needle" + "y" * 60 + "\r\nother line").encode()
    selected.write_bytes(payload)

    result = search_selected_local_text_files(
        allowed_root=root,
        file_paths=(selected,),
        query="needle",
        show_snippets=True,
    )

    match = result.files[0].matches[0]
    preview = match.preview
    assert result.snippets_included is True
    assert preview is not None
    preview_bytes = payload[preview.start_byte : preview.end_byte]
    match_bytes = payload[match.start_byte : match.end_byte]
    assert len(preview_bytes) <= 256
    assert preview_bytes.startswith(b"x" * 40 + b"needle")
    assert b"other line" not in preview_bytes
    assert hashlib.sha256(preview_bytes).hexdigest() == preview.text_sha256
    assert preview.start_byte <= match.start_byte < match.end_byte <= preview.end_byte
    assert preview.cited_text.encode() == preview_bytes
    assert match.text_sha256 == hashlib.sha256(match_bytes).hexdigest()
    source = read_allowlisted_local_text(allowed_root=root, file_path=selected)
    verified_preview = verify_local_text_span(
        source,
        start_byte=preview.start_byte,
        end_byte=preview.end_byte,
    )
    assert verified_preview.bound_citation.span.span_id == preview.span_id
    assert verified_preview.bound_citation.span.text_sha256 == preview.text_sha256
    assert verified_preview.cited_text == preview.cited_text
    prefix, suffix = preview.cited_text.split("needle", maxsplit=1)
    assert len(prefix) <= 40
    assert len(suffix) <= 40
    assert "\r" not in preview.cited_text
    assert "\n" not in preview.cited_text


def test_preview_never_splits_codepoints_and_escapes_controls_for_display(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "unicode.md"
    payload = ("日本語" * 20 + " 🧭 target \x1b\x07\u202e tail\r\nnext").encode()
    selected.write_bytes(payload)

    result = search_selected_local_text_files(
        allowed_root=root,
        file_paths=(selected,),
        query="target",
        show_snippets=True,
    )

    preview = result.files[0].matches[0].preview
    assert preview is not None
    assert payload[: preview.start_byte].decode("utf-8")
    assert payload[: preview.end_byte].decode("utf-8")
    assert "日本語" in preview.cited_text


def test_display_escapes_controls_without_changing_verified_slice_digest(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "controls.txt"
    payload = b"left\x1b[31m\x07\x08\x00target" + "\u202e".encode() + b" right\r\nnext"
    selected.write_bytes(payload)

    result = search_selected_local_text_files(
        allowed_root=root,
        file_paths=(selected,),
        query="target",
        show_snippets=True,
    )
    match = result.files[0].matches[0]
    output = format_json_local_file_search(result)

    assert match.text_sha256 == hashlib.sha256(b"target").hexdigest()
    assert "\\x1b" in output
    assert "\\x07" in output
    assert "\\x08" in output
    assert "\\x00" in output
    assert "\\u202e" in output
    assert "\x1b" not in output
    assert "\x07" not in output
    assert "\x08" not in output
    assert "\x00" not in output
    assert "\u202e" not in output
