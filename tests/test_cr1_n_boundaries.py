from __future__ import annotations

import pytest

import sentinel.readers.local_search as local_search
from sentinel.readers import (
    LocalSearchError,
    LocalSearchErrorCode,
    LocalTextError,
    search_selected_local_text_files,
)


def _search(root, paths, query="x", **kwargs):
    return search_selected_local_text_files(
        allowed_root=root, file_paths=paths, query=query, **kwargs
    )


@pytest.mark.parametrize(
    "query",
    [
        "",
        "x" * 129,
        "x" * 128 + "🧭",
        "a\x00b",
        "a\x1bb",
        "a\x9bb",
        "a\tb",
        "a\nb",
        "a\rb",
        "a\u202eb",
        "\ud800",
    ],
)
def test_invalid_queries_fail_before_opening_files(tmp_path, monkeypatch, query) -> None:
    def forbidden(**_kwargs):
        raise AssertionError("invalid query must be rejected before any file read")

    monkeypatch.setattr(local_search, "read_allowlisted_local_text", forbidden)
    with pytest.raises(LocalSearchError) as error:
        _search(tmp_path / "unused", (tmp_path / "not-opened.txt",), query)
    assert error.value.code is LocalSearchErrorCode.INVALID_QUERY


def test_ninth_file_and_duplicate_case_alias_are_rejected(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "one.txt"
    selected.write_text("x", encoding="utf-8")

    with pytest.raises(LocalSearchError) as too_many:
        _search(root, tuple(root / f"{n}.txt" for n in range(9)))
    assert too_many.value.code is LocalSearchErrorCode.TOO_MANY_FILES

    with pytest.raises(LocalSearchError) as duplicate:
        _search(root, (selected, type(selected)(str(selected).upper())))
    assert duplicate.value.code is LocalSearchErrorCode.DUPLICATE_FILE


def test_more_than_32_matches_fails_closed(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "many.txt"
    selected.write_bytes(b"x" * 33)

    with pytest.raises(LocalSearchError) as error:
        _search(root, (selected,))

    assert error.value.code is LocalSearchErrorCode.TOO_MANY_MATCHES
    assert "x" not in str(error.value)
    assert str(selected) not in str(error.value)


def test_preview_rejects_query_that_cannot_fit_its_byte_budget(tmp_path, monkeypatch) -> None:
    def forbidden(**_kwargs):
        raise AssertionError("impossible preview must fail before reading files")

    monkeypatch.setattr(local_search, "read_allowlisted_local_text", forbidden)
    with pytest.raises(LocalSearchError) as error:
        _search(tmp_path, (tmp_path / "unused.txt",), "🧭" * 65, show_snippets=True)
    assert error.value.code is LocalSearchErrorCode.PREVIEW_UNAVAILABLE


def test_missing_final_file_rejects_whole_search(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    first = root / "first.txt"
    first.write_text("x", encoding="utf-8")

    with pytest.raises(LocalTextError):
        _search(root, (first, root / "missing.txt"))


@pytest.mark.parametrize(
    ("root_value", "file_value"),
    [
        ("relative-root", "relative-root/note.txt"),
        ("C:\\Notes", "C:\\NotesPrivate\\note.txt"),
        ("C:\\Notes", "C:\\Notes\\..\\outside.txt"),
        ("\\\\server\\share", "\\\\server\\share\\note.txt"),
        ("\\\\?\\C:\\Notes", "\\\\?\\C:\\Notes\\note.txt"),
    ],
)
def test_unsafe_path_forms_are_delegated_to_the_existing_reader(
    root_value: str, file_value: str
) -> None:
    with pytest.raises(LocalTextError):
        _search(root_value, (file_value,))


def test_unsupported_extension_invalid_utf8_and_oversize_fail_closed(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    unsupported = root / "note.csv"
    unsupported.write_bytes(b"x")
    invalid_utf8 = root / "invalid.txt"
    invalid_utf8.write_bytes(b"bad:\xff")
    oversized = root / "oversized.md"
    oversized.write_bytes(b"x" * (1_048_576 + 1))

    for selected in (unsupported, invalid_utf8, oversized):
        with pytest.raises(LocalTextError) as error:
            _search(root, (selected,))
        assert str(selected) not in str(error.value)


def test_search_does_not_use_database_network_or_subprocess_apis(tmp_path, monkeypatch) -> None:
    import socket
    import sqlite3
    import subprocess
    import urllib.request

    root = tmp_path / "root"
    root.mkdir()
    selected = root / "note.txt"
    selected.write_bytes(b"needle")
    before_bytes = selected.read_bytes()
    before_names = sorted(path.name for path in root.iterdir())

    def forbidden(*_args, **_kwargs):
        raise AssertionError("search must not use persistence or external operations")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    result = _search(root, (selected,), query="needle")

    assert result.total_match_count == 1
    assert selected.read_bytes() == before_bytes
    assert sorted(path.name for path in root.iterdir()) == before_names
