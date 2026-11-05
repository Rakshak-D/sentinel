from __future__ import annotations

import json

import pytest

import sentinel.readers.notes_registry as notes_registry
from sentinel.readers.notes_registry import (
    LOCAL_NOTES_REGISTRY_SCHEMA_VERSION,
    build_local_notes_registry,
    format_json_local_notes_registry,
    verify_local_notes_registry,
)
from sentinel.readers.notes_registry_types import (
    LocalNotesEntryStatus,
    LocalNotesRegistryError,
    LocalNotesRegistryErrorCode,
)


def _save_registry(root, *paths):
    registry_path = root / "baseline.txt"
    registry_path.write_text(
        format_json_local_notes_registry(
            build_local_notes_registry(allowed_root=root, file_paths=paths)
        ),
        encoding="utf-8",
    )
    return registry_path


def _registry_bytes(*entries):
    return json.dumps(
        {"schema_version": LOCAL_NOTES_REGISTRY_SCHEMA_VERSION, "entries": list(entries)},
        separators=(",", ":"),
    ).encode("utf-8")


def _entry(path: str, *, length: int = 1, digest: str | None = None):
    return {
        "relative_path": path,
        "byte_length": length,
        "content_sha256": digest or "0" * 64,
    }


def test_crlf_change_is_detected_without_rewriting_the_baseline(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    note = root / "line.txt"
    note.write_bytes(b"one\r\ntwo\r\n")
    registry_path = _save_registry(root, note)
    baseline_bytes = registry_path.read_bytes()

    note.write_bytes(b"one\ntwo\n")
    changed = verify_local_notes_registry(allowed_root=root, registry_path=registry_path)

    assert changed.entries[0].status is LocalNotesEntryStatus.CHANGED
    assert registry_path.read_bytes() == baseline_bytes


def test_missing_note_fails_closed_with_bounded_error(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    note = root / "note.txt"
    note.write_bytes(b"present")
    registry_path = _save_registry(root, note)
    note.unlink()

    with pytest.raises(LocalNotesRegistryError) as error:
        verify_local_notes_registry(allowed_root=root, registry_path=registry_path)
    assert error.value.code is LocalNotesRegistryErrorCode.FILE_UNAVAILABLE
    assert str(root) not in str(error.value)
    assert "present" not in str(error.value)


@pytest.mark.parametrize(
    "entry_path",
    [
        "../outside.txt",
        "C:/outside.txt",
        "//server/share/note.txt",
        "\\\\?\\C:\\outside.txt",
        "note.txt:stream",
        "CON.txt",
        "folder//note.txt",
        "folder/./note.txt",
        "folder/name. /note.txt",
        "folder\\note.txt",
        "baseline.txt",
    ],
)
def test_unsafe_or_self_referencing_registry_paths_are_rejected(tmp_path, entry_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    registry_path = root / "baseline.txt"
    registry_path.write_bytes(_registry_bytes(_entry(entry_path)))

    with pytest.raises(LocalNotesRegistryError) as error:
        verify_local_notes_registry(allowed_root=root, registry_path=registry_path)
    assert error.value.code is LocalNotesRegistryErrorCode.INVALID_REGISTRY
    assert str(root) not in str(error.value)


def test_duplicate_case_alias_entries_and_invalid_hashes_are_rejected(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    registry_path = root / "baseline.txt"
    registry_path.write_bytes(_registry_bytes(_entry("Note.txt"), _entry("note.TXT")))
    with pytest.raises(LocalNotesRegistryError) as duplicate:
        verify_local_notes_registry(allowed_root=root, registry_path=registry_path)
    assert duplicate.value.code is LocalNotesRegistryErrorCode.INVALID_REGISTRY

    registry_path.write_bytes(_registry_bytes(_entry("note.txt", digest="g" * 64)))
    with pytest.raises(LocalNotesRegistryError) as digest:
        verify_local_notes_registry(allowed_root=root, registry_path=registry_path)
    assert digest.value.code is LocalNotesRegistryErrorCode.INVALID_REGISTRY


def test_invalid_utf8_registry_is_rejected_before_note_following(
    tmp_path, monkeypatch
) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    registry_path = root / "baseline.txt"
    registry_path.write_bytes(b"\xff")

    original_read = notes_registry.read_allowlisted_local_text
    calls = []

    def registry_only_read(*, allowed_root, file_path):
        calls.append(file_path)
        if file_path != registry_path:
            raise AssertionError("invalid registry must not cause note reads")
        return original_read(allowed_root=allowed_root, file_path=file_path)

    monkeypatch.setattr(notes_registry, "read_allowlisted_local_text", registry_only_read)
    with pytest.raises(LocalNotesRegistryError) as error:
        verify_local_notes_registry(allowed_root=root, registry_path=registry_path)
    assert error.value.code is LocalNotesRegistryErrorCode.INVALID_REGISTRY
    assert calls == [registry_path]


def test_detectable_note_edit_between_reads_rejects_the_verification(tmp_path, monkeypatch) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    note = root / "note.txt"
    note.write_bytes(b"before")
    registry_path = _save_registry(root, note)
    original_read = notes_registry.read_allowlisted_local_text
    changed = False

    def edit_after_first_note_read(*, allowed_root, file_path):
        nonlocal changed
        source = original_read(allowed_root=allowed_root, file_path=file_path)
        if file_path == note and not changed:
            changed = True
            note.write_bytes(b"after!")
        return source

    monkeypatch.setattr(notes_registry, "read_allowlisted_local_text", edit_after_first_note_read)
    with pytest.raises(LocalNotesRegistryError) as error:
        verify_local_notes_registry(allowed_root=root, registry_path=registry_path)
    assert changed
    assert error.value.code is LocalNotesRegistryErrorCode.FILE_CHANGED


def test_detectable_registry_edit_between_reads_rejects_verification(tmp_path, monkeypatch) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    note = root / "note.txt"
    note.write_bytes(b"note")
    registry_path = _save_registry(root, note)
    original_read = notes_registry.read_allowlisted_local_text
    changed = False

    def edit_after_registry_read(*, allowed_root, file_path):
        nonlocal changed
        source = original_read(allowed_root=allowed_root, file_path=file_path)
        if file_path == registry_path and not changed:
            changed = True
            registry_path.write_bytes(b"{}")
        return source

    monkeypatch.setattr(notes_registry, "read_allowlisted_local_text", edit_after_registry_read)
    with pytest.raises(LocalNotesRegistryError) as error:
        verify_local_notes_registry(allowed_root=root, registry_path=registry_path)
    assert changed
    assert error.value.code is LocalNotesRegistryErrorCode.INVALID_REGISTRY or (
        error.value.code is LocalNotesRegistryErrorCode.FILE_CHANGED
    )


def test_detectable_edit_during_registry_build_is_rejected(tmp_path, monkeypatch) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    note = root / "note.txt"
    note.write_bytes(b"before")
    original_read = notes_registry.read_allowlisted_local_text
    changed = False

    def edit_after_first_read(*, allowed_root, file_path):
        nonlocal changed
        source = original_read(allowed_root=allowed_root, file_path=file_path)
        if file_path == note and not changed:
            changed = True
            note.write_bytes(b"after!")
        return source

    monkeypatch.setattr(notes_registry, "read_allowlisted_local_text", edit_after_first_read)
    with pytest.raises(LocalNotesRegistryError) as error:
        build_local_notes_registry(allowed_root=root, file_paths=(note,))
    assert changed
    assert error.value.code is LocalNotesRegistryErrorCode.FILE_CHANGED


def test_registry_size_limit_is_applied_after_bounded_reader_read(tmp_path) -> None:
    root = tmp_path / "notes"
    root.mkdir()
    registry_path = root / "baseline.txt"
    registry_path.write_bytes(b" " * (16 * 1024 + 1))

    with pytest.raises(LocalNotesRegistryError) as error:
        verify_local_notes_registry(allowed_root=root, registry_path=registry_path)
    assert error.value.code is LocalNotesRegistryErrorCode.TOO_LARGE
