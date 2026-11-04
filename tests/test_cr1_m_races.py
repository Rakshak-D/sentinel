from __future__ import annotations

from pathlib import Path

import pytest

import sentinel.readers.local_text as local_text
from sentinel.readers import LocalTextError, LocalTextErrorCode, read_allowlisted_local_text


def test_replacement_between_path_check_and_open_is_rejected(tmp_path, monkeypatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "note.txt"
    replacement = root / "replacement.txt"
    selected.write_bytes(b"before")
    replacement.write_bytes(b"after")

    original_open = local_text._create_file_handle
    replaced = False

    def replace_before_open(path: Path, *, directory: bool) -> int:
        nonlocal replaced
        if not directory and path == selected and not replaced:
            replaced = True
            replacement.replace(selected)
        return original_open(path, directory=directory)

    monkeypatch.setattr(local_text, "_create_file_handle", replace_before_open)

    with pytest.raises(LocalTextError) as error:
        read_allowlisted_local_text(allowed_root=root, file_path=selected)

    assert error.value.code is LocalTextErrorCode.FILE_CHANGED


def test_open_handle_denies_concurrent_write_and_preserves_original(tmp_path, monkeypatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "note.txt"
    selected.write_bytes(b"stable bytes")
    blocked: list[bool] = []

    original_read = local_text.os.read
    attempted = False

    def attempt_write(descriptor: int, size: int) -> bytes:
        nonlocal attempted
        if not attempted:
            attempted = True
            try:
                with selected.open("r+b") as handle:
                    handle.write(b"change")
            except PermissionError:
                blocked.append(True)
            else:
                blocked.append(False)
        return original_read(descriptor, size)

    monkeypatch.setattr(local_text.os, "read", attempt_write)
    result = read_allowlisted_local_text(allowed_root=root, file_path=selected)

    assert blocked == [True]
    assert result.normalized_source.original_bytes == b"stable bytes"
    assert selected.read_bytes() == b"stable bytes"
