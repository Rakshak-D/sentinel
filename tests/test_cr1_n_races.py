from __future__ import annotations

from pathlib import Path

import pytest

import sentinel.readers.local_search as local_search
from sentinel.readers import LocalSearchError, LocalSearchErrorCode


def test_mutation_between_search_and_final_validation_fails_closed(tmp_path, monkeypatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "note.txt"
    selected.write_text("needle original", encoding="utf-8")
    original_read = local_search.read_allowlisted_local_text
    calls = 0

    def mutate_on_revalidation(*, allowed_root, file_path):
        nonlocal calls
        calls += 1
        if calls == 2:
            Path(file_path).write_text("needle changed", encoding="utf-8")
        return original_read(allowed_root=allowed_root, file_path=file_path)

    monkeypatch.setattr(local_search, "read_allowlisted_local_text", mutate_on_revalidation)

    with pytest.raises(LocalSearchError) as error:
        local_search.search_selected_local_text_files(
            allowed_root=root, file_paths=(selected,), query="needle"
        )

    assert error.value.code is LocalSearchErrorCode.SOURCE_CHANGED
