from __future__ import annotations

import os

import pytest

import sentinel.readers.local_text as local_text
from sentinel.readers import LocalTextError, LocalTextErrorCode, read_allowlisted_local_text


def _expect_path_error(root, target, code=LocalTextErrorCode.INVALID_PATH) -> None:
    with pytest.raises(LocalTextError) as error:
        read_allowlisted_local_text(allowed_root=root, file_path=target)
    assert error.value.code is code


def test_explicit_absolute_paths_and_root_confinement(tmp_path) -> None:
    root = tmp_path / "Notes"
    root.mkdir()
    selected = root / "ok.txt"
    selected.write_text("ok", encoding="utf-8")
    sibling = tmp_path / "NotesPrivate" / "secret.txt"
    sibling.parent.mkdir()
    sibling.write_text("outside", encoding="utf-8")

    _expect_path_error("relative-root", selected)
    _expect_path_error(root, "relative-file")
    _expect_path_error(root, sibling, LocalTextErrorCode.PATH_NOT_ALLOWED)
    _expect_path_error(root, root / "sub" / ".." / "ok.txt")


@pytest.mark.parametrize(
    "path_text",
    [
        r"\\server\share\notes",
        r"\\?\C:\notes\a.txt",
        r"\\.\C:\notes\a.txt",
        r"C:\notes\a.txt:stream",
        r"C:\notes\CON.txt",
        r"C:\notes\bad. ",
    ],
)
def test_network_device_ads_and_unsafe_windows_forms_rejected(tmp_path, path_text) -> None:
    root = tmp_path / "root"
    root.mkdir()
    _expect_path_error(root, path_text)


def test_missing_root_target_and_directory_are_rejected(tmp_path) -> None:
    root = tmp_path / "missing"
    _expect_path_error(root, root / "x.txt", LocalTextErrorCode.FILE_UNAVAILABLE)
    root.mkdir()
    _expect_path_error(root, root / "missing.txt", LocalTextErrorCode.FILE_UNAVAILABLE)
    directory = root / "subdir.txt"
    directory.mkdir()
    _expect_path_error(root, directory, LocalTextErrorCode.NOT_REGULAR_FILE)


def test_detectable_hard_link_alias_is_rejected(tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    original = root / "one.txt"
    alias = root / "two.txt"
    original.write_text("synthetic", encoding="utf-8")
    try:
        os.link(original, alias)
    except (OSError, NotImplementedError):
        pytest.fail("Expected the disposable local volume to support this hard-link boundary test.")

    _expect_path_error(root, original, LocalTextErrorCode.PATH_NOT_ALLOWED)
    _expect_path_error(root, alias, LocalTextErrorCode.PATH_NOT_ALLOWED)


def test_controlled_reparse_component_is_rejected(tmp_path, monkeypatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    selected = root / "x.txt"
    selected.write_text("safe", encoding="utf-8")
    monkeypatch.setattr(local_text, "_has_reparse_attribute", lambda _path: True)

    _expect_path_error(root, selected, LocalTextErrorCode.PATH_NOT_ALLOWED)
