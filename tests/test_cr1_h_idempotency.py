from __future__ import annotations

from pathlib import Path

import pytest
from cr1_h_support import blob_path, prepare_store

from sentinel.content import (
    PublicFixtureStoreError,
    PublicFixtureStoreErrorCode,
    read_public_fixture_blob,
    store_packaged_github_public_bodies,
)


def test_valid_existing_blob_is_verified_and_never_clobbered(tmp_path: Path) -> None:
    root, first = prepare_store(tmp_path / "store")
    digest = first.blobs[0].content_sha256
    path = blob_path(root, digest)
    original = path.read_bytes()
    original_stat = path.stat()

    second = store_packaged_github_public_bodies(root)
    assert second.existing_count == 3
    assert path.read_bytes() == original
    assert path.stat().st_ino == original_stat.st_ino
    assert path.stat().st_mtime_ns == original_stat.st_mtime_ns


def test_corrupted_existing_blob_is_not_silently_repaired(tmp_path: Path) -> None:
    root, first = prepare_store(tmp_path / "store")
    digest = first.blobs[0].content_sha256
    path = blob_path(root, digest)
    corrupted = path.read_bytes()[:-1]
    path.write_bytes(corrupted)

    with pytest.raises(PublicFixtureStoreError) as error:
        store_packaged_github_public_bodies(root)
    assert error.value.code is PublicFixtureStoreErrorCode.BLOB_INVALID
    assert path.read_bytes() == corrupted


def test_bad_store_format_is_rejected_without_repair(tmp_path: Path) -> None:
    root, _report = prepare_store(tmp_path / "store")
    marker = root / "store-format-v1.json"
    original = marker.read_bytes()
    marker.write_bytes(b'{"format_version":"sentinel.public-fixture-store.v99"}')

    with pytest.raises(PublicFixtureStoreError) as error:
        read_public_fixture_blob(root, content_sha256="0" * 64)
    assert error.value.code is PublicFixtureStoreErrorCode.STORE_INVALID
    assert marker.read_bytes() != original
    assert marker.read_bytes() == b'{"format_version":"sentinel.public-fixture-store.v99"}'


def test_unrecognized_store_entry_is_rejected_without_cleanup(tmp_path: Path) -> None:
    root, _report = prepare_store(tmp_path / "store")
    unexpected = root / "unrecognized.txt"
    unexpected.write_text("synthetic extra", encoding="utf-8")
    with pytest.raises(PublicFixtureStoreError) as error:
        store_packaged_github_public_bodies(root)
    assert error.value.code is PublicFixtureStoreErrorCode.STORE_INVALID
    assert unexpected.read_text(encoding="utf-8") == "synthetic extra"
