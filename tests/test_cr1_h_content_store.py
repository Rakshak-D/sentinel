from __future__ import annotations

import hashlib
import inspect
import os
import re
from pathlib import Path

import pytest
from cr1_h_support import EXPECTED_BODY_DIGESTS, blob_path, prepare_store, split_blob

from sentinel.content import (
    MAX_BLOB_BYTES,
    STORE_FORMAT_VERSION,
    PublicFixtureStoreError,
    PublicFixtureStoreErrorCode,
    initialize_public_fixture_store,
    read_public_fixture_blob,
    store_packaged_github_public_bodies,
)
from sentinel.contracts.labels import SensitivityLabel, TrustLabel
from sentinel.readers.github_fixture import read_packaged_github_fixture


def test_explicit_store_initialization_and_reinitialization(tmp_path: Path) -> None:
    root = tmp_path / "selected-public-store"
    initialize_public_fixture_store(root)
    marker = root / "store-format-v1.json"
    assert marker.is_file()
    assert STORE_FORMAT_VERSION.encode() in marker.read_bytes()
    original_marker = marker.read_bytes()
    initialize_public_fixture_store(root)
    assert marker.read_bytes() == original_marker


def test_packaged_fixture_bodies_are_stored_exactly(tmp_path: Path) -> None:
    root = tmp_path / "store"
    initialize_public_fixture_store(root)
    fixture = read_packaged_github_fixture()
    report = store_packaged_github_public_bodies(root)

    assert report.inserted_count == 3
    assert report.existing_count == 0
    assert len(report.blobs) == 3
    assert {blob.content_sha256 for blob in report.blobs} == EXPECTED_BODY_DIGESTS
    assert report.fixture_sha256 == fixture.fixture_sha256
    assert report.fixture_version == fixture.fixture_version

    lengths = []
    for issue, stored in zip(fixture.issues, report.blobs, strict=True):
        body = issue.normalized_source.original_bytes
        digest = hashlib.sha256(body).hexdigest()
        assert stored.content_sha256 == digest
        assert stored.payload_byte_length == len(body) <= MAX_BLOB_BYTES
        assert read_public_fixture_blob(root, content_sha256=digest) == body
        lengths.append(len(body))
    assert len(lengths) == 3
    assert any(b"\r\n" in issue.normalized_source.original_bytes for issue in fixture.issues)
    assert any(b"\n" in issue.normalized_source.original_bytes for issue in fixture.issues)
    assert any(
        any(ord(character) > 0xFFFF for character in issue.body_text)
        for issue in fixture.issues
    )
    assert any(
        any("\u3040" <= character <= "\u30ff" or "\u4e00" <= character <= "\u9fff"
            for character in issue.body_text)
        for issue in fixture.issues
    )


def test_blob_metadata_is_bounded_body_free_and_preserves_labels(tmp_path: Path) -> None:
    root, report = prepare_store(tmp_path / "store")
    fixture = read_packaged_github_fixture()

    for issue, stored in zip(fixture.issues, report.blobs, strict=True):
        path = blob_path(root, stored.content_sha256)
        metadata, _prefix, header = split_blob(path)
        assert metadata == {
            "content_sha256": stored.content_sha256,
            "fixture_sha256": fixture.fixture_sha256,
            "fixture_version": fixture.fixture_version,
            "format_version": "sentinel.public-fixture-blob.v1",
            "payload_byte_length": len(issue.normalized_source.original_bytes),
            "retention_class": "fixture_public",
            "sensitivity": SensitivityLabel.PUBLIC.value,
            "trust_provenance": TrustLabel.T4_EXTERNAL.value,
        }
        assert issue.title.encode("utf-8") not in header
        assert issue.normalized_source.original_bytes not in header
        assert set(metadata) == {
            "content_sha256",
            "fixture_sha256",
            "fixture_version",
            "format_version",
            "payload_byte_length",
            "retention_class",
            "sensitivity",
            "trust_provenance",
        }


def test_repeated_storage_is_idempotent_and_does_not_rewrite_blobs(tmp_path: Path) -> None:
    root, first = prepare_store(tmp_path / "store")
    before = {
        blob.content_sha256: (
            blob_path(root, blob.content_sha256).read_bytes(),
            blob_path(root, blob.content_sha256).stat().st_mtime_ns,
        )
        for blob in first.blobs
    }

    second = store_packaged_github_public_bodies(root)
    third = store_packaged_github_public_bodies(root)

    for repeated in (second, third):
        assert repeated.inserted_count == 0
        assert repeated.existing_count == 3
        assert repeated.blobs == first.blobs
    for digest, (original, mtime_ns) in before.items():
        path = blob_path(root, digest)
        assert path.read_bytes() == original
        assert path.stat().st_mtime_ns == mtime_ns


def test_uninitialized_store_and_relative_or_unc_roots_fail_closed(tmp_path: Path) -> None:
    relative = Path("relative-public-store")
    with pytest.raises(PublicFixtureStoreError) as relative_error:
        initialize_public_fixture_store(relative)
    assert relative_error.value.code is PublicFixtureStoreErrorCode.INVALID_ROOT

    missing = tmp_path / "not-initialized"
    with pytest.raises(PublicFixtureStoreError) as read_error:
        read_public_fixture_blob(missing, content_sha256=next(iter(EXPECTED_BODY_DIGESTS)))
    assert read_error.value.code is PublicFixtureStoreErrorCode.STORE_UNINITIALIZED
    with pytest.raises(PublicFixtureStoreError) as write_error:
        store_packaged_github_public_bodies(missing)
    assert write_error.value.code is PublicFixtureStoreErrorCode.STORE_UNINITIALIZED
    assert not missing.exists()

    missing_parent = tmp_path / "must-not-create-parent" / "store"
    with pytest.raises(PublicFixtureStoreError) as parent_error:
        initialize_public_fixture_store(missing_parent)
    assert parent_error.value.code is PublicFixtureStoreErrorCode.INVALID_ROOT
    assert not missing_parent.parent.exists()

    if os.name == "nt":
        with pytest.raises(PublicFixtureStoreError) as unc_error:
            initialize_public_fixture_store(r"\\example.invalid\share\fixture-store")
        assert unc_error.value.code is PublicFixtureStoreErrorCode.UNSUPPORTED_FILESYSTEM


def test_invalid_digest_and_traversal_never_select_a_path(tmp_path: Path) -> None:
    root, _report = prepare_store(tmp_path / "store")
    for invalid in ("../outside", "..", "A" * 64, "g" * 64, "0" * 63):
        with pytest.raises(PublicFixtureStoreError) as error:
            read_public_fixture_blob(root, content_sha256=invalid)
        assert error.value.code is PublicFixtureStoreErrorCode.INVALID_DIGEST


def test_fixed_fixture_api_has_no_arbitrary_content_or_destination_inputs() -> None:
    store_parameters = tuple(inspect.signature(store_packaged_github_public_bodies).parameters)
    read_parameters = tuple(inspect.signature(read_public_fixture_blob).parameters)
    assert store_parameters == ("root",)
    assert read_parameters == ("root", "content_sha256")


def test_windows_no_clobber_rename_preserves_existing_destination(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.fail("CR1-H acceptance requires the target Windows filesystem behavior")
    source = tmp_path / "new.tmp"
    destination = tmp_path / "already.blob"
    source.write_bytes(b"new bytes")
    destination.write_bytes(b"existing bytes")

    with pytest.raises(FileExistsError):
        os.rename(source, destination)

    assert source.read_bytes() == b"new bytes"
    assert destination.read_bytes() == b"existing bytes"


def test_reparse_components_are_refused_with_controlled_boundary(tmp_path, monkeypatch) -> None:
    from sentinel.content import public_fixture_store as store_module

    root, report = prepare_store(tmp_path / "store")
    target = root / "public-v1"
    original = store_module._is_reparse_point
    monkeypatch.setattr(
        store_module,
        "_is_reparse_point",
        lambda candidate: Path(candidate) == target or original(Path(candidate)),
    )
    with pytest.raises(PublicFixtureStoreError) as error:
        read_public_fixture_blob(root, content_sha256=report.blobs[0].content_sha256)
    assert error.value.code is PublicFixtureStoreErrorCode.STORE_INVALID


def test_root_symlink_is_refused_or_controlled_reparse_check_is_exercised(
    tmp_path: Path, monkeypatch
) -> None:
    from sentinel.content import public_fixture_store as store_module

    root, report = prepare_store(tmp_path / "store")
    linked_root = tmp_path / "root-link"
    try:
        linked_root.symlink_to(root, target_is_directory=True)
    except OSError:
        original = store_module._is_reparse_point
        monkeypatch.setattr(
            store_module,
            "_is_reparse_point",
            lambda candidate: Path(candidate) == root or original(Path(candidate)),
        )
        selected = root
    else:
        selected = linked_root
    with pytest.raises(PublicFixtureStoreError) as error:
        read_public_fixture_blob(selected, content_sha256=report.blobs[0].content_sha256)
    assert error.value.code is PublicFixtureStoreErrorCode.STORE_INVALID


def test_body_canary_is_not_echoed_in_failures_or_report_repr(tmp_path: Path) -> None:
    root, report = prepare_store(tmp_path / "SYNTHETIC-PRIVATE-CANARY-store")
    canaries = [issue.body_text.encode("utf-8") for issue in read_packaged_github_fixture().issues]
    rendered = repr(report).encode("utf-8")
    assert all(canary not in rendered for canary in canaries)

    with pytest.raises(PublicFixtureStoreError) as error:
        read_public_fixture_blob(root, content_sha256="body text is not a digest")
    assert "SYNTHETIC-PRIVATE-CANARY" not in str(error.value)
    assert str(root) not in str(error.value)
    assert re.search(r"[\r\n]", str(error.value)) is None
