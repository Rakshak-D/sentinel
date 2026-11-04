from __future__ import annotations

import json
import os
import struct
from pathlib import Path

import pytest
from cr1_h_support import BLOB_MAGIC, blob_path, prepare_store, rewrite_blob, split_blob

from sentinel.content import (
    MAX_BLOB_BYTES,
    PublicFixtureStoreError,
    PublicFixtureStoreErrorCode,
    read_public_fixture_blob,
)
from sentinel.readers.github_fixture import read_packaged_github_fixture


def test_missing_blob_is_reported_without_fixture_fallback(tmp_path: Path) -> None:
    root, _report = prepare_store(tmp_path / "store")
    missing_digest = "f" * 64
    assert not blob_path(root, missing_digest).exists()
    with pytest.raises(PublicFixtureStoreError) as error:
        read_public_fixture_blob(root, content_sha256=missing_digest)
    assert error.value.code is PublicFixtureStoreErrorCode.BLOB_NOT_FOUND
    assert not blob_path(root, missing_digest).exists()


@pytest.mark.parametrize(
    "mutation,payload",
    [
        (lambda metadata: metadata.update(extra="rejected") or metadata, None),
        (lambda metadata: metadata.update(sensitivity="PRIVATE") or metadata, None),
        (lambda metadata: metadata.update(retention_class="unbounded") or metadata, None),
        (lambda metadata: metadata.update(format_version="sentinel.blob.v2") or metadata, None),
        (lambda metadata: metadata.update(trust_provenance="T1 OWNER_INTENT") or metadata, None),
        (lambda metadata: metadata.update(fixture_sha256="0" * 64) or metadata, None),
        (lambda metadata: metadata.update(payload_byte_length=True) or metadata, None),
    ],
)
def test_unknown_or_unsupported_metadata_is_rejected(tmp_path, mutation, payload) -> None:
    root, report = prepare_store(tmp_path / "store")
    digest = report.blobs[0].content_sha256
    path = blob_path(root, digest)
    rewrite_blob(path, mutation, payload)
    with pytest.raises(PublicFixtureStoreError) as error:
        read_public_fixture_blob(root, content_sha256=digest)
    assert error.value.code is PublicFixtureStoreErrorCode.BLOB_INVALID


def test_duplicate_json_metadata_fields_are_rejected(tmp_path: Path) -> None:
    root, report = prepare_store(tmp_path / "store")
    digest = report.blobs[0].content_sha256
    path = blob_path(root, digest)
    metadata, prefix, metadata_bytes = split_blob(path)
    payload = path.read_bytes()[len(prefix) + len(metadata_bytes) :]
    header = json.dumps(metadata, separators=(",", ":"), sort_keys=True)
    duplicate = header[:-1] + ',"sensitivity":"PRIVATE"}'
    encoded = duplicate.encode("utf-8")
    path.write_bytes(BLOB_MAGIC + struct.pack(">I", len(encoded)) + encoded + payload)
    with pytest.raises(PublicFixtureStoreError) as error:
        read_public_fixture_blob(root, content_sha256=digest)
    assert error.value.code is PublicFixtureStoreErrorCode.BLOB_INVALID


def test_truncation_payload_digest_mismatch_and_trailing_bytes_are_rejected(tmp_path: Path) -> None:
    root, report = prepare_store(tmp_path / "store")
    digest = report.blobs[0].content_sha256
    path = blob_path(root, digest)
    original = path.read_bytes()

    path.write_bytes(original[:-1])
    with pytest.raises(PublicFixtureStoreError):
        read_public_fixture_blob(root, content_sha256=digest)

    path.write_bytes(original + b"trailing")
    with pytest.raises(PublicFixtureStoreError):
        read_public_fixture_blob(root, content_sha256=digest)

    altered = bytearray(original)
    altered[-1] ^= 1
    path.write_bytes(altered)
    with pytest.raises(PublicFixtureStoreError):
        read_public_fixture_blob(root, content_sha256=digest)

    path.write_bytes(original)
    rewrite_blob(path, lambda metadata: metadata.update(content_sha256="0" * 64) or metadata)
    with pytest.raises(PublicFixtureStoreError) as mismatch:
        read_public_fixture_blob(root, content_sha256=digest)
    assert mismatch.value.code is PublicFixtureStoreErrorCode.BLOB_INVALID


def test_oversized_blob_is_rejected(tmp_path: Path) -> None:
    root, report = prepare_store(tmp_path / "store")
    digest = report.blobs[0].content_sha256
    path = blob_path(root, digest)
    path.write_bytes(b"x" * (MAX_BLOB_BYTES + 8192))
    with pytest.raises(PublicFixtureStoreError) as error:
        read_public_fixture_blob(root, content_sha256=digest)
    assert error.value.code is PublicFixtureStoreErrorCode.BLOB_INVALID


def test_fixture_readback_does_not_call_packaged_fixture_loader(tmp_path, monkeypatch) -> None:
    from sentinel.content import public_fixture_store as store_module

    root, report = prepare_store(tmp_path / "store")
    original_bodies = [
        issue.normalized_source.original_bytes
        for issue in read_packaged_github_fixture().issues
    ]

    def forbidden_fixture_read():
        raise AssertionError("read API attempted to open packaged fixture")

    monkeypatch.setattr(store_module, "read_packaged_github_fixture", forbidden_fixture_read)
    for blob, expected in zip(report.blobs, original_bodies, strict=True):
        assert read_public_fixture_blob(root, content_sha256=blob.content_sha256) == expected


def test_hard_linked_blob_is_rejected_and_original_recovers_after_alias_removed(
    tmp_path: Path,
) -> None:
    root, report = prepare_store(tmp_path / "store")
    digest = report.blobs[0].content_sha256
    path = blob_path(root, digest)
    alias = tmp_path / "outside-hardlink.blob"
    os.link(path, alias)
    try:
        with pytest.raises(PublicFixtureStoreError) as error:
            read_public_fixture_blob(root, content_sha256=digest)
        assert error.value.code is PublicFixtureStoreErrorCode.BLOB_INVALID
    finally:
        alias.unlink()
    assert read_public_fixture_blob(root, content_sha256=digest)


def test_final_component_symlink_is_refused_or_controlled_check_is_exercised(
    tmp_path: Path, monkeypatch
) -> None:
    from sentinel.content import public_fixture_store as store_module

    root, report = prepare_store(tmp_path / "store")
    digest = report.blobs[0].content_sha256
    path = blob_path(root, digest)
    preserved_blob = path.read_bytes()
    external_target = tmp_path / "outside-target"
    external_target.write_bytes(b"synthetic outside bytes")
    path.unlink()
    try:
        path.symlink_to(external_target)
    except OSError:
        path.write_bytes(preserved_blob)
        original = store_module._is_reparse_point
        monkeypatch.setattr(
            store_module,
            "_is_reparse_point",
            lambda candidate: Path(candidate) == path or original(Path(candidate)),
        )
    try:
        with pytest.raises(PublicFixtureStoreError) as error:
            read_public_fixture_blob(root, content_sha256=digest)
        assert error.value.code in {
            PublicFixtureStoreErrorCode.BLOB_INVALID,
            PublicFixtureStoreErrorCode.STORE_INVALID,
        }
    finally:
        if path.is_symlink():
            path.unlink()
        if not path.exists():
            path.write_bytes(preserved_blob)
    monkeypatch.undo()
    assert read_public_fixture_blob(root, content_sha256=digest)


def test_changed_packaged_fixture_identity_is_rejected_before_writes(tmp_path, monkeypatch) -> None:
    from dataclasses import replace

    from sentinel.content import public_fixture_store as store_module

    root = tmp_path / "store"
    from sentinel.content import initialize_public_fixture_store

    initialize_public_fixture_store(root)
    fixture = read_packaged_github_fixture()
    monkeypatch.setattr(
        store_module,
        "read_packaged_github_fixture",
        lambda: replace(fixture, fixture_sha256="0" * 64),
    )
    with pytest.raises(PublicFixtureStoreError) as error:
        store_module.store_packaged_github_public_bodies(root)
    assert error.value.code is PublicFixtureStoreErrorCode.FIXTURE_INVALID
    assert not list((root / "public-v1" / "sha256").glob("*.blob"))


def test_header_bound_is_enforced(tmp_path: Path) -> None:
    root, report = prepare_store(tmp_path / "store")
    digest = report.blobs[0].content_sha256
    path = blob_path(root, digest)
    path.write_bytes(BLOB_MAGIC + struct.pack(">I", 8192) + b"x" * 8192)
    with pytest.raises(PublicFixtureStoreError):
        read_public_fixture_blob(root, content_sha256=digest)
