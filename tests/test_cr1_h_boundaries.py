from __future__ import annotations

import inspect
import socket
import subprocess
import urllib.request
from pathlib import Path

import pytest
from cr1_h_support import prepare_store

from sentinel.content import (
    PublicFixtureStoreError,
    initialize_public_fixture_store,
    read_public_fixture_blob,
    store_packaged_github_public_bodies,
)
from sentinel.readers.github_fixture import read_packaged_github_fixture


def test_unexpected_root_objects_are_rejected_without_stringification(tmp_path: Path) -> None:
    class HostilePath:
        def __fspath__(self) -> str:
            raise AssertionError("path object evaluated")

        def __str__(self) -> str:
            raise AssertionError("path object stringified")

        def __repr__(self) -> str:
            raise AssertionError("path object repr evaluated")

    with pytest.raises(PublicFixtureStoreError):
        initialize_public_fixture_store(HostilePath())  # type: ignore[arg-type]


def test_no_network_subprocess_or_gateway_operation_is_needed(tmp_path, monkeypatch) -> None:
    root = tmp_path / "store"
    initialize_public_fixture_store(root)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("external operation attempted")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    report = store_packaged_github_public_bodies(root)
    assert report.inserted_count == 3
    assert all(
        read_public_fixture_blob(root, content_sha256=blob.content_sha256)
        for blob in report.blobs
    )


def test_private_gmail_fixture_is_not_a_write_source(tmp_path, monkeypatch) -> None:
    from sentinel.content import public_fixture_store as store_module
    from sentinel.readers import gmail_fixture

    root = tmp_path / "store"
    initialize_public_fixture_store(root)
    called = False

    def forbidden_gmail_read():
        nonlocal called
        called = True
        raise AssertionError("Gmail fixture accessed")

    monkeypatch.setattr(gmail_fixture, "read_packaged_gmail_fixture", forbidden_gmail_read)
    report = store_packaged_github_public_bodies(root)
    assert report.inserted_count == 3
    assert not called
    assert store_module.read_packaged_github_fixture is read_packaged_github_fixture


def test_representations_and_errors_never_include_issue_title_or_body(tmp_path: Path) -> None:
    root, report = prepare_store(tmp_path / "store")
    fixture = read_packaged_github_fixture()
    redacted = repr(report)
    for issue in fixture.issues:
        assert issue.title not in redacted
        assert issue.body_text not in redacted
    with pytest.raises(PublicFixtureStoreError) as error:
        read_public_fixture_blob(root, content_sha256="not-a-real-digest")
    for issue in fixture.issues:
        assert issue.title not in str(error.value)
        assert issue.body_text not in str(error.value)


def test_result_contract_is_immutable_and_body_free(tmp_path: Path) -> None:
    _root, report = prepare_store(tmp_path / "store")
    assert "bytes" not in inspect.signature(type(report)).parameters
    assert report.inserted_count == 3
    with pytest.raises((AttributeError, TypeError)):
        report.inserted_count = 4  # type: ignore[misc]
