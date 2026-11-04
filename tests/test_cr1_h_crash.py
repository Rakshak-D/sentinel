from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from cr1_h_support import EXPECTED_BODY_DIGESTS

from sentinel.content import (
    PublicFixtureStoreError,
    read_public_fixture_blob,
    store_packaged_github_public_bodies,
)
from sentinel.readers.github_fixture import read_packaged_github_fixture


def _run_writer_crash(
    root: Path, tmp_path: Path, code: str, exit_code: int
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["SENTINEL_TEST_STORE_ROOT"] = str(root)
    process = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert process.returncode == exit_code
    assert process.stdout == ""
    assert process.stderr == ""
    return process


def test_failed_prepublication_write_removes_own_temp_and_no_final(
    tmp_path: Path, monkeypatch
) -> None:
    from sentinel.content import public_fixture_store as store_module

    root = tmp_path / "store"
    from sentinel.content import initialize_public_fixture_store

    initialize_public_fixture_store(root)

    def fail_before_publish(_temporary: Path, _final: Path, _identity: object) -> None:
        raise OSError("SYNTHETIC-CANARY")

    monkeypatch.setattr(store_module, "_publish_no_clobber", fail_before_publish)
    with pytest.raises(PublicFixtureStoreError) as error:
        store_packaged_github_public_bodies(root)
    assert "SYNTHETIC-CANARY" not in str(error.value)
    assert not list((root / "public-v1" / "sha256").glob("*.blob"))
    assert not list((root / "public-v1" / "sha256").glob(".tmp-*.part"))


def test_process_exit_before_publication_leaves_no_final_blob(tmp_path: Path) -> None:
    from sentinel.content import initialize_public_fixture_store

    root = tmp_path / "store"
    initialize_public_fixture_store(root)
    code = (
        "import os; from pathlib import Path; "
        "import sentinel.content.public_fixture_store as m; "
        "m._publish_no_clobber=lambda *_: os._exit(71); "
        "m.store_packaged_github_public_bodies(Path(os.environ['SENTINEL_TEST_STORE_ROOT']))"
    )
    _run_writer_crash(root, tmp_path, code, 71)

    folder = root / "public-v1" / "sha256"
    assert not list(folder.glob("*.blob"))
    assert list(folder.glob(".tmp-*.part"))
    with pytest.raises(PublicFixtureStoreError):
        read_public_fixture_blob(root, content_sha256=next(iter(EXPECTED_BODY_DIGESTS)))


def test_process_exit_after_publication_leaves_readable_complete_blob(tmp_path: Path) -> None:
    from sentinel.content import initialize_public_fixture_store

    root = tmp_path / "store"
    initialize_public_fixture_store(root)
    code = (
        "import os; from pathlib import Path; "
        "import sentinel.content.public_fixture_store as m; "
        "m._read_blob=lambda *_: os._exit(72); "
        "m.store_packaged_github_public_bodies(Path(os.environ['SENTINEL_TEST_STORE_ROOT']))"
    )
    _run_writer_crash(root, tmp_path, code, 72)

    fixture = read_packaged_github_fixture()
    expected_by_digest = {
        issue.normalized_source.envelope.content_sha256: issue.normalized_source.original_bytes
        for issue in fixture.issues
    }
    published = list((root / "public-v1" / "sha256").glob("*.blob"))
    assert len(published) == 1
    digest = published[0].stem
    assert read_public_fixture_blob(root, content_sha256=digest) == expected_by_digest[digest]


def test_failure_after_publish_leaves_complete_blob_not_corrupted(tmp_path, monkeypatch) -> None:
    from sentinel.content import initialize_public_fixture_store
    from sentinel.content import public_fixture_store as store_module

    root = tmp_path / "store"
    initialize_public_fixture_store(root)
    original_read = store_module._read_blob
    raised = False

    def fail_first_read(store_root: Path, digest: str) -> bytes:
        nonlocal raised
        if not raised:
            raised = True
            raise OSError("SYNTHETIC-CANARY")
        return original_read(store_root, digest)

    monkeypatch.setattr(store_module, "_read_blob", fail_first_read)
    with pytest.raises(PublicFixtureStoreError):
        store_packaged_github_public_bodies(root)
    assert raised
    published = list((root / "public-v1" / "sha256").glob("*.blob"))
    assert len(published) == 1
    digest = published[0].stem
    assert read_public_fixture_blob(root, content_sha256=digest)
