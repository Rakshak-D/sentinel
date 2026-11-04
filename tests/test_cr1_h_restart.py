from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from cr1_h_support import prepare_store

from sentinel.content import read_public_fixture_blob
from sentinel.readers.github_fixture import read_packaged_github_fixture


def test_independent_process_reads_exact_bytes_without_fixture_resource(tmp_path: Path) -> None:
    root, report = prepare_store(tmp_path / "selected-store")
    expected = [
        issue.normalized_source.original_bytes
        for issue in read_packaged_github_fixture().issues
    ]
    env = os.environ.copy()
    env["SENTINEL_STORE_ROOT"] = str(root)
    env["SENTINEL_BLOBS"] = json.dumps(
        [blob.content_sha256 for blob in report.blobs], separators=(",", ":")
    )
    script = """
import base64, hashlib, json, os
import sentinel.content.public_fixture_store as store
store.read_packaged_github_fixture = lambda: (_ for _ in ()).throw(AssertionError('fixture read'))
root = os.environ['SENTINEL_STORE_ROOT']
digests = json.loads(os.environ['SENTINEL_BLOBS'])
result = []
for digest in digests:
    body = store.read_public_fixture_blob(root, content_sha256=digest)
    result.append({'sha256': hashlib.sha256(body).hexdigest(), 'length': len(body),
                   'bytes_b64': base64.b64encode(body).decode('ascii')})
print(json.dumps(result, sort_keys=True, separators=(',', ':')))
"""
    process = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    assert process.stderr == ""
    output = json.loads(process.stdout)
    returned = [base64.b64decode(entry["bytes_b64"], validate=True) for entry in output]
    assert set(returned) == set(expected)
    assert {entry["sha256"] for entry in output} == {
        blob.content_sha256 for blob in report.blobs
    }
    assert {entry["length"] for entry in output} == {
        blob.payload_byte_length for blob in report.blobs
    }


def test_content_directory_has_no_sqlite_database_or_sidecars(tmp_path: Path) -> None:
    root, report = prepare_store(tmp_path / "store")
    for path in root.rglob("*"):
        assert path.suffix.lower() not in {".db", ".sqlite", ".sqlite3", ".wal", ".shm"}
    for blob in report.blobs:
        value = read_public_fixture_blob(root, content_sha256=blob.content_sha256)
        assert hashlib.sha256(value).hexdigest() == blob.content_sha256
