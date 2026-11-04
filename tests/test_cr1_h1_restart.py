from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

from sentinel.ingestion import promote_github_fixture_to_public_blobs
from sentinel.readers.github_fixture import read_packaged_github_fixture
from tests.cr1_h1_support import prepared_case


def test_fresh_process_reads_promoted_bodies_without_fixture_resource(tmp_path: Path) -> None:
    database, store_root = prepared_case(tmp_path, name="restart")
    fixture = read_packaged_github_fixture()
    promote_github_fixture_to_public_blobs(database, store_root=store_root)
    expected = {
        issue.normalized_source.envelope.content_sha256: issue.normalized_source.original_bytes
        for issue in fixture.issues
    }
    environment = os.environ.copy()
    environment["CR1H1_DATABASE"] = str(database)
    environment["CR1H1_STORE"] = str(store_root)
    child = r"""
import base64, json, os
import sentinel.readers.github_fixture as fixture_reader
fixture_reader.read_packaged_github_fixture = lambda: (
    (_ for _ in ()).throw(AssertionError("fixture loader used"))
)
from sentinel.ingestion import read_blob_backed_github_body, read_blob_backed_github_fixture
database = os.environ["CR1H1_DATABASE"]
store = os.environ["CR1H1_STORE"]
report = read_blob_backed_github_fixture(database, store_root=store)
rows = []
for item in report.items:
    body = read_blob_backed_github_body(database, store_root=store, item_id=item.item_id)
    rows.append({"item_id": str(item.item_id), "content_sha256": item.content_sha256,
                 "body_b64": base64.b64encode(body).decode("ascii"),
                 "spans": len(item.spans)})
print(json.dumps(rows, sort_keys=True, separators=(",", ":")))
"""
    completed = subprocess.run(
        [sys.executable, "-c", child],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    rows = json.loads(completed.stdout)
    actual = {
        row["content_sha256"]: base64.b64decode(row["body_b64"], validate=True) for row in rows
    }
    assert actual == expected
    assert sum(row["spans"] for row in rows) == 9
