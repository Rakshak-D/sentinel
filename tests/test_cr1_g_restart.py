"""A new interpreter process verifies persisted rows after ingestion."""

import json
import subprocess
import sys
from pathlib import Path

from sentinel.ingestion import ingest_packaged_github_fixture
from tests.cr1_g_support import initialized_database


def test_fresh_python_process_reconstructs_three_items_and_nine_spans(
    tmp_path: Path,
) -> None:
    database = initialized_database(tmp_path / "restart.sqlite3")
    ingest_packaged_github_fixture(database)
    script = (
        "import json, sys; "
        "from sentinel.ingestion import read_persisted_github_fixture; "
        "report = read_persisted_github_fixture(sys.argv[1]); "
        "print(json.dumps({'items': len(report.items), 'spans': "
        "sum(len(item.spans) for item in report.items), 'fixture_sha256': "
        "report.fixture_sha256}, sort_keys=True))"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script, str(database)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "items": 3,
        "spans": 9,
        "fixture_sha256": "7a28c6434ad25f06f6c24a9fa912e94c44796c9e3d4d8676642b37c554a13bc1",
    }
