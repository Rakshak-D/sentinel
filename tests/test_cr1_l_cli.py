from __future__ import annotations

import json

from typer.testing import CliRunner

from sentinel.cli import app
from tests.cr1_l_support import AS_OF, add_task, overview_case, persisted_state

runner = CliRunner()


def test_cli_text_json_counts_agree_and_no_task_or_proposal_is_created(tmp_path) -> None:
    database, store_root = overview_case(tmp_path, name="cli", generation=1)
    add_task(database, key="cli-task", title="Manual CLI task")
    before = persisted_state(database, store_root)
    command = [
        "brief", "local-overview", "--database", str(database), "--store-root", str(store_root),
        "--as-of", AS_OF.isoformat(),
    ]
    text = runner.invoke(app, command)
    encoded = runner.invoke(app, [*command, "--format", "json"])

    assert text.exit_code == encoded.exit_code == 0
    assert text.stderr == encoded.stderr == ""
    document = json.loads(encoded.stdout)
    assert "Manually entered local tasks: 1" in text.stdout
    assert document["task_count"] == 1
    assert sum(document["task_counts"].values()) == 1
    assert document["synthetic_evidence"]["item_count"] == 3
    assert document["synthetic_evidence"]["citation_count"] == 9
    assert document["incremental_sync"]["generation"] == 1
    assert document["incremental_sync"]["item_count"] == 1
    assert "action_proposals" not in encoded.stdout
    assert persisted_state(database, store_root) == before
