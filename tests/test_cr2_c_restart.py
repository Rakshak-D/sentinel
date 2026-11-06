from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tests.test_cr1_i_support import promoted_case


def test_installed_cli_process_repeats_body_free_preview_outside_checkout(tmp_path: Path) -> None:
    database, store_root = promoted_case(tmp_path, name="cr2-c-installed-preview")
    cli = Path(sys.executable).with_name("sentinel.exe")
    assert cli.is_file(), "the development environment must install the Sentinel CLI"
    command = [
        str(cli),
        "proposal",
        "preview-github-fixture",
        "--database",
        str(database),
        "--store-root",
        str(store_root),
        "--issue",
        "102",
        "--format",
        "json",
    ]
    first = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, check=False)
    second = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, check=False)

    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == ""
    assert first.stdout == second.stdout
    document = json.loads(first.stdout)
    assert document["provider_item_id"] == "example-owner/fixture-project#102"
    assert document["policy_rule_id"] == "P06"
    assert document["status"] == "PREVIEW_ONLY"
    assert "cited_text" not in document
    assert "source_body" not in document
