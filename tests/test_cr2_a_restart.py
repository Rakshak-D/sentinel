import json
import subprocess
import sys
from pathlib import Path


def test_policy_status_runs_in_a_fresh_cli_process_outside_checkout(tmp_path: Path) -> None:
    cli = Path(sys.executable).with_name("sentinel.exe")
    assert cli.is_file(), "the development environment must install the sentinel console script"
    result = subprocess.run(
        [str(cli), "policy", "status", "--format", "json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "sentinel.policy-status.v3"
    assert payload["default_outcome"] == "DENY"
    assert payload["enforcement_integration"] == "INCOMPLETE"
