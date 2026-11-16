from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from tools.cr2_g_b1.service_host import (
    SERVICE_CONFIG_SCHEMA,
    SERVICE_NAME,
    ServiceConfig,
    ServiceLabError,
    ServiceState,
    next_service_state,
    parse_service_config,
)
from tools.cr2_g_b1.windows_pipe import BrokerPipeError, _pipe_sddl
from tools.cr2_g_b1.windows_service_lab import (
    LabProbeError,
    _raw_frame_parts,
    _require_exact_aces,
)


def _config(root: Path) -> dict[str, object]:
    return {
        "schema_version": SERVICE_CONFIG_SCHEMA,
        "service_name": SERVICE_NAME,
        "pipe_name": r"\\.\pipe\SentinelCR2GB2-lab",
        "allowed_client_sid": "S-1-5-21-1001-1002-1003-1004",
        "database_path": str(root / "data" / "canary.sqlite"),
    }


def test_service_configuration_is_typed_and_fixed_scope(tmp_path: Path) -> None:
    parsed = parse_service_config(
        json.dumps(_config(tmp_path), sort_keys=True).encode("utf-8"),
        root=tmp_path,
    )
    assert parsed == ServiceConfig(
        pipe_name=r"\\.\pipe\SentinelCR2GB2-lab",
        allowed_client_sid="S-1-5-21-1001-1002-1003-1004",
        database_path=tmp_path / "data" / "canary.sqlite",
    )


@pytest.mark.parametrize(
    "payload_change",
    [
        {"owner_verified": True},
        {"command": "arbitrary"},
        {"database_path": "C:\\outside\\canary.sqlite"},
        {"pipe_name": r"\\.\pipe\arbitrary"},
        {"service_name": "OtherService"},
    ],
)
def test_service_configuration_rejects_authority_and_scope_changes(
    tmp_path: Path,
    payload_change: dict[str, object],
) -> None:
    data = _config(tmp_path)
    data.update(payload_change)
    with pytest.raises(ServiceLabError):
        parse_service_config(json.dumps(data).encode("utf-8"), root=tmp_path)


def test_service_configuration_rejects_duplicate_and_oversized_json(
    tmp_path: Path,
) -> None:
    duplicate = (
        b'{"schema_version":"sentinel.cr2-g-b2-service-config.v1",'
        b'"service_name":"SentinelCR2GB2Lab",'
        b'"service_name":"AttackerService"}'
    )
    with pytest.raises(ServiceLabError):
        parse_service_config(duplicate, root=tmp_path)
    with pytest.raises(ServiceLabError):
        parse_service_config(b" " * 8193, root=tmp_path)
    deeply_nested = b"[" * 2000 + b"0" + b"]" * 2000
    with pytest.raises(ServiceLabError):
        parse_service_config(deeply_nested, root=tmp_path)


@pytest.mark.parametrize("client_sid", ["S-1-5-18", "S-1-5-32-544", "owner_verified=true"])
def test_service_configuration_requires_disposable_local_user_sid(
    tmp_path: Path,
    client_sid: str,
) -> None:
    data = _config(tmp_path)
    data["allowed_client_sid"] = client_sid
    with pytest.raises(ServiceLabError):
        parse_service_config(json.dumps(data).encode("utf-8"), root=tmp_path)


def test_service_state_machine_has_bounded_start_and_stop_order() -> None:
    assert next_service_state(ServiceState.STOPPED, "START") is ServiceState.START_PENDING
    assert next_service_state(ServiceState.START_PENDING, "READY") is ServiceState.RUNNING
    assert next_service_state(ServiceState.RUNNING, "STOP") is ServiceState.STOP_PENDING
    assert next_service_state(ServiceState.STOP_PENDING, "EXIT") is ServiceState.STOPPED


@pytest.mark.parametrize(
    ("state", "event"),
    [
        (ServiceState.STOPPED, "READY"),
        (ServiceState.RUNNING, "READY"),
        (ServiceState.STOP_PENDING, "START"),
        (ServiceState.RUNNING, "APPROVE"),
    ],
)
def test_service_state_machine_rejects_invalid_or_authorizing_events(
    state: ServiceState,
    event: str,
) -> None:
    with pytest.raises(ServiceLabError):
        next_service_state(state, event)


def test_b2_pipe_acl_is_explicit_and_client_cannot_create_instances() -> None:
    client_sid = "S-1-5-21-1-2-3-1001"
    service_sid = "S-1-5-80-12345-12345-12345-12345-12345"
    sddl = _pipe_sddl(client_sid, service_sid)
    assert f"(A;;0x00100083;;;{client_sid})" in sddl
    assert f"(A;;GA;;;{service_sid})" in sddl
    assert "(A;;0x00120083;;;S-1-5-32-544)" in sddl
    assert "0x0004" not in sddl
    assert "FILE_CREATE_PIPE_INSTANCE" not in sddl
    assert _pipe_sddl(client_sid).endswith(f"(A;;0x00100083;;;{client_sid})")


def test_b2_pipe_acl_rejects_untrusted_sid_text() -> None:
    with pytest.raises(BrokerPipeError, match="INVALID_ALLOWED_SID"):
        _pipe_sddl("owner_verified=true")
    with pytest.raises(BrokerPipeError, match="INVALID_SERVER_SID"):
        _pipe_sddl("S-1-5-21-1-2-3-1001", "C:\\arbitrary")


def test_live_acl_validation_rejects_duplicate_or_extra_allow_aces() -> None:
    expected = {"S-1-5-19": 0x001200A9, "S-1-5-18": 0x001F01FF}
    assert _require_exact_aces(
        [(sid, mask) for sid, mask in expected.items()],
        expected,
        reason="ACL_MISMATCH",
    ) == expected
    with pytest.raises(LabProbeError, match="ACL_MISMATCH"):
        _require_exact_aces(
            [("S-1-5-19", 0x001F01FF), ("S-1-5-19", 0x001200A9), ("S-1-5-18", 0x001F01FF)],
            expected,
            reason="ACL_MISMATCH",
        )
    with pytest.raises(LabProbeError, match="ACL_MISMATCH"):
        _require_exact_aces(
            [("S-1-5-19", 0x001200A9), ("S-1-5-18", 0x001F01FF), ("S-1-5-11", 0x001F01FF)],
            expected,
            reason="ACL_MISMATCH",
        )


def test_raw_pipe_probe_preserves_complete_frame_bytes() -> None:
    payload = b'{"duplicate":"first","duplicate":"last"}'
    parts = _raw_frame_parts(payload)
    assert parts == [len(payload).to_bytes(4, "big"), payload]
    assert b"".join(parts) == len(payload).to_bytes(4, "big") + payload
    assert _raw_frame_parts(None, declared=4097) == [(4097).to_bytes(4, "big")]
    with pytest.raises(LabProbeError, match="RAW_FRAME_INVALID"):
        _raw_frame_parts(None)


def test_service_host_has_no_external_or_production_authorization_imports() -> None:
    source = Path("tools/cr2_g_b1/service_host.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", maxsplit=1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module.split(".", maxsplit=1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )
    assert imported.isdisjoint(
        {"socket", "urllib", "requests", "subprocess", "webbrowser", "sentinel"}
    )
    assert "StartServiceCtrlDispatcherW" in source
    assert "owner_verified = True" not in source
    assert "owner_verified=True" not in source


def _yaml_entry(text: str, path: tuple[str, ...]) -> tuple[int, int, str, list[str]]:
    """Read one simple, indentation-based YAML mapping entry and its block."""
    lines = text.splitlines()
    search_from = 0
    parent_indent = -2
    found: tuple[int, int, str] | None = None
    for key in path:
        expected_indent = parent_indent + 2
        found = None
        for index in range(search_from, len(lines)):
            line = lines[index]
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent <= parent_indent:
                break
            if indent == expected_indent and line.lstrip().startswith(f"{key}:"):
                found = (index, indent, line.lstrip().split(":", maxsplit=1)[1].strip())
                break
        assert found is not None, f"missing YAML mapping path: {path!r}"
        search_from = found[0] + 1
        parent_indent = found[1]
    assert found is not None
    block = []
    for line in lines[found[0] + 1 :]:
        if line.strip() and len(line) - len(line.lstrip(" ")) <= found[1]:
            break
        block.append(line)
    return found[0], found[1], found[2], block


def _yaml_sequence(text: str, path: tuple[str, ...]) -> list[str]:
    _, indent, value, block = _yaml_entry(text, path)
    assert value == ""
    sequence_indent = indent + 2
    values = []
    for line in block:
        if not line.strip():
            continue
        line_indent = len(line) - len(line.lstrip(" "))
        if line_indent == sequence_indent and line.lstrip().startswith("- "):
            values.append(line.lstrip()[2:].strip())
        elif line_indent <= indent:
            break
        else:
            raise AssertionError(f"unexpected YAML sequence structure at {path!r}")
    return values


def _yaml_folded_scalar(text: str, path: tuple[str, ...]) -> str:
    _, indent, marker, block = _yaml_entry(text, path)
    assert marker in {">", ">-"}
    return " ".join(line.strip() for line in block if line.strip())


def test_ephemeral_workflow_is_same_repo_opened_nondraft_pr_only() -> None:
    workflow = Path(
        ".github/workflows/cr2-g-b2-ephemeral-windows-lab.yml"
    ).read_text(encoding="utf-8")
    assert _yaml_sequence(workflow, ("on", "pull_request", "types")) == ["opened"]
    condition = _yaml_folded_scalar(workflow, ("jobs", "isolated-service-lab", "if"))
    assert [term.strip() for term in condition.split("&&")] == [
        "github.event_name == 'pull_request'",
        "github.event.action == 'opened'",
        "github.event.pull_request.draft == false",
        "github.event.pull_request.head.repo.full_name == github.repository",
        "github.event.pull_request.head.ref == 'feat/cr2-g-b2-r2-diagnostics'",
        "github.event.pull_request.base.repo.full_name == github.repository",
        "github.event.pull_request.base.ref == 'main'",
    ]
    assert "pull_request_target" not in workflow
    assert "workflow_dispatch" not in workflow
    assert "workflow_run" not in workflow
    assert "repository_dispatch" not in workflow
    assert "push:" not in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "runs-on: windows-2025" in workflow
    assert "timeout-minutes: 45" in workflow
    assert "persist-credentials: false" in workflow
    assert "@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
    assert "@a26af69be951a213d495a4c3e4e4022e16d87065" in workflow
    assert "secrets." not in workflow
    assert "pull_request.head.sha" in workflow


def test_lab_script_rejects_non_opened_or_draft_pull_requests() -> None:
    script = Path("tools/cr2_g_b1/run_ephemeral_lab.ps1").read_text(encoding="utf-8")
    guard_start = script.index("if (\n        $event.action")
    guard_end = script.index(
        "    ) {\n        Stop-WithCode \"PULL_REQUEST_EVENT_NOT_ALLOWLISTED\"",
        guard_start,
    )
    guard = script[guard_start:guard_end]
    assert '$event.action -ne "opened"' in guard
    assert "$event.pull_request.draft -ne $false" in guard
    assert "$event.pull_request.head.repo.full_name -ne $repoName" in guard
    assert "$event.pull_request.head.ref -ne $requiredBranch" in guard
    assert "$event.pull_request.base.repo.full_name -ne $repoName" in guard
    assert '$event.pull_request.base.ref -ne "main"' in guard
