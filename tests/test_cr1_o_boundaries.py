from __future__ import annotations

import ast
from pathlib import Path

import pytest

from sentinel.extraction import (
    JobAlertError,
    JobAlertErrorCode,
    parse_gmail_fixture_job_alert,
    parse_local_job_alert,
)
from sentinel.readers import LocalTextError
from tests.cr1_o_support import gmail_message


def test_source_and_line_field_bounds_fail_with_fixed_errors() -> None:
    oversized = gmail_message("x" * (64 * 1024 + 1))
    with pytest.raises(JobAlertError) as source_error:
        parse_gmail_fixture_job_alert(oversized)
    assert source_error.value.code is JobAlertErrorCode.SOURCE_TOO_LARGE

    for body in (
        "Company: " + "x" * 1025,
        "\n".join(["note"] * 257),
        "\n".join(["Company: A", "Role: B"] + ["Location: Somewhere"] * 11),
    ):
        with pytest.raises(JobAlertError) as error:
            parse_gmail_fixture_job_alert(gmail_message(body))
        assert error.value.code is JobAlertErrorCode.INPUT_TOO_COMPLEX


def test_private_canaries_do_not_appear_in_errors_or_repr() -> None:
    bad = gmail_message("Company: PRIVATE_BODY_CANARY\u202e\nRole: Safe\n")
    result = parse_gmail_fixture_job_alert(bad)
    assert "PRIVATE_BODY_CANARY" not in repr(result)
    assert result.fields[0].value is None


def test_local_adapter_requires_existing_file_beneath_explicit_root(tmp_path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    file_path = root / "missing.txt"
    with pytest.raises(LocalTextError):
        parse_local_job_alert(allowed_root=root, file_path=file_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("Company: A\nRole: B\n", encoding="utf-8")
    with pytest.raises(LocalTextError):
        parse_local_job_alert(allowed_root=root, file_path=outside)


def test_invalid_utf8_local_file_is_rejected_without_path_or_content_leak(tmp_path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    path = root / "bad.txt"
    path.write_bytes(b"PRIVATE_CANARY\xff")
    with pytest.raises(LocalTextError) as error:
        parse_local_job_alert(allowed_root=root, file_path=path)
    assert str(path) not in str(error.value)
    assert "PRIVATE_CANARY" not in str(error.value)


def test_local_read_creates_no_files_and_never_persists_source_bytes(tmp_path) -> None:
    root = tmp_path / "allow"
    root.mkdir()
    file_path = root / "alert.txt"
    content = b"Company: Private Fictional Co\nRole: Test Analyst\n"
    file_path.write_bytes(content)
    before = tuple(sorted((item.name, item.read_bytes()) for item in root.iterdir()))
    result = parse_local_job_alert(allowed_root=root, file_path=file_path)
    after = tuple(sorted((item.name, item.read_bytes()) for item in root.iterdir()))
    assert before == after
    assert result.normalized_source.original_bytes == content
    assert result.sensitivity.value == "PRIVATE"


def test_exact_source_line_and_physical_line_limits_are_accepted() -> None:
    source = ("x" * 1023 + "\n") * 64
    assert len(source.encode("utf-8")) == 64 * 1024
    result = parse_gmail_fixture_job_alert(gmail_message(source))
    assert result.byte_length == 64 * 1024
    assert result.status.value == "NO_MATCH"

    exactly_256_lines = "\n".join(["note"] * 256)
    assert (
        parse_gmail_fixture_job_alert(gmail_message(exactly_256_lines)).status.value == "NO_MATCH"
    )


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("Company", "x" * 161),
        ("Role", "x" * 201),
        ("Location", "x" * 201),
        ("Deadline", "x" * 65),
    ],
)
def test_field_byte_bounds_reject_only_the_invalid_field(label, value) -> None:
    lines = []
    if label != "Company":
        lines.append("Company: Base")
    if label != "Role":
        lines.append("Role: Base Role")
    lines.append(f"{label}: {value}")
    result = parse_gmail_fixture_job_alert(gmail_message("\n".join(lines) + "\n"))
    assert result.status.value == "INCOMPLETE"
    field_name = {
        "Company": "company",
        "Role": "role",
        "Location": "location",
        "Deadline": "deadline",
    }[label]
    invalid = next(field for field in result.fields if field.field_id.value == field_name)
    assert invalid.value is None
    assert invalid.evidence is None


def test_parser_has_no_database_network_model_tool_or_task_dependencies() -> None:
    module = Path("src/sentinel/extraction/job_alert.py")
    tree = ast.parse(module.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported.isdisjoint(
        {
            "sqlite3",
            "requests",
            "httpx",
            "socket",
            "subprocess",
            "smtplib",
            "imaplib",
            "webbrowser",
        }
    )
    source = module.read_text(encoding="utf-8")
    assert "create_local_task" not in source
    assert "ModelGateway" not in source
    assert "ToolGateway" not in source
